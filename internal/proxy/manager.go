package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Manager serializes mutations without holding its read lock across network
// shutdown. Readers and the configuration callback remain free to take snapshots.
type Manager struct {
	opMu     sync.Mutex
	mu       sync.RWMutex
	rules    map[string]*Rule
	order    []string
	onChange func()
	journal  eventJournal
}

func NewManager() *Manager { return &Manager{rules: make(map[string]*Rule)} }

func (m *Manager) SetOnChange(fn func()) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

func (m *Manager) notify() {
	m.mu.RLock()
	fn := m.onChange
	m.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

func newID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("r%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (m *Manager) checkPortConflictLocked(spec RuleSpec, excludeID string) error {
	for id, rule := range m.rules {
		if id == excludeID {
			continue
		}
		other := rule.Spec()
		if other.ListenPort != spec.ListenPort {
			continue
		}
		left, right := net.ParseIP(other.ListenHost), net.ParseIP(spec.ListenHost)
		if other.ListenHost == spec.ListenHost || (left != nil && left.IsUnspecified()) || (right != nil && right.IsUnspecified()) || (left != nil && right != nil && left.Equal(right)) {
			name := other.Name
			if name == "" {
				name = other.ID
			}
			return fmt.Errorf("порт %d уже занят правилом %q", spec.ListenPort, name)
		}
	}
	return nil
}

func (m *Manager) Add(spec RuleSpec) (*Rule, error) {
	m.opMu.Lock()
	rule, err := m.addLocked(spec)
	m.opMu.Unlock()
	if rule != nil {
		m.notify()
	}
	return rule, err
}

func (m *Manager) addLocked(spec RuleSpec) (*Rule, error) {
	spec = spec.Clone()
	if spec.ID == "" {
		spec.ID = newID()
	}
	spec.applyDefaults()
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if _, exists := m.rules[spec.ID]; exists {
		m.mu.Unlock()
		return nil, fmt.Errorf("правило %s уже существует", spec.ID)
	}
	if err := m.checkPortConflictLocked(spec, ""); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	rule, err := newRule(spec)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	rule.event = m.journal.add
	m.rules[spec.ID] = rule
	m.order = append(m.order, spec.ID)
	m.mu.Unlock()
	rule.emit("created", "Правило создано")
	if spec.Enabled {
		if err := rule.Start(); err != nil {
			rule.mu.Lock()
			rule.spec.Enabled = false
			rule.mu.Unlock()
			return rule, err
		}
	}
	return rule, nil
}

func (m *Manager) Update(id string, spec RuleSpec) error {
	m.opMu.Lock()
	err := m.updateLocked(id, spec)
	m.opMu.Unlock()
	m.notify()
	return err
}

func (m *Manager) updateLocked(id string, spec RuleSpec) error {
	rule, ok := m.Get(id)
	if !ok {
		return fmt.Errorf("правило %s не найдено", id)
	}
	spec = spec.Clone()
	spec.ID = id
	spec.applyDefaults()
	if err := spec.Validate(); err != nil {
		return err
	}
	acl, err := parseACL(spec.AllowCIDR)
	if err != nil {
		return err
	}
	m.mu.RLock()
	err = m.checkPortConflictLocked(spec, id)
	m.mu.RUnlock()
	if err != nil {
		return err
	}
	rule.lifeMu.Lock()
	defer rule.lifeMu.Unlock()
	old := rule.Spec()
	wasRunning := rule.Snapshot().Running
	needListener := spec.Enabled && (!wasRunning || old.ListenAddr() != spec.ListenAddr())
	stoppedOld := false
	var candidate net.Listener
	// Bind before changing configuration or trimming captures. When old and new
	// bindings overlap on the same port, retry after Stop and restore on failure.
	restore := func(cause error) error {
		if candidate != nil {
			candidate.Close()
		}
		if stoppedOld {
			if rollbackErr := rule.startLocked(nil); rollbackErr != nil {
				rule.mu.Lock()
				rule.spec.Enabled = false
				rule.mu.Unlock()
				cause = fmt.Errorf("%v; восстановить прежний слушатель не удалось: %w", cause, rollbackErr)
			}
		}
		rule.emit("update_failed", cause.Error())
		return cause
	}
	if needListener {
		candidate, err = net.Listen("tcp", spec.ListenAddr())
		if err != nil && wasRunning && old.ListenPort == spec.ListenPort {
			rule.stopLocked()
			stoppedOld = true
			candidate, err = net.Listen("tcp", spec.ListenAddr())
		}
		if err != nil {
			return restore(fmt.Errorf("не удалось занять %s: %w", spec.ListenAddr(), err))
		}
	}
	if err := rule.rec.Resize(spec.Dump.MaxConns, spec.Dump.MaxBytesPer); err != nil {
		return restore(err)
	}
	if wasRunning && (!spec.Enabled || needListener) && !stoppedOld {
		rule.stopLocked()
	}
	rule.stopHealthLocked()
	rule.mu.Lock()
	rule.spec, rule.acl = spec, acl
	if old.Target != spec.Target {
		rule.targetUp = true
		rule.failStreak, rule.riseStreak = 0, 0
	}
	if !sameEndpoint(old.Backup, spec.Backup) {
		rule.backupUp = true
		rule.bkFailStrk, rule.bkRiseStrk = 0, 0
	}
	rule.decideFailoverLocked()
	rule.emitLocked("updated", "Настройки правила обновлены")
	rule.mu.Unlock()
	if needListener {
		return rule.startLocked(candidate)
	}
	if spec.Enabled {
		rule.startHealthLocked()
	}
	return nil
}

func sameEndpoint(left, right *Endpoint) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (m *Manager) SetEnabled(id string, enabled bool) error {
	m.opMu.Lock()
	rule, ok := m.Get(id)
	var err error
	if !ok {
		err = fmt.Errorf("правило %s не найдено", id)
	} else {
		spec := rule.Spec()
		spec.Enabled = enabled
		err = m.updateLocked(id, spec)
	}
	m.opMu.Unlock()
	m.notify()
	return err
}

func (m *Manager) SetRoutingMode(id, mode string) error {
	m.opMu.Lock()
	rule, ok := m.Get(id)
	var err error
	if !ok {
		err = fmt.Errorf("правило %s не найдено", id)
	} else {
		rule.lifeMu.Lock()
		rule.mu.Lock()
		err = rule.setRoutingModeLocked(mode)
		rule.mu.Unlock()
		rule.lifeMu.Unlock()
	}
	m.opMu.Unlock()
	if err == nil {
		m.notify()
	}
	return err
}

func (m *Manager) Delete(id string) error {
	m.opMu.Lock()
	m.mu.Lock()
	rule, ok := m.rules[id]
	if !ok {
		m.mu.Unlock()
		m.opMu.Unlock()
		return fmt.Errorf("правило %s не найдено", id)
	}
	delete(m.rules, id)
	for i, candidate := range m.order {
		if candidate == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.mu.Unlock()
	rule.Stop()
	rule.emit("deleted", "Правило удалено")
	m.opMu.Unlock()
	m.notify()
	return nil
}

func (m *Manager) Get(id string) (*Rule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rule, ok := m.rules[id]
	return rule, ok
}

func (m *Manager) List() []*Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Rule, 0, len(m.rules))
	for _, id := range m.order {
		if rule, ok := m.rules[id]; ok {
			result = append(result, rule)
		}
	}
	return result
}

func (m *Manager) Snapshots() []Snapshot {
	rules := m.List()
	result := make([]Snapshot, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.Snapshot())
	}
	return result
}

func (m *Manager) Specs() []RuleSpec {
	rules := m.List()
	result := make([]RuleSpec, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.Spec())
	}
	return result
}

// LoadSpecs does not notify on individual rules: a save midway through loading
// must not overwrite the rest of the configuration. Duplicate IDs are rejected.
func (m *Manager) LoadSpecs(specs []RuleSpec) []error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	var errs []error
	for _, spec := range specs {
		if _, err := m.addLocked(spec); err != nil {
			errs = append(errs, fmt.Errorf("правило %s: %w", spec.Name, err))
		}
	}
	return errs
}

func (m *Manager) StopAll() {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	for _, rule := range m.List() {
		rule.Stop()
	}
}

func (m *Manager) UsedPorts() []int {
	rules := m.List()
	result := make([]int, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.Spec().ListenPort)
	}
	sort.Ints(result)
	return result
}
