package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
)

// Manager владеет набором правил и следит за их запуском/остановкой.
type Manager struct {
	mu       sync.RWMutex
	rules    map[string]*Rule
	order    []string
	onChange func()
}

func NewManager() *Manager {
	return &Manager{rules: make(map[string]*Rule)}
}

// SetOnChange вешает колбэк, который дёргается после любого изменения набора
// правил — им наружный код сохраняет конфиг на диск.
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
		return fmt.Sprintf("r%d", len(b))
	}
	return hex.EncodeToString(b)
}

// checkPortConflict ищет другое правило, которое уже слушает тот же адрес.
// Вызывать под m.mu.
func (m *Manager) checkPortConflictLocked(spec RuleSpec, excludeID string) error {
	for id, r := range m.rules {
		if id == excludeID {
			continue
		}
		other := r.Spec()
		if other.ListenPort != spec.ListenPort {
			continue
		}
		// 0.0.0.0 конфликтует с любым адресом на том же порту.
		if other.ListenHost == spec.ListenHost ||
			other.ListenHost == "0.0.0.0" || spec.ListenHost == "0.0.0.0" {
			name := other.Name
			if name == "" {
				name = other.ID
			}
			return fmt.Errorf("порт %d уже занят правилом %q", spec.ListenPort, name)
		}
	}
	return nil
}

// Add создаёт правило и, если оно включено, сразу его поднимает.
func (m *Manager) Add(spec RuleSpec) (*Rule, error) {
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
	r, err := newRule(spec)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	m.rules[spec.ID] = r
	m.order = append(m.order, spec.ID)
	m.mu.Unlock()

	if spec.Enabled {
		if err := r.Start(); err != nil {
			// Правило остаётся в списке, но выключенным — пользователь увидит ошибку.
			r.mu.Lock()
			r.spec.Enabled = false
			r.mu.Unlock()
			m.notify()
			return r, err
		}
	}
	m.notify()
	return r, nil
}

// Update меняет конфигурацию существующего правила. Слушатель перезапускается
// только если изменилось то, что на него влияет, — статистика и дампы при
// правке мелочей не теряются.
func (m *Manager) Update(id string, spec RuleSpec) error {
	m.mu.RLock()
	r, ok := m.rules[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("правило %s не найдено", id)
	}

	spec.ID = id
	spec.applyDefaults()
	if err := spec.Validate(); err != nil {
		return err
	}
	acl, err := parseACL(spec.AllowCIDR)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if err := m.checkPortConflictLocked(spec, id); err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()

	old := r.Spec()
	wasRunning := r.Snapshot().Running
	needRestart := old.ListenAddr() != spec.ListenAddr() ||
		old.Health.Enabled != spec.Health.Enabled ||
		old.Health.IntervalSec != spec.Health.IntervalSec

	if wasRunning && (needRestart || !spec.Enabled) {
		r.Stop()
	}

	r.mu.Lock()
	r.spec = spec
	r.acl = acl
	// Если резерв убрали, нельзя остаться на нём висеть.
	if spec.Backup == nil || spec.Backup.IsZero() {
		r.usingBackup = false
	}
	r.mu.Unlock()
	r.rec.Resize(spec.Dump.MaxConns, spec.Dump.MaxBytesPer)

	if spec.Enabled && (!wasRunning || needRestart) {
		if err := r.Start(); err != nil {
			r.mu.Lock()
			r.spec.Enabled = false
			r.mu.Unlock()
			m.notify()
			return err
		}
	}
	m.notify()
	return nil
}

// SetEnabled включает или выключает правило.
func (m *Manager) SetEnabled(id string, enabled bool) error {
	m.mu.RLock()
	r, ok := m.rules[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("правило %s не найдено", id)
	}

	if enabled {
		r.mu.Lock()
		r.spec.Enabled = true
		r.mu.Unlock()
		if err := r.Start(); err != nil {
			r.mu.Lock()
			r.spec.Enabled = false
			r.mu.Unlock()
			m.notify()
			return err
		}
	} else {
		r.Stop()
		r.mu.Lock()
		r.spec.Enabled = false
		r.mu.Unlock()
	}
	m.notify()
	return nil
}

// Delete останавливает и убирает правило.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	r, ok := m.rules[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("правило %s не найдено", id)
	}
	delete(m.rules, id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.mu.Unlock()

	r.Stop()
	m.notify()
	return nil
}

func (m *Manager) Get(id string) (*Rule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rules[id]
	return r, ok
}

// List отдаёт правила в порядке добавления.
func (m *Manager) List() []*Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Rule, 0, len(m.rules))
	for _, id := range m.order {
		if r, ok := m.rules[id]; ok {
			out = append(out, r)
		}
	}
	return out
}

func (m *Manager) Snapshots() []Snapshot {
	rules := m.List()
	out := make([]Snapshot, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Snapshot())
	}
	return out
}

// Specs отдаёт конфигурацию всех правил — то, что уходит в config.json.
func (m *Manager) Specs() []RuleSpec {
	rules := m.List()
	out := make([]RuleSpec, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Spec())
	}
	return out
}

// LoadSpecs поднимает набор правил из конфига. Ошибки по отдельным правилам
// собираются в список, остальные всё равно стартуют: одно битое правило не
// должно ронять весь проброс.
func (m *Manager) LoadSpecs(specs []RuleSpec) []error {
	var errs []error
	for _, spec := range specs {
		if spec.ID == "" {
			spec.ID = newID()
		}
		spec.applyDefaults()
		if err := spec.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("правило %s: %w", spec.Name, err))
			continue
		}
		m.mu.Lock()
		if err := m.checkPortConflictLocked(spec, ""); err != nil {
			m.mu.Unlock()
			errs = append(errs, fmt.Errorf("правило %s: %w", spec.Name, err))
			continue
		}
		r, err := newRule(spec)
		if err != nil {
			m.mu.Unlock()
			errs = append(errs, fmt.Errorf("правило %s: %w", spec.Name, err))
			continue
		}
		m.rules[spec.ID] = r
		m.order = append(m.order, spec.ID)
		m.mu.Unlock()

		if spec.Enabled {
			if err := r.Start(); err != nil {
				r.mu.Lock()
				r.spec.Enabled = false
				r.mu.Unlock()
				errs = append(errs, err)
			}
		}
	}
	return errs
}

// StopAll гасит все правила — вызывается при завершении процесса.
func (m *Manager) StopAll() {
	for _, r := range m.List() {
		r.Stop()
	}
}

// UsedPorts — какие локальные порты уже заняты правилами (для подсказок в UI).
func (m *Manager) UsedPorts() []int {
	rules := m.List()
	out := make([]int, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Spec().ListenPort)
	}
	sort.Ints(out)
	return out
}
