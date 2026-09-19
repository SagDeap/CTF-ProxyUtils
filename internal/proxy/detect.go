package proxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const detectionQueueSize = 1024

// DetectorSpec is an explainable traffic signal. Scope can be stream,
// http_headers, http_path or http_body; mode can be text, hex or regex.
type DetectorSpec struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	Mode            string   `json:"mode"`
	Pattern         string   `json:"pattern"`
	Direction       string   `json:"direction"`
	Scope           string   `json:"scope"`
	Score           int      `json:"score"`
	CaseInsensitive bool     `json:"case_insensitive,omitempty"`
	Sensitive       bool     `json:"sensitive,omitempty"`
	RuleIDs         []string `json:"rule_ids,omitempty"`
}

func (d DetectorSpec) Clone() DetectorSpec {
	d.RuleIDs = append([]string(nil), d.RuleIDs...)
	return d
}

// DetectionConfig bounds CPU and memory while keeping detector behavior
// portable in exported profiles.
type DetectionConfig struct {
	Enabled      bool           `json:"enabled"`
	Builtins     bool           `json:"builtins"`
	Threshold    int            `json:"threshold"`
	AutoPinScore int            `json:"auto_pin_score"`
	MaxFindings  int            `json:"max_findings"`
	BufferBytes  int            `json:"buffer_bytes"`
	Detectors    []DetectorSpec `json:"detectors"`
}

func DefaultDetectionConfig() DetectionConfig {
	return DetectionConfig{Enabled: true, Builtins: true, Threshold: 25, AutoPinScore: 60, MaxFindings: 500, BufferBytes: 128 * 1024}
}

func (c DetectionConfig) Clone() DetectionConfig {
	detectors := c.Detectors
	c.Detectors = make([]DetectorSpec, len(detectors))
	for i, detector := range detectors {
		c.Detectors[i] = detector.Clone()
	}
	return c
}

func (c *DetectionConfig) applyDefaults() {
	if c.Threshold <= 0 {
		c.Threshold = 25
	}
	if c.AutoPinScore <= 0 {
		c.AutoPinScore = 60
	}
	if c.MaxFindings <= 0 {
		c.MaxFindings = 500
	}
	if c.BufferBytes <= 0 {
		c.BufferBytes = 128 * 1024
	}
}

func (c *DetectionConfig) ApplyDefaults() { c.applyDefaults() }

func (c DetectionConfig) Validate() error {
	c.applyDefaults()
	if c.Threshold < 1 || c.Threshold > 100 || c.AutoPinScore < 1 || c.AutoPinScore > 100 {
		return errors.New("порог детектора и автозакрепления должен быть от 1 до 100")
	}
	if c.MaxFindings < 1 || c.MaxFindings > 5000 || c.BufferBytes < 4096 || c.BufferBytes > 4*1024*1024 {
		return errors.New("лимиты детектора: 1–5000 находок и 4 КиБ–4 МиБ буфера")
	}
	seen := make(map[string]bool)
	for i, detector := range c.Detectors {
		if detector.ID == "" {
			return fmt.Errorf("детектор %d: пустой ID", i+1)
		}
		if seen[detector.ID] {
			return fmt.Errorf("повторяющийся ID детектора %q", detector.ID)
		}
		seen[detector.ID] = true
		if _, err := compileDetector(detector); err != nil {
			return fmt.Errorf("детектор %q: %w", detector.Name, err)
		}
	}
	return nil
}

type DetectionSignal struct {
	DetectorID   string `json:"detector_id"`
	DetectorName string `json:"detector_name"`
	Direction    string `json:"direction"`
	Score        int    `json:"score"`
	Reason       string `json:"reason"`
	Excerpt      string `json:"excerpt,omitempty"`
}

type Finding struct {
	ID           uint64            `json:"id"`
	At           time.Time         `json:"at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	RuleID       string            `json:"rule_id"`
	RuleName     string            `json:"rule_name"`
	ConnectionID uint64            `json:"connection_id"`
	RemoteAddr   string            `json:"remote_addr"`
	Target       string            `json:"target"`
	Protocol     string            `json:"protocol"`
	Score        int               `json:"score"`
	Severity     string            `json:"severity"`
	Signals      []DetectionSignal `json:"signals"`
	AutoPinned   bool              `json:"auto_pinned"`
}

func (f *Finding) clone() *Finding {
	copyFinding := *f
	copyFinding.Signals = append([]DetectionSignal(nil), f.Signals...)
	return &copyFinding
}

type compiledDetector struct {
	spec   DetectorSpec
	needle []byte
	re     *regexp.Regexp
}

func compileDetector(spec DetectorSpec) (compiledDetector, error) {
	if spec.Name == "" || len(spec.Name) > 120 || len(spec.Pattern) == 0 || len(spec.Pattern) > 4096 {
		return compiledDetector{}, errors.New("нужны имя и шаблон длиной до 4096 байт")
	}
	if spec.Mode == "" {
		spec.Mode = "text"
	}
	if spec.Direction == "" {
		spec.Direction = "any"
	}
	if spec.Scope == "" {
		spec.Scope = "stream"
	}
	if spec.Score <= 0 {
		spec.Score = 25
	}
	if spec.Score > 100 {
		return compiledDetector{}, errors.New("оценка должна быть от 1 до 100")
	}
	if spec.Direction != "any" && spec.Direction != DirIn && spec.Direction != DirOut {
		return compiledDetector{}, errors.New("направление должно быть any, in или out")
	}
	switch spec.Scope {
	case "stream", "http_headers", "http_path", "http_body":
	default:
		return compiledDetector{}, errors.New("область должна быть stream, http_headers, http_path или http_body")
	}
	compiled := compiledDetector{spec: spec}
	switch spec.Mode {
	case "text":
		compiled.needle = []byte(spec.Pattern)
		if spec.CaseInsensitive {
			compiled.needle = bytes.ToLower(compiled.needle)
		}
	case "hex":
		needle, err := hex.DecodeString(strings.Join(strings.Fields(spec.Pattern), ""))
		if err != nil || len(needle) == 0 {
			return compiledDetector{}, errors.New("некорректный hex-шаблон")
		}
		compiled.needle = needle
	case "regex":
		pattern := spec.Pattern
		if spec.CaseInsensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return compiledDetector{}, fmt.Errorf("регулярное выражение: %w", err)
		}
		compiled.re = re
	default:
		return compiledDetector{}, errors.New("режим должен быть text, hex или regex")
	}
	return compiled, nil
}

func builtinDetectors() []compiledDetector {
	specs := []DetectorSpec{
		{ID: "builtin-automation", Name: "Автоматизированный HTTP-клиент", Enabled: true, Mode: "regex", Pattern: `User-Agent\s*:\s*(?:python-requests|aiohttp|python-httpx|httpx|curl/|Go-http-client|Wget/)`, Direction: DirIn, Scope: "http_headers", Score: 45, CaseInsensitive: true},
		{ID: "builtin-traversal", Name: "Path traversal", Enabled: true, Mode: "regex", Pattern: `(?:\.\./|%2e%2e(?:%2f|/)|/etc/passwd|/proc/self/)`, Direction: DirIn, Scope: "stream", Score: 35, CaseInsensitive: true},
		{ID: "builtin-injection", Name: "Инъекция команды или SQL", Enabled: true, Mode: "regex", Pattern: `(?:;\s*(?:sh|bash|cat|wget|curl)\b|\bunion\s+(?:all\s+)?select\b|\b(?:eval|system|exec)\s*\()`, Direction: DirIn, Scope: "stream", Score: 40, CaseInsensitive: true},
	}
	out := make([]compiledDetector, 0, len(specs))
	for _, spec := range specs {
		compiled, _ := compileDetector(spec)
		out = append(out, compiled)
	}
	return out
}

type detectionEvent struct {
	kind                        string
	ruleID, ruleName, remote    string
	target, protocol, direction string
	connectionID                uint64
	data                        []byte
	autoPin                     bool
}

type detectionSession struct {
	ruleID, ruleName, remote, target, protocol string
	connectionID                               uint64
	autoPin                                    bool
	lastSeen                                   time.Time
	buffers                                    map[string][]byte
	matched                                    map[string]bool
	finding                                    *Finding
}

// DetectorEngine owns a single bounded worker. Observe never blocks proxy I/O.
type DetectorEngine struct {
	// Keep the 64-bit atomic aligned on 32-bit platforms.
	dropped  uint64
	mu       sync.RWMutex
	config   DetectionConfig
	compiled []compiledDetector
	findings []*Finding // newest first
	sequence uint64
	events   chan detectionEvent
	done     chan struct{}
	close    sync.Once
	wg       sync.WaitGroup
	hook     func(Finding, bool, bool)
}

func NewDetectorEngine(config DetectionConfig) (*DetectorEngine, error) {
	engine := &DetectorEngine{events: make(chan detectionEvent, detectionQueueSize), done: make(chan struct{})}
	if err := engine.Configure(config); err != nil {
		return nil, err
	}
	engine.wg.Add(1)
	go engine.run()
	return engine, nil
}

func (e *DetectorEngine) SetHook(hook func(Finding, bool, bool)) {
	e.mu.Lock()
	e.hook = hook
	e.mu.Unlock()
}

func (e *DetectorEngine) Configure(config DetectionConfig) error {
	config.applyDefaults()
	if err := config.Validate(); err != nil {
		return err
	}
	compiled := make([]compiledDetector, 0, len(config.Detectors)+3)
	if config.Builtins {
		compiled = append(compiled, builtinDetectors()...)
	}
	for _, spec := range config.Detectors {
		if !spec.Enabled {
			continue
		}
		detector, err := compileDetector(spec)
		if err != nil {
			return err
		}
		compiled = append(compiled, detector)
	}
	e.mu.Lock()
	e.config, e.compiled = config.Clone(), compiled
	if len(e.findings) > config.MaxFindings {
		e.findings = append([]*Finding(nil), e.findings[:config.MaxFindings]...)
	}
	e.mu.Unlock()
	return nil
}

func (e *DetectorEngine) Config() DetectionConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.Clone()
}

func (e *DetectorEngine) Findings() []*Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Finding, len(e.findings))
	for i, finding := range e.findings {
		out[i] = finding.clone()
	}
	return out
}

func (e *DetectorEngine) Dropped() uint64 { return atomic.LoadUint64(&e.dropped) }

func (e *DetectorEngine) ClearFindings() {
	e.mu.Lock()
	e.findings = nil
	e.mu.Unlock()
}

func (e *DetectorEngine) enqueue(event detectionEvent) {
	e.mu.RLock()
	enabled := e.config.Enabled
	e.mu.RUnlock()
	if !enabled {
		return
	}
	select {
	case e.events <- event:
	default:
		atomic.AddUint64(&e.dropped, 1)
	}
}

func (e *DetectorEngine) Begin(ruleID, ruleName string, connectionID uint64, remote, target, protocol string, autoPin bool) {
	e.enqueue(detectionEvent{kind: "begin", ruleID: ruleID, ruleName: ruleName, connectionID: connectionID, remote: remote, target: target, protocol: protocol, autoPin: autoPin})
}

func (e *DetectorEngine) Observe(ruleID, ruleName string, connectionID uint64, remote, target, protocol, direction string, data []byte, autoPin bool) {
	if len(data) == 0 {
		return
	}
	e.enqueue(detectionEvent{kind: "chunk", ruleID: ruleID, ruleName: ruleName, connectionID: connectionID, remote: remote, target: target, protocol: protocol, direction: direction, data: append([]byte(nil), data...), autoPin: autoPin})
}

func (e *DetectorEngine) End(ruleID string, connectionID uint64) {
	e.enqueue(detectionEvent{kind: "end", ruleID: ruleID, connectionID: connectionID})
}

func (e *DetectorEngine) Close() {
	e.close.Do(func() {
		close(e.done)
		e.wg.Wait()
	})
}

func sessionKey(ruleID string, connectionID uint64) string {
	return fmt.Sprintf("%s/%d", ruleID, connectionID)
}

func (e *DetectorEngine) run() {
	defer e.wg.Done()
	sessions := make(map[string]*detectionSession)
	bursts := make(map[string][]time.Time)
	cleanup := time.NewTicker(time.Minute)
	defer cleanup.Stop()
	for {
		select {
		case <-e.done:
			return
		case now := <-cleanup.C:
			for key, session := range sessions {
				if now.Sub(session.lastSeen) > 5*time.Minute {
					delete(sessions, key)
				}
			}
			cutoff := now.Add(-10 * time.Second)
			for host, times := range bursts {
				first := sort.Search(len(times), func(i int) bool { return !times[i].Before(cutoff) })
				if first == len(times) {
					delete(bursts, host)
				} else {
					bursts[host] = times[first:]
				}
			}
		case event := <-e.events:
			key := sessionKey(event.ruleID, event.connectionID)
			session := sessions[key]
			switch event.kind {
			case "begin":
				session = newDetectionSession(event)
				sessions[key] = session
				e.detectBurst(session, bursts)
			case "end":
				delete(sessions, key)
			case "chunk":
				if session == nil {
					session = newDetectionSession(event)
					sessions[key] = session
				}
				session.lastSeen = time.Now()
				e.inspectChunk(session, event.direction, event.data)
			}
		}
	}
}

func newDetectionSession(event detectionEvent) *detectionSession {
	return &detectionSession{ruleID: event.ruleID, ruleName: event.ruleName, connectionID: event.connectionID, remote: event.remote, target: event.target, protocol: event.protocol, autoPin: event.autoPin, lastSeen: time.Now(), buffers: make(map[string][]byte), matched: make(map[string]bool)}
}

func (e *DetectorEngine) detectBurst(session *detectionSession, bursts map[string][]time.Time) {
	e.mu.RLock()
	builtins := e.config.Builtins
	e.mu.RUnlock()
	if !builtins {
		return
	}
	host, _, err := net.SplitHostPort(session.remote)
	if err != nil {
		host = session.remote
	}
	now := time.Now()
	cutoff := now.Add(-10 * time.Second)
	times := bursts[host]
	first := sort.Search(len(times), func(i int) bool { return !times[i].Before(cutoff) })
	times = append(times[first:], now)
	bursts[host] = times
	if len(times) == 20 {
		e.addSignal(session, DetectionSignal{DetectorID: "builtin-burst", DetectorName: "Всплеск соединений", Direction: "any", Score: 25, Reason: "20 соединений от клиента за 10 секунд"})
	}
}

func (e *DetectorEngine) inspectChunk(session *detectionSession, direction string, data []byte) {
	e.mu.RLock()
	config := e.config
	detectors := append([]compiledDetector(nil), e.compiled...)
	e.mu.RUnlock()
	buffer := append(session.buffers[direction], data...)
	if len(buffer) > config.BufferBytes {
		buffer = append([]byte(nil), buffer[len(buffer)-config.BufferBytes:]...)
	}
	session.buffers[direction] = buffer
	for _, detector := range detectors {
		if session.matched[detector.spec.ID] || detector.spec.Direction != "any" && detector.spec.Direction != direction || !detectorApplies(detector.spec, session.ruleID) {
			continue
		}
		scoped := detectionScope(buffer, direction, detector.spec.Scope)
		start, end, ok := detectorMatch(detector, scoped)
		if !ok {
			if decoded := decodeInspectionData(scoped); decoded != nil {
				scoped = decoded
				start, end, ok = detectorMatch(detector, scoped)
			}
		}
		if !ok {
			continue
		}
		excerpt := findingExcerpt(scoped, start, end)
		if detector.spec.Sensitive {
			excerpt = "[скрыто: чувствительный шаблон]"
		}
		e.addSignal(session, DetectionSignal{DetectorID: detector.spec.ID, DetectorName: detector.spec.Name, Direction: direction, Score: detector.spec.Score, Reason: detector.spec.Name, Excerpt: excerpt})
	}
}

// decodeInspectionData gives detectors a normalized view of URL-encoded HTTP
// traffic while preserving the raw stream for captures and excerpts by default.
func decodeInspectionData(data []byte) []byte {
	if len(data) == 0 || !bytes.ContainsAny(data, "%+") || !utf8.Valid(data) {
		return nil
	}
	decoded, err := url.QueryUnescape(string(data))
	if err != nil || decoded == string(data) {
		return nil
	}
	return []byte(decoded)
}

func detectorApplies(spec DetectorSpec, ruleID string) bool {
	if len(spec.RuleIDs) == 0 {
		return true
	}
	for _, id := range spec.RuleIDs {
		if id == ruleID {
			return true
		}
	}
	return false
}

func detectionScope(data []byte, direction, scope string) []byte {
	if scope == "stream" {
		return data
	}
	separator := bytes.Index(data, []byte("\r\n\r\n"))
	separatorSize := 4
	if separator < 0 {
		separator = bytes.Index(data, []byte("\n\n"))
		separatorSize = 2
	}
	switch scope {
	case "http_headers":
		if separator >= 0 {
			return data[:separator]
		}
		return data
	case "http_body":
		if separator >= 0 {
			return data[separator+separatorSize:]
		}
		return nil
	case "http_path":
		if direction != DirIn {
			return nil
		}
		lineEnd := bytes.IndexByte(data, '\n')
		if lineEnd < 0 {
			return nil
		}
		parts := bytes.Fields(data[:lineEnd])
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return nil
}

func detectorMatch(detector compiledDetector, data []byte) (int, int, bool) {
	if len(data) == 0 {
		return 0, 0, false
	}
	if detector.re != nil {
		match := detector.re.FindIndex(data)
		if match == nil {
			return 0, 0, false
		}
		return match[0], match[1], true
	}
	haystack := data
	if detector.spec.CaseInsensitive && detector.spec.Mode == "text" {
		haystack = bytes.ToLower(data)
	}
	start := bytes.Index(haystack, detector.needle)
	return start, start + len(detector.needle), start >= 0
}

func findingExcerpt(data []byte, start, end int) string {
	if start < 0 {
		return ""
	}
	left, right := start-48, end+48
	if left < 0 {
		left = 0
	}
	if right > len(data) {
		right = len(data)
	}
	chunk := append([]byte(nil), data[left:right]...)
	for i, b := range chunk {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			chunk[i] = '.'
		}
	}
	if !utf8.Valid(chunk) {
		return hex.EncodeToString(chunk)
	}
	return strings.TrimSpace(string(chunk))
}

func findingSeverity(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 35:
		return "medium"
	default:
		return "low"
	}
}

func (e *DetectorEngine) addSignal(session *detectionSession, signal DetectionSignal) {
	if session.matched[signal.DetectorID] {
		return
	}
	session.matched[signal.DetectorID] = true
	now := time.Now()
	created := false
	e.mu.Lock()
	if session.finding == nil {
		session.finding = &Finding{At: now, UpdatedAt: now, RuleID: session.ruleID, RuleName: session.ruleName, ConnectionID: session.connectionID, RemoteAddr: session.remote, Target: session.target, Protocol: session.protocol}
	}
	session.finding.Signals = append(session.finding.Signals, signal)
	session.finding.Score += signal.Score
	if session.finding.Score > 100 {
		session.finding.Score = 100
	}
	session.finding.Severity = findingSeverity(session.finding.Score)
	session.finding.UpdatedAt = now
	config := e.config
	if session.finding.ID == 0 && session.finding.Score >= config.Threshold {
		e.sequence++
		session.finding.ID = e.sequence
		e.findings = append([]*Finding{session.finding}, e.findings...)
		if len(e.findings) > config.MaxFindings {
			e.findings = e.findings[:config.MaxFindings]
		}
		created = true
	}
	autoPin := session.autoPin && session.finding.ID != 0 && session.finding.Score >= config.AutoPinScore && !session.finding.AutoPinned
	if autoPin {
		session.finding.AutoPinned = true
	}
	hook := e.hook
	finding := *session.finding.clone()
	e.mu.Unlock()
	if session.finding.ID != 0 && hook != nil {
		hook(finding, created, autoPin)
	}
}
