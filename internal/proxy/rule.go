package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Rule owns one listener and its connections. lifeMu serializes lifecycle and
// configuration changes; mu protects the state exposed to API readers.
type Rule struct {
	// Keep 64-bit atomics aligned on 32-bit platforms.
	totalConns  int64
	activeConns int64 // includes reserved slots while dialing
	failedConns int64
	deniedConns int64
	bytesIn     int64
	bytesOut    int64
	lastActive  int64
	connSeq     uint64

	lifeMu       sync.Mutex
	mu           sync.RWMutex
	spec         RuleSpec
	acl          []*net.IPNet
	ln           net.Listener
	running      bool
	lastErr      string
	ctx          context.Context
	cancel       context.CancelFunc
	healthCancel context.CancelFunc
	wg           sync.WaitGroup
	healthWG     sync.WaitGroup
	conns        map[uint64]net.Conn
	dialContext  func(context.Context, string, string) (net.Conn, error)

	targetUp           bool
	backupUp           bool
	usingBackup        bool
	failStreak         int
	riseStreak         int
	bkFailStrk         int
	bkRiseStrk         int
	lastCheck          time.Time
	lastFailureEvent   time.Time
	suppressedFailures int
	event              func(ruleID, ruleName, kind, message string)
	rec                *Recorder
}

func newRule(spec RuleSpec) (*Rule, error) {
	spec = spec.Clone()
	spec.applyDefaults()
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	acl, err := parseACL(spec.AllowCIDR)
	if err != nil {
		return nil, err
	}
	r := &Rule{
		spec: spec, acl: acl, conns: make(map[uint64]net.Conn),
		rec:      NewRecorder(spec.Dump.MaxConns, spec.Dump.MaxBytesPer),
		targetUp: true, backupUp: true,
		dialContext: (&net.Dialer{}).DialContext,
	}
	r.usingBackup = spec.RoutingMode == "backup"
	return r, nil
}

func (r *Rule) Spec() RuleSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.spec.Clone()
}

func (r *Rule) ID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.spec.ID
}

func (r *Rule) Dumps() []*ConnDump                            { return r.rec.List() }
func (r *Rule) ClearDumps()                                   { r.rec.Clear() }
func (r *Rule) SearchDumps(query DumpQuery) (DumpPage, error) { return r.rec.Search(query) }
func (r *Rule) GetDump(id uint64) (*ConnDump, bool)           { return r.rec.Get(id) }
func (r *Rule) PinDump(id uint64, pinned bool) error          { return r.rec.SetPinned(id, pinned) }

func (r *Rule) emitLocked(kind, message string) {
	if r.event != nil {
		r.event(r.spec.ID, r.spec.Name, kind, message)
	}
}

func (r *Rule) emit(kind, message string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.emitLocked(kind, message)
}

// Start is safe to call concurrently with Stop or another Start.
func (r *Rule) Start() error {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	return r.startLocked(nil)
}

// startLocked accepts an already bound listener for transactional updates.
func (r *Rule) startLocked(ln net.Listener) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		if ln != nil {
			ln.Close()
		}
		return nil
	}
	spec := r.spec.Clone()
	r.mu.Unlock()
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", spec.ListenAddr())
		if err != nil {
			r.mu.Lock()
			r.lastErr = err.Error()
			r.emitLocked("start_failed", err.Error())
			r.mu.Unlock()
			return fmt.Errorf("не удалось занять %s: %w", spec.ListenAddr(), err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.ln, r.ctx, r.cancel = ln, ctx, cancel
	r.running, r.lastErr = true, ""
	r.emitLocked("started", "Проброс запущен: "+spec.ListenAddr())
	r.mu.Unlock()
	r.wg.Add(1)
	go r.acceptLoop(ln, ctx)
	r.startHealthLocked()
	return nil
}

func (r *Rule) Stop() {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	r.stopLocked()
}

func (r *Rule) stopLocked() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	ln, cancel := r.ln, r.cancel
	r.ln, r.cancel = nil, nil
	conns := make([]net.Conn, 0, len(r.conns))
	for _, conn := range r.conns {
		conns = append(conns, conn)
	}
	r.mu.Unlock()
	cancel() // also interrupts DNS, pending dials and health probes
	ln.Close()
	for _, conn := range conns {
		conn.Close()
	}
	r.stopHealthLocked()
	r.wg.Wait()
	r.emit("stopped", "Проброс остановлен")
}

func (r *Rule) acceptLoop(ln net.Listener, ctx context.Context) {
	defer r.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.mu.Lock()
			r.lastErr = err.Error()
			r.mu.Unlock()
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		// acceptLoop itself remains in wg until no further Add can happen.
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.handle(conn, ctx) }()
	}
}

func allowedByACL(addr net.Addr, acl []*net.IPNet) bool {
	if len(acl) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	for _, network := range acl {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *Rule) currentTarget() (Endpoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentTargetLocked()
}

func (r *Rule) currentTargetLocked() (Endpoint, bool) {
	if r.usingBackup && r.spec.Backup != nil && !r.spec.Backup.IsZero() {
		return *r.spec.Backup, true
	}
	return r.spec.Target, false
}

func (r *Rule) handle(client net.Conn, ctx context.Context) {
	defer client.Close()
	r.mu.Lock()
	if !r.running || ctx.Err() != nil {
		r.mu.Unlock()
		return
	}
	if !allowedByACL(client.RemoteAddr(), r.acl) || (r.spec.MaxConns > 0 && len(r.conns) >= r.spec.MaxConns) {
		r.mu.Unlock()
		atomic.AddInt64(&r.deniedConns, 1)
		return
	}
	// Reserve capacity and register for Stop before starting a potentially slow dial.
	id := atomic.AddUint64(&r.connSeq, 1)
	r.conns[id] = client
	atomic.AddInt64(&r.activeConns, 1)
	spec := r.spec.Clone()
	target, viaBackup := r.currentTargetLocked()
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.conns, id)
		atomic.AddInt64(&r.activeConns, -1)
		r.mu.Unlock()
	}()
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(spec.DialTimeoutMS)*time.Millisecond)
	upstream, err := r.dialContext(dialCtx, "tcp", target.Addr())
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		atomic.AddInt64(&r.failedConns, 1)
		r.mu.Lock()
		r.lastErr = fmt.Sprintf("%s: %v", target.Addr(), err)
		if time.Since(r.lastFailureEvent) >= 5*time.Second {
			message := r.lastErr
			if r.suppressedFailures > 0 {
				message += fmt.Sprintf(" (ещё %d ошибок за интервал)", r.suppressedFailures)
			}
			r.emitLocked("connection_failed", message)
			r.lastFailureEvent, r.suppressedFailures = time.Now(), 0
		} else {
			r.suppressedFailures++
		}
		r.mu.Unlock()
		r.noteEndpointProbe(!viaBackup, target, false)
		return
	}
	defer upstream.Close()
	if ctx.Err() != nil {
		return
	}
	r.noteEndpointProbe(!viaBackup, target, true)
	atomic.AddInt64(&r.totalConns, 1)
	var writer *connWriter
	if spec.Dump.Enabled {
		writer = r.rec.Begin(id, client.RemoteAddr().String(), target.Addr())
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
			upstream.Close()
		case <-done:
		}
	}()
	stream := &relay{client: client, upstream: upstream, idle: time.Duration(spec.IdleTimeoutSec) * time.Second}
	stream.touch()
	var in, out int64
	var pipes sync.WaitGroup
	pipes.Add(2)
	go func() { defer pipes.Done(); in = r.pipe(upstream, client, DirIn, writer, stream, &r.bytesIn) }()
	go func() { defer pipes.Done(); out = r.pipe(client, upstream, DirOut, writer, stream, &r.bytesOut) }()
	pipes.Wait()
	writer.Finish(in, out)
}

type relay struct {
	client, upstream net.Conn
	idle             time.Duration
	mu               sync.Mutex
}

// Reads share one idle clock: an active one-way stream keeps both halves alive.
// Write deadlines are separate so a peer that stops reading cannot stall forever.
func (s *relay) touch() {
	if s.idle <= 0 {
		return
	}
	s.mu.Lock()
	deadline := time.Now().Add(s.idle)
	s.client.SetReadDeadline(deadline)
	s.upstream.SetReadDeadline(deadline)
	s.mu.Unlock()
}

func (s *relay) close() { s.client.Close(); s.upstream.Close() }

func (r *Rule) pipe(dst, src net.Conn, dir string, writer *connWriter, stream *relay, counter *int64) int64 {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			stream.touch()
			for offset := 0; offset < n; {
				if stream.idle > 0 {
					dst.SetWriteDeadline(time.Now().Add(stream.idle))
				}
				written, writeErr := dst.Write(buf[offset:n])
				if written > 0 {
					writer.Write(dir, buf[offset:offset+written])
					total += int64(written)
					atomic.AddInt64(counter, int64(written))
					atomic.StoreInt64(&r.lastActive, time.Now().UnixNano())
					stream.touch()
					offset += written
				}
				if writeErr != nil || written == 0 {
					stream.close()
					return total
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if half, ok := dst.(interface{ CloseWrite() error }); ok {
					half.CloseWrite()
				} else {
					dst.Close()
				}
			} else {
				stream.close()
			}
			return total
		}
	}
}

type Snapshot struct {
	Spec        RuleSpec  `json:"spec"`
	Running     bool      `json:"running"`
	LastError   string    `json:"last_error,omitempty"`
	ActiveConns int64     `json:"active_conns"`
	TotalConns  int64     `json:"total_conns"`
	FailedConns int64     `json:"failed_conns"`
	DeniedConns int64     `json:"denied_conns"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	LastActive  int64     `json:"last_active_unix_ms"`
	TargetUp    bool      `json:"target_up"`
	BackupUp    bool      `json:"backup_up"`
	UsingBackup bool      `json:"using_backup"`
	LastCheck   time.Time `json:"last_check,omitempty"`
	DumpCount   int       `json:"dump_count"`
}

func (r *Rule) Snapshot() Snapshot {
	r.mu.RLock()
	s := Snapshot{Spec: r.spec.Clone(), Running: r.running, LastError: r.lastErr,
		TargetUp: r.targetUp, BackupUp: r.backupUp, UsingBackup: r.usingBackup, LastCheck: r.lastCheck}
	r.mu.RUnlock()
	s.ActiveConns = atomic.LoadInt64(&r.activeConns)
	s.TotalConns = atomic.LoadInt64(&r.totalConns)
	s.FailedConns = atomic.LoadInt64(&r.failedConns)
	s.DeniedConns = atomic.LoadInt64(&r.deniedConns)
	s.BytesIn = atomic.LoadInt64(&r.bytesIn)
	s.BytesOut = atomic.LoadInt64(&r.bytesOut)
	s.LastActive = atomic.LoadInt64(&r.lastActive) / int64(time.Millisecond)
	s.DumpCount = r.rec.Count()
	return s
}

func (r *Rule) ResetStats() {
	atomic.StoreInt64(&r.totalConns, 0)
	atomic.StoreInt64(&r.failedConns, 0)
	atomic.StoreInt64(&r.deniedConns, 0)
	atomic.StoreInt64(&r.bytesIn, 0)
	atomic.StoreInt64(&r.bytesOut, 0)
	atomic.StoreInt64(&r.lastActive, 0)
	r.emit("stats_reset", "Счётчики сброшены")
}
