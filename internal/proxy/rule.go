package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Rule — правило проброса вместе со своим рантайм-состоянием.
type Rule struct {
	// 64-битные счётчики держим первыми: atomic-операции над ними требуют
	// 8-байтового выравнивания на 32-битных платформах.
	totalConns  int64
	activeConns int64
	failedConns int64
	deniedConns int64
	bytesIn     int64
	bytesOut    int64
	lastActive  int64 // unix nano
	connSeq     uint64

	mu      sync.RWMutex
	spec    RuleSpec
	acl     []*net.IPNet
	ln      net.Listener
	running bool
	lastErr string

	// health
	targetUp    bool
	backupUp    bool
	usingBackup bool
	failStreak  int
	riseStreak  int
	bkFailStrk  int
	bkRiseStrk  int
	lastCheck   time.Time

	rec *Recorder

	conns  map[uint64]net.Conn // активные клиентские соединения, для форс-закрытия
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func newRule(spec RuleSpec) (*Rule, error) {
	spec.applyDefaults()
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	acl, err := parseACL(spec.AllowCIDR)
	if err != nil {
		return nil, err
	}
	return &Rule{
		spec:     spec,
		acl:      acl,
		conns:    make(map[uint64]net.Conn),
		rec:      NewRecorder(spec.Dump.MaxConns, spec.Dump.MaxBytesPer),
		targetUp: true, // до первой проверки считаем таргет живым
		backupUp: true,
	}, nil
}

// Spec отдаёт копию конфигурации правила.
func (r *Rule) Spec() RuleSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.spec
}

func (r *Rule) ID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.spec.ID
}

// Dumps отдаёт записанный трафик правила.
func (r *Rule) Dumps() []*ConnDump { return r.rec.List() }

// ClearDumps стирает записанный трафик.
func (r *Rule) ClearDumps() { r.rec.Clear() }

// Start поднимает слушатель. Повторный вызов на уже запущенном правиле — no-op.
func (r *Rule) Start() error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil
	}
	spec := r.spec
	r.mu.Unlock()

	ln, err := net.Listen("tcp", spec.ListenAddr())
	if err != nil {
		r.mu.Lock()
		r.lastErr = err.Error()
		r.mu.Unlock()
		return fmt.Errorf("не удалось занять %s: %w", spec.ListenAddr(), err)
	}

	r.mu.Lock()
	r.ln = ln
	r.running = true
	r.lastErr = ""
	r.stopCh = make(chan struct{})
	stopCh := r.stopCh
	r.mu.Unlock()

	r.wg.Add(1)
	go r.acceptLoop(ln, stopCh)

	if spec.Health.Enabled {
		r.wg.Add(1)
		go r.healthLoop(stopCh)
	}
	return nil
}

// Stop закрывает слушатель, рвёт активные соединения и дожидается горутин.
func (r *Rule) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	ln := r.ln
	r.ln = nil
	if r.stopCh != nil {
		close(r.stopCh)
		r.stopCh = nil
	}
	conns := make([]net.Conn, 0, len(r.conns))
	for _, c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	// Закрытие клиентской стороны разблокирует пайпы, те закроют таргет.
	for _, c := range conns {
		c.Close()
	}
	r.wg.Wait()
}

func (r *Rule) acceptLoop(ln net.Listener, stopCh chan struct{}) {
	defer r.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stopCh:
				return // штатная остановка
			default:
			}
			// Временная ошибка (кончились дескрипторы и т.п.) — переждём.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			r.mu.Lock()
			r.lastErr = err.Error()
			r.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.handle(conn, stopCh)
		}()
	}
}

// allowed проверяет клиента по белому списку подсетей.
func (r *Rule) allowed(addr net.Addr) bool {
	r.mu.RLock()
	acl := r.acl
	r.mu.RUnlock()
	if len(acl) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range acl {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// currentTarget выбирает, куда слать: основной адрес или резервный.
func (r *Rule) currentTarget() (Endpoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.usingBackup && r.spec.Backup != nil && !r.spec.Backup.IsZero() {
		return *r.spec.Backup, true
	}
	return r.spec.Target, false
}

func (r *Rule) handle(client net.Conn, stopCh chan struct{}) {
	defer client.Close()

	if !r.allowed(client.RemoteAddr()) {
		atomic.AddInt64(&r.deniedConns, 1)
		return
	}

	r.mu.RLock()
	spec := r.spec
	r.mu.RUnlock()

	if spec.MaxConns > 0 && atomic.LoadInt64(&r.activeConns) >= int64(spec.MaxConns) {
		atomic.AddInt64(&r.deniedConns, 1)
		return
	}

	target, viaBackup := r.currentTarget()
	dialTimeout := time.Duration(spec.DialTimeoutMS) * time.Millisecond
	upstream, err := net.DialTimeout("tcp", target.Addr(), dialTimeout)
	if err != nil {
		atomic.AddInt64(&r.failedConns, 1)
		r.mu.Lock()
		r.lastErr = fmt.Sprintf("%s: %v", target.Addr(), err)
		r.mu.Unlock()
		// Живой трафик — тоже сигнал о здоровье таргета.
		r.noteProbe(!viaBackup, false)
		return
	}
	defer upstream.Close()
	r.noteProbe(!viaBackup, true)

	id := atomic.AddUint64(&r.connSeq, 1)
	atomic.AddInt64(&r.totalConns, 1)
	atomic.AddInt64(&r.activeConns, 1)
	defer atomic.AddInt64(&r.activeConns, -1)

	r.mu.Lock()
	r.conns[id] = client
	dumpOn := r.spec.Dump.Enabled
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.conns, id)
		r.mu.Unlock()
	}()

	var w *connWriter
	if dumpOn {
		w = r.rec.Begin(id, client.RemoteAddr().String(), target.Addr())
	}

	// Отмена по Stop(): рвём обе стороны, пайпы выйдут по ошибке чтения.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-stopCh:
			client.Close()
			upstream.Close()
		case <-done:
		}
	}()

	idle := time.Duration(spec.IdleTimeoutSec) * time.Second
	var in, out int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		in = r.pipe(upstream, client, DirIn, w, idle, &r.bytesIn)
	}()
	go func() {
		defer wg.Done()
		out = r.pipe(client, upstream, DirOut, w, idle, &r.bytesOut)
	}()
	wg.Wait()

	if w != nil {
		w.Finish(in, out)
	}
}

// pipe качает байты src -> dst, считая статистику и (опционально) записывая дамп.
// Возвращает количество перенесённых байт.
func (r *Rule) pipe(dst, src net.Conn, dir string, w *connWriter, idle time.Duration, counter *int64) int64 {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if idle > 0 {
			src.SetReadDeadline(time.Now().Add(idle))
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			total += int64(n)
			atomic.AddInt64(counter, int64(n))
			atomic.StoreInt64(&r.lastActive, time.Now().UnixNano())
			w.Write(dir, buf[:n])
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				// таймаут простоя или разрыв — в обоих случаях выходим
				_ = rerr
			}
			break
		}
	}
	// Полузакрытие: даём второй стороне дочитать хвост, не убивая соединение.
	if tc, ok := dst.(*net.TCPConn); ok {
		tc.CloseWrite()
	} else {
		dst.Close()
	}
	return total
}

// Snapshot — состояние правила для API.
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
	s := Snapshot{
		Spec:        r.spec,
		Running:     r.running,
		LastError:   r.lastErr,
		TargetUp:    r.targetUp,
		BackupUp:    r.backupUp,
		UsingBackup: r.usingBackup,
		LastCheck:   r.lastCheck,
	}
	r.mu.RUnlock()

	s.ActiveConns = atomic.LoadInt64(&r.activeConns)
	s.TotalConns = atomic.LoadInt64(&r.totalConns)
	s.FailedConns = atomic.LoadInt64(&r.failedConns)
	s.DeniedConns = atomic.LoadInt64(&r.deniedConns)
	s.BytesIn = atomic.LoadInt64(&r.bytesIn)
	s.BytesOut = atomic.LoadInt64(&r.bytesOut)
	if la := atomic.LoadInt64(&r.lastActive); la > 0 {
		s.LastActive = la / int64(time.Millisecond)
	}
	if r.spec.Dump.Enabled {
		s.DumpCount = len(r.rec.List())
	}
	return s
}

// ResetStats обнуляет счётчики правила.
func (r *Rule) ResetStats() {
	atomic.StoreInt64(&r.totalConns, 0)
	atomic.StoreInt64(&r.failedConns, 0)
	atomic.StoreInt64(&r.deniedConns, 0)
	atomic.StoreInt64(&r.bytesIn, 0)
	atomic.StoreInt64(&r.bytesOut, 0)
	atomic.StoreInt64(&r.lastActive, 0)
}
