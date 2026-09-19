package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// udpSession maps one client address to one connected upstream socket until it
// stays idle. Connected UDP sockets let the kernel reject unrelated replies.
type udpSession struct {
	// Keep 64-bit atomics aligned on 32-bit platforms.
	last     int64
	bytesIn  int64
	bytesOut int64

	rule     *Rule
	key      string
	id       uint64
	client   net.Addr
	target   Endpoint
	upstream net.Conn
	writer   *connWriter
	once     sync.Once
}

func (s *udpSession) touch() {
	atomic.StoreInt64(&s.last, time.Now().UnixNano())
	idle := time.Duration(s.rule.Spec().UDPIdleSec) * time.Second
	if idle > 0 {
		s.upstream.SetReadDeadline(time.Now().Add(idle))
	}
}

func (s *udpSession) close() {
	s.once.Do(func() {
		s.upstream.Close()
		if s.writer != nil {
			s.writer.Finish(atomic.LoadInt64(&s.bytesIn), atomic.LoadInt64(&s.bytesOut))
		}
	})
}

func (r *Rule) udpLoop(pc net.PacketConn, ctx context.Context) {
	defer r.wg.Done()
	buffer := make([]byte, 64*1024)
	for {
		n, remote, err := pc.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.mu.Lock()
			r.lastErr = err.Error()
			r.mu.Unlock()
			continue
		}
		r.mu.RLock()
		allowed := allowedByACL(remote, r.acl)
		r.mu.RUnlock()
		if !allowed {
			atomic.AddInt64(&r.deniedConns, 1)
			continue
		}
		payload := append([]byte(nil), buffer[:n]...)
		r.handleUDPDatagram(ctx, pc, remote, payload)
	}
}

func (r *Rule) handleUDPDatagram(ctx context.Context, pc net.PacketConn, remote net.Addr, payload []byte) {
	key := remote.String()
	r.mu.Lock()
	if !r.running || ctx.Err() != nil {
		r.mu.Unlock()
		return
	}
	spec := r.spec.Clone()
	target, viaBackup := r.currentTargetLocked()
	session := r.udpSessions[key]
	if session != nil && session.target != target {
		delete(r.udpSessions, key)
		session.close()
		session = nil
		atomic.AddInt64(&r.activeConns, -1)
	}
	if session == nil && spec.MaxConns > 0 && len(r.udpSessions) >= spec.MaxConns {
		r.mu.Unlock()
		atomic.AddInt64(&r.deniedConns, 1)
		return
	}
	r.mu.Unlock()

	if session == nil {
		dialCtx, cancel := context.WithTimeout(ctx, time.Duration(spec.DialTimeoutMS)*time.Millisecond)
		upstream, err := r.dialContext(dialCtx, "udp", target.Addr())
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				atomic.AddInt64(&r.failedConns, 1)
				r.mu.Lock()
				r.lastErr = fmt.Sprintf("%s: %v", target.Addr(), err)
				r.emitLocked("connection_failed", r.lastErr)
				r.mu.Unlock()
				r.noteEndpointProbe(!viaBackup, target, false)
			}
			return
		}
		id := atomic.AddUint64(&r.connSeq, 1)
		var writer *connWriter
		if spec.Dump.Enabled || spec.Inspect.Enabled {
			writer = r.rec.BeginProtocol(id, remote.String(), target.Addr(), "udp")
		}
		if spec.Inspect.Enabled && r.detector != nil {
			if writer == nil {
				writer = &connWriter{}
			}
			remoteAddr, targetAddr, ruleID, ruleName := remote.String(), target.Addr(), spec.ID, spec.Name
			r.detector.Begin(ruleID, ruleName, id, remoteAddr, targetAddr, "udp", spec.Inspect.AutoPin)
			writer.observe = func(direction string, data []byte) {
				r.detector.Observe(ruleID, ruleName, id, remoteAddr, targetAddr, "udp", direction, data, spec.Inspect.AutoPin)
			}
			writer.onFinish = func() { r.detector.End(ruleID, id) }
		}
		session = &udpSession{rule: r, key: key, id: id, client: remote, target: target, upstream: upstream, writer: writer}
		session.touch()
		r.mu.Lock()
		if !r.running || ctx.Err() != nil {
			r.mu.Unlock()
			session.close()
			return
		}
		if existing := r.udpSessions[key]; existing != nil {
			r.mu.Unlock()
			session.close()
			session = existing
		} else {
			r.udpSessions[key] = session
			r.mu.Unlock()
			atomic.AddInt64(&r.activeConns, 1)
			atomic.AddInt64(&r.totalConns, 1)
			r.noteEndpointProbe(!viaBackup, target, true)
			r.wg.Add(1)
			go r.readUDPReplies(ctx, pc, session)
		}
	}

	session.touch()
	n, err := session.upstream.Write(payload)
	if n > 0 {
		if session.writer != nil {
			session.writer.WriteDatagram(DirIn, payload[:n])
		}
		atomic.AddInt64(&session.bytesIn, int64(n))
		atomic.AddInt64(&r.bytesIn, int64(n))
		atomic.StoreInt64(&r.lastActive, time.Now().UnixNano())
	}
	if err != nil {
		atomic.AddInt64(&r.failedConns, 1)
		r.removeUDPSession(session)
	}
}

func (r *Rule) readUDPReplies(ctx context.Context, pc net.PacketConn, session *udpSession) {
	defer r.wg.Done()
	defer r.removeUDPSession(session)
	buffer := make([]byte, 64*1024)
	for {
		n, err := session.upstream.Read(buffer)
		if n > 0 {
			if _, writeErr := pc.WriteTo(buffer[:n], session.client); writeErr != nil {
				return
			}
			session.touch()
			if session.writer != nil {
				session.writer.WriteDatagram(DirOut, buffer[:n])
			}
			atomic.AddInt64(&session.bytesOut, int64(n))
			atomic.AddInt64(&r.bytesOut, int64(n))
			atomic.StoreInt64(&r.lastActive, time.Now().UnixNano())
		}
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			idle := time.Duration(r.Spec().UDPIdleSec) * time.Second
			if time.Since(time.Unix(0, atomic.LoadInt64(&session.last))) < idle {
				session.touch()
				continue
			}
		}
		return
	}
}

func (r *Rule) removeUDPSession(session *udpSession) {
	r.mu.Lock()
	if r.udpSessions[session.key] == session {
		delete(r.udpSessions, session.key)
		atomic.AddInt64(&r.activeConns, -1)
	}
	r.mu.Unlock()
	session.close()
}
