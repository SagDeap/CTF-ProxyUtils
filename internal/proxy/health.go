package proxy

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Health workers can restart without closing active client connections.
func (r *Rule) startHealthLocked() {
	r.mu.Lock()
	if !r.running || !r.spec.Health.Enabled {
		r.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(r.ctx)
	r.healthCancel = cancel
	spec := r.spec.Clone()
	r.mu.Unlock()
	r.healthWG.Add(1)
	go func() {
		defer r.healthWG.Done()
		r.probeOnce(ctx, spec)
		ticker := time.NewTicker(time.Duration(spec.Health.IntervalSec) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.probeOnce(ctx, spec)
			}
		}
	}()
}

func (r *Rule) stopHealthLocked() {
	r.mu.Lock()
	cancel := r.healthCancel
	r.healthCancel = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	r.healthWG.Wait()
}

func (r *Rule) probeOnce(ctx context.Context, spec RuleSpec) {
	probe := func(primary bool, endpoint Endpoint) {
		probeCtx, cancel := context.WithTimeout(ctx, time.Duration(spec.Health.TimeoutMS)*time.Millisecond)
		conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", endpoint.Addr())
		cancel()
		if conn != nil {
			conn.Close()
		}
		if ctx.Err() == nil {
			r.noteEndpointProbe(primary, endpoint, err == nil)
		}
	}
	probe(true, spec.Target)
	if ctx.Err() != nil {
		return
	}
	if spec.Backup != nil && !spec.Backup.IsZero() {
		probe(false, *spec.Backup)
	}
	if ctx.Err() == nil {
		r.mu.Lock()
		r.lastCheck = time.Now()
		r.mu.Unlock()
	}
}

// Ignore late outcomes from connections opened against a previous target.
func (r *Rule) noteEndpointProbe(primary bool, endpoint Endpoint, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if primary && r.spec.Target != endpoint {
		return
	}
	if !primary && (r.spec.Backup == nil || *r.spec.Backup != endpoint) {
		return
	}
	r.noteProbeLocked(primary, ok)
}

func (r *Rule) noteProbe(primary bool, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.noteProbeLocked(primary, ok)
}

func (r *Rule) noteProbeLocked(primary bool, ok bool) {
	failAfter, riseAfter := r.spec.Health.FailAfter, r.spec.Health.RiseAfter
	if failAfter <= 0 {
		failAfter = 2
	}
	if riseAfter <= 0 {
		riseAfter = 2
	}
	up, failed, risen := &r.targetUp, &r.failStreak, &r.riseStreak
	name := "Основной адрес"
	if !primary {
		up, failed, risen = &r.backupUp, &r.bkFailStrk, &r.bkRiseStrk
		name = "Резервный адрес"
	}
	before := *up
	if ok {
		*failed = 0
		if *risen < riseAfter {
			*risen++
		}
		if *risen >= riseAfter {
			*up = true
		}
	} else {
		*risen = 0
		if *failed < failAfter {
			*failed++
		}
		if *failed >= failAfter {
			*up = false
		}
	}
	if before != *up {
		state := "недоступен"
		if *up {
			state = "доступен"
		}
		r.emitLocked("health_changed", name+" "+state)
	}
	r.decideFailoverLocked()
}

func (r *Rule) decideFailoverLocked() {
	before := r.usingBackup
	hasBackup := r.spec.Backup != nil && !r.spec.Backup.IsZero()
	switch {
	case !hasBackup, r.spec.RoutingMode == "primary":
		r.usingBackup = false
	case r.spec.RoutingMode == "backup":
		r.usingBackup = true
	case r.spec.Health.Enabled:
		switch {
		case !r.usingBackup && !r.targetUp && r.backupUp && r.spec.Health.AutoFail:
			r.usingBackup = true
		case r.usingBackup && r.targetUp && r.spec.Health.AutoBack:
			r.usingBackup = false
		case r.usingBackup && !r.backupUp && r.targetUp:
			r.usingBackup = false
		}
	}
	if before != r.usingBackup {
		destination := "основной"
		if r.usingBackup {
			destination = "резерв"
		}
		r.emitLocked("route_changed", fmt.Sprintf("Новые соединения → %s (режим %s)", destination, r.spec.RoutingMode))
	}
}

func (r *Rule) setRoutingModeLocked(mode string) error {
	if mode != "auto" && mode != "primary" && mode != "backup" {
		return fmt.Errorf("режим маршрутизации должен быть auto, primary или backup")
	}
	if mode == "backup" && (r.spec.Backup == nil || r.spec.Backup.IsZero()) {
		return fmt.Errorf("резервный адрес не задан")
	}
	if r.spec.RoutingMode != mode {
		r.spec.RoutingMode = mode
		r.emitLocked("routing_mode", "Режим маршрутизации: "+mode)
	}
	r.decideFailoverLocked()
	return nil
}

// SwitchTo keeps the legacy API; manual choices remain until explicitly changed.
// Manager.SetRoutingMode additionally notifies configuration persistence.
func (r *Rule) SwitchTo(backup bool) {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	mode := "primary"
	if backup {
		mode = "backup"
	}
	r.setRoutingModeLocked(mode)
}
