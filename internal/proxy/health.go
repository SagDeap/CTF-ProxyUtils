package proxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
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
		started := time.Now()
		err := runHealthProbe(probeCtx, spec, endpoint)
		cancel()
		if ctx.Err() == nil {
			result := HealthResult{At: time.Now(), OK: err == nil, LatencyMS: time.Since(started).Milliseconds()}
			if err != nil {
				result.Error = err.Error()
			}
			r.mu.Lock()
			if primary {
				r.targetHealth = result
			} else {
				r.backupHealth = result
			}
			r.mu.Unlock()
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

func runHealthProbe(ctx context.Context, spec RuleSpec, endpoint Endpoint) error {
	mode := spec.Health.Mode
	if mode == "" {
		mode = "tcp"
	}
	if mode == "http" {
		if spec.Protocol == "udp" {
			return errors.New("HTTP health-check недоступен для UDP")
		}
		return runHTTPHealthProbe(ctx, spec.Health, endpoint)
	}
	network := spec.Protocol
	if network == "" {
		network = "tcp"
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, endpoint.Addr())
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if mode == "tcp" {
		return nil
	}
	request, err := decodeHealthBytes(spec.Health.RequestMode, spec.Health.Request)
	if err != nil {
		return fmt.Errorf("запрос: %w", err)
	}
	if len(request) > 0 {
		if _, err := conn.Write(request); err != nil {
			return err
		}
	}
	if spec.Health.Expect == "" {
		return nil
	}
	return readHealthResponse(conn, spec.Health.ExpectMode, spec.Health.Expect)
}

func readHealthResponse(reader io.Reader, mode, pattern string) error {
	response := make([]byte, 0, 4096)
	buffer := make([]byte, 4096)
	for len(response) < 64*1024 {
		n, err := reader.Read(buffer)
		if n > 0 {
			response = append(response, buffer[:n]...)
			if matchHealthResponse(mode, pattern, response) {
				return nil
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return errors.New("ответ не совпал с ожидаемым шаблоном")
}

func runHTTPHealthProbe(ctx context.Context, health HealthSpec, endpoint Endpoint) error {
	method := health.HTTPMethod
	if method == "" {
		method = http.MethodGet
	}
	path := health.HTTPPath
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://"+endpoint.Addr()+path, strings.NewReader(health.Request))
	if err != nil {
		return err
	}
	if health.HTTPHost != "" {
		request.Host = health.HTTPHost
	}
	for key, value := range health.HTTPHeaders {
		request.Header.Set(key, value)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Duration(health.TimeoutMS) * time.Millisecond}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if health.HTTPStatus > 0 && response.StatusCode != health.HTTPStatus {
		return fmt.Errorf("HTTP %d вместо %d", response.StatusCode, health.HTTPStatus)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return err
	}
	if health.Expect != "" && !matchHealthResponse(health.ExpectMode, health.Expect, body) {
		return errors.New("HTTP-тело не совпало с ожидаемым шаблоном")
	}
	return nil
}

func decodeHealthBytes(mode, value string) ([]byte, error) {
	if mode == "hex" {
		return hex.DecodeString(strings.Join(strings.Fields(value), ""))
	}
	return []byte(value), nil
}

func matchHealthResponse(mode, pattern string, response []byte) bool {
	switch mode {
	case "hex":
		value, err := hex.DecodeString(strings.Join(strings.Fields(pattern), ""))
		return err == nil && bytes.Contains(response, value)
	case "regex":
		re, err := regexp.Compile(pattern)
		return err == nil && re.Match(response)
	default:
		return bytes.Contains(response, []byte(pattern))
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
