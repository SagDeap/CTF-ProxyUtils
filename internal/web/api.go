package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
	"github.com/SagDeap/CTF-ProxyUtils/internal/scan"
)

const maxBody = 1 << 20

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "некорректный JSON: "+err.Error())
		return false
	}
	return true
}

// handleState — единственный опрашиваемый эндпоинт: отдаёт всё, что рисует
// панель, чтобы фронтенд не дёргал пять ручек в цикле.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": s.mgr.Snapshots(),
		"scan":  s.scanner.State(),
		"system": map[string]interface{}{
			"hostname":   host,
			"version":    s.version,
			"uptime_s":   int(time.Since(s.started).Seconds()),
			"config":     s.cfg.Path(),
			"web_addr":   s.cfg.Web.Addr,
			"auth":       s.cfg.Web.Token != "",
			"used_ports": s.mgr.UsedPorts(),
		},
		"scan_defaults": s.cfg.Scan,
	})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interfaces":   scan.Interfaces(),
		"default_cidr": scan.DefaultCIDR(),
		"ctf_ports":    scan.CTFPortRange,
	})
}

// handleRules: GET — список, POST — создание.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.mgr.Snapshots())
	case http.MethodPost:
		var spec proxy.RuleSpec
		if !decode(w, r, &spec) {
			return
		}
		rule, err := s.mgr.Add(spec)
		if err != nil {
			// Правило могло создаться, но не подняться (занятый порт) —
			// тогда отдаём и ошибку, и созданное правило.
			if rule != nil {
				writeJSON(w, http.StatusConflict, map[string]interface{}{
					"error": err.Error(),
					"rule":  rule.Snapshot(),
				})
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, rule.Snapshot())
	default:
		writeErr(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

// handleRuleItem разбирает /api/rules/{id}[/{action}] вручную:
// ServeMux из Go 1.18 шаблонов в путях не понимает.
func (s *Server) handleRuleItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusBadRequest, "не указан идентификатор правила")
		return
	}
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	rule, ok := s.mgr.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "правило не найдено")
		return
	}

	switch action {
	case "":
		s.ruleCRUD(w, r, id, rule)
	case "toggle":
		s.ruleToggle(w, r, id)
	case "switch":
		s.ruleSwitch(w, r, rule)
	case "reset":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "только POST")
			return
		}
		rule.ResetStats()
		writeJSON(w, http.StatusOK, rule.Snapshot())
	case "dumps":
		s.ruleDumps(w, r, rule)
	default:
		writeErr(w, http.StatusNotFound, "неизвестное действие")
	}
}

func (s *Server) ruleCRUD(w http.ResponseWriter, r *http.Request, id string, rule *proxy.Rule) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, rule.Snapshot())
	case http.MethodPut:
		var spec proxy.RuleSpec
		if !decode(w, r, &spec) {
			return
		}
		if err := s.mgr.Update(id, spec); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rule.Snapshot())
	case http.MethodDelete:
		if err := s.mgr.Delete(id); err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

func (s *Server) ruleToggle(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "только POST")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.mgr.SetEnabled(id, body.Enabled); err != nil {
		// Порт занят или таргет невалиден — правило осталось выключенным.
		rule, _ := s.mgr.Get(id)
		if rule != nil {
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"error": err.Error(),
				"rule":  rule.Snapshot(),
			})
			return
		}
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	rule, _ := s.mgr.Get(id)
	writeJSON(w, http.StatusOK, rule.Snapshot())
}

func (s *Server) ruleSwitch(w http.ResponseWriter, r *http.Request, rule *proxy.Rule) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "только POST")
		return
	}
	var body struct {
		Backup bool `json:"backup"`
	}
	if !decode(w, r, &body) {
		return
	}
	rule.SwitchTo(body.Backup)
	writeJSON(w, http.StatusOK, rule.Snapshot())
}

func (s *Server) ruleDumps(w http.ResponseWriter, r *http.Request, rule *proxy.Rule) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, rule.Dumps())
	case http.MethodDelete:
		rule.ClearDumps()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

// handleScan: GET — состояние, POST — запуск, DELETE — остановка.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.scanner.State())
	case http.MethodPost:
		var opts scan.Options
		if !decode(w, r, &opts) {
			return
		}
		if opts.CIDR == "" {
			opts.CIDR = scan.DefaultCIDR()
		}
		if err := s.scanner.Start(opts); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		// Запомним параметры, чтобы форма открывалась с ними в следующий раз.
		s.cfg.Scan.CIDR = opts.CIDR
		s.cfg.Scan.Ports = opts.Ports
		s.cfg.Scan.TimeoutMS = opts.TimeoutMS
		s.cfg.Scan.Concurrency = opts.Concurrency
		s.cfg.Scan.Fingerprint = opts.Fingerprint
		go s.cfg.Save()
		writeJSON(w, http.StatusAccepted, s.scanner.State())
	case http.MethodDelete:
		s.scanner.Stop()
		writeJSON(w, http.StatusOK, s.scanner.State())
	default:
		writeErr(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}
