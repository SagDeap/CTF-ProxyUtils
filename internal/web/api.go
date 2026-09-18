package web

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SagDeap/CTF-ProxyUtils/internal/config"
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
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeErr(w, http.StatusUnsupportedMediaType, "требуется Content-Type: application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "некорректный JSON: "+err.Error())
		return false
	}
	if err := dec.Decode(new(interface{})); err != io.EOF {
		writeErr(w, http.StatusBadRequest, "ожидался один JSON-объект")
		return false
	}
	return true
}

// handleState — единственный опрашиваемый эндпоинт: отдаёт всё, что рисует
// панель, чтобы фронтенд не дёргал пять ручек в цикле.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "только GET")
		return
	}
	host, _ := os.Hostname()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules":   s.mgr.Snapshots(),
		"scan":    s.scanner.State(),
		"events":  s.mgr.Events(),
		"metrics": s.metrics.snapshot(),
		"system": map[string]interface{}{
			"hostname":   host,
			"version":    s.version,
			"uptime_s":   int(time.Since(s.started).Seconds()),
			"config":     s.cfg.Path(),
			"web_addr":   s.cfg.Web.Addr,
			"auth":       s.cfg.Web.Token != "",
			"used_ports": s.mgr.UsedPorts(),
		},
		"scan_defaults": s.cfg.ScanSnapshot(),
	})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "только GET")
		return
	}
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
	if len(parts) > 2 && action != "dumps" {
		writeErr(w, http.StatusNotFound, "неизвестный путь")
		return
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
		s.ruleDumps(w, r, rule, parts[2:])
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
	if rule == nil {
		writeErr(w, http.StatusNotFound, "правило удалено")
		return
	}
	writeJSON(w, http.StatusOK, rule.Snapshot())
}

func (s *Server) ruleSwitch(w http.ResponseWriter, r *http.Request, rule *proxy.Rule) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "только POST")
		return
	}
	var body struct {
		Mode   string `json:"mode"`
		Backup *bool  `json:"backup,omitempty"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Mode == "" && body.Backup != nil {
		body.Mode = "primary"
		if *body.Backup {
			body.Mode = "backup"
		}
	}
	if body.Mode == "" {
		writeErr(w, http.StatusBadRequest, "задайте mode: auto, primary или backup")
		return
	}
	if err := s.mgr.SetRoutingMode(rule.ID(), body.Mode); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule.Snapshot())
}

func (s *Server) ruleDumps(w http.ResponseWriter, r *http.Request, rule *proxy.Rule, tail []string) {
	if len(tail) > 0 {
		s.dumpItem(w, r, rule, tail)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("summary") == "1" {
			query, err := parseDumpQuery(r)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			page, err := rule.SearchDumps(query)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, page)
			return
		}
		writeJSON(w, http.StatusOK, rule.Dumps())
	case http.MethodDelete:
		rule.ClearDumps()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

func parseDumpQuery(r *http.Request) (proxy.DumpQuery, error) {
	v := r.URL.Query()
	q := proxy.DumpQuery{Query: v.Get("q"), Mode: v.Get("mode"), Direction: v.Get("dir"), Remote: v.Get("remote"), PinnedOnly: v.Get("pinned") == "1", Limit: 50}
	for key, dest := range map[string]*time.Time{"from": &q.From, "to": &q.To} {
		if value := v.Get(key); value != "" {
			t, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return q, err
			}
			*dest = t
		}
	}
	for key, dest := range map[string]*int{"offset": &q.Offset, "limit": &q.Limit} {
		if value := v.Get(key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil {
				return q, err
			}
			*dest = n
		}
	}
	return q, nil
}

func (s *Server) dumpItem(w http.ResponseWriter, r *http.Request, rule *proxy.Rule, tail []string) {
	if len(tail) > 2 || (len(tail) == 2 && tail[1] != "pin") {
		writeErr(w, http.StatusNotFound, "неизвестный путь")
		return
	}
	id, err := strconv.ParseUint(tail[0], 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "некорректный ID соединения")
		return
	}
	if len(tail) == 2 {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "только POST")
			return
		}
		var body struct {
			Pinned *bool `json:"pinned"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.Pinned == nil {
			writeErr(w, http.StatusBadRequest, "задайте pinned")
			return
		}
		if err := rule.PinDump(id, *body.Pinned); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
	} else if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "только GET")
		return
	}
	dump, ok := rule.GetDump(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "запись не найдена или уже вытеснена")
		return
	}
	writeJSON(w, http.StatusOK, dump)
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
		if err := s.cfg.SetScan(config.ScanDefaults{CIDR: opts.CIDR, Ports: opts.Ports, TimeoutMS: opts.TimeoutMS, Concurrency: opts.Concurrency, Fingerprint: opts.Fingerprint}); err != nil {
			writeErr(w, http.StatusInternalServerError, "скан запущен, но параметры не сохранены: "+err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, s.scanner.State())
	case http.MethodDelete:
		s.scanner.Stop()
		writeJSON(w, http.StatusOK, s.scanner.State())
	default:
		writeErr(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}
