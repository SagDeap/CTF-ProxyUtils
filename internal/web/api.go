package web

import (
	"encoding/json"
	"fmt"
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
		"rules":    s.mgr.Snapshots(),
		"scan":     s.scanner.State(),
		"events":   s.mgr.Events(),
		"metrics":  s.metrics.snapshot(),
		"findings": s.mgr.Findings(),
		"detection": map[string]interface{}{
			"config":  s.mgr.DetectionConfig(),
			"dropped": s.mgr.DetectionDropped(),
		},
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
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	if rest == r.URL.Path {
		rest = strings.TrimPrefix(r.URL.Path, "/api/rules/")
	}
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

func (s *Server) applyDetectionConfig(config proxy.DetectionConfig) error {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return err
	}
	previous := s.mgr.DetectionConfig()
	if err := s.mgr.SetDetectionConfig(config); err != nil {
		return err
	}
	if err := s.cfg.SetDetection(config); err != nil {
		_ = s.mgr.SetDetectionConfig(previous)
		return err
	}
	return nil
}

func (s *Server) handleDetectors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.mgr.DetectionConfig())
	case http.MethodPut:
		var config proxy.DetectionConfig
		if !decode(w, r, &config) {
			return
		}
		if err := s.applyDetectionConfig(config); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.mgr.DetectionConfig())
	case http.MethodPost:
		var detector proxy.DetectorSpec
		if !decode(w, r, &detector) {
			return
		}
		if detector.ID == "" {
			detector.ID = proxy.NewDetectorID()
		}
		config := s.mgr.DetectionConfig()
		config.Detectors = append(config.Detectors, detector)
		if err := s.applyDetectionConfig(config); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, detector)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

func (s *Server) handleDetectorItem(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/detectors/"), "/")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusNotFound, "детектор не найден")
		return
	}
	config := s.mgr.DetectionConfig()
	index := -1
	for i, detector := range config.Detectors {
		if detector.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		writeErr(w, http.StatusNotFound, "детектор не найден")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var detector proxy.DetectorSpec
		if !decode(w, r, &detector) {
			return
		}
		detector.ID = id
		config.Detectors[index] = detector
	case http.MethodDelete:
		config.Detectors = append(config.Detectors[:index], config.Detectors[index+1:]...)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "только PUT или DELETE")
		return
	}
	if err := s.applyDetectionConfig(config); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.DetectionConfig())
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.mgr.ClearFindings()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "только GET или DELETE")
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	ruleID := r.URL.Query().Get("rule_id")
	minimum, _ := strconv.Atoi(r.URL.Query().Get("min_score"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	items := make([]*proxy.Finding, 0)
	for _, finding := range s.mgr.Findings() {
		if ruleID != "" && finding.RuleID != ruleID || finding.Score < minimum {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(fmt.Sprintf("%s %s %s %s", finding.RuleName, finding.RemoteAddr, finding.Target, finding.Severity))
			for _, signal := range finding.Signals {
				haystack += " " + strings.ToLower(signal.DetectorName+" "+signal.Reason+" "+signal.Excerpt)
			}
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		items = append(items, finding)
		if len(items) == limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items), "dropped": s.mgr.DetectionDropped()})
}

type profileImportRequest struct {
	Profile config.Profile `json:"profile"`
	Mode    string         `json:"mode"`
	DryRun  bool           `json:"dry_run"`
}

type profilePreview struct {
	Added   int              `json:"added"`
	Updated int              `json:"updated"`
	Removed int              `json:"removed"`
	Rules   []proxy.RuleSpec `json:"rules"`
}

func mergeProfileRules(current, imported []proxy.RuleSpec, mode string) ([]proxy.RuleSpec, profilePreview, error) {
	if mode == "" {
		mode = "merge"
	}
	if mode != "merge" && mode != "replace" {
		return nil, profilePreview{}, fmt.Errorf("режим импорта должен быть merge или replace")
	}
	preview := profilePreview{}
	currentIDs := make(map[string]bool)
	for _, rule := range current {
		currentIDs[rule.ID] = true
	}
	var combined []proxy.RuleSpec
	if mode == "replace" {
		combined = append([]proxy.RuleSpec(nil), imported...)
		importedIDs := make(map[string]bool)
		for _, rule := range imported {
			if rule.ID != "" {
				importedIDs[rule.ID] = true
			}
			if currentIDs[rule.ID] && rule.ID != "" {
				preview.Updated++
			} else {
				preview.Added++
			}
		}
		for id := range currentIDs {
			if !importedIDs[id] {
				preview.Removed++
			}
		}
	} else {
		combined = append([]proxy.RuleSpec(nil), current...)
		positions := make(map[string]int)
		for i, rule := range combined {
			positions[rule.ID] = i
		}
		for _, rule := range imported {
			if index, exists := positions[rule.ID]; exists && rule.ID != "" {
				combined[index] = rule
				preview.Updated++
			} else {
				combined = append(combined, rule)
				preview.Added++
			}
		}
	}
	normalized, err := proxy.NormalizeRuleSet(combined)
	if err != nil {
		return nil, preview, err
	}
	preview.Rules = normalized
	return normalized, preview, nil
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		host, _ := os.Hostname()
		profile := s.cfg.ProfileSnapshot(host)
		profile.Rules = s.mgr.Specs()
		profile.Detection = s.mgr.DetectionConfig()
		profile.ExportedAt = time.Now().UTC().Format(time.RFC3339)
		writeJSON(w, http.StatusOK, profile)
	case http.MethodPost:
		var request profileImportRequest
		if !decode(w, r, &request) {
			return
		}
		if request.Profile.SchemaVersion > 1 {
			writeErr(w, http.StatusBadRequest, "профиль создан более новой версией программы")
			return
		}
		request.Profile.Detection.ApplyDefaults()
		if err := request.Profile.Detection.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, "детекторы: "+err.Error())
			return
		}
		rules, preview, err := mergeProfileRules(s.mgr.Specs(), request.Profile.Rules, request.Mode)
		if err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		if request.DryRun {
			writeJSON(w, http.StatusOK, preview)
			return
		}
		if err := s.mgr.ReplaceSpecs(rules); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		if err := s.applyDetectionConfig(request.Profile.Detection); err != nil {
			writeErr(w, http.StatusInternalServerError, "правила применены, но детекторы не сохранены: "+err.Error())
			return
		}
		if err := s.cfg.SetScan(request.Profile.Scan); err != nil {
			writeErr(w, http.StatusInternalServerError, "профиль применён, но параметры сканера не сохранены: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, preview)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "только GET или POST")
	}
}
