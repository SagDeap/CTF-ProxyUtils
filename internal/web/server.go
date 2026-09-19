package web

import (
	"crypto/subtle"
	"embed"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/SagDeap/CTF-ProxyUtils/internal/config"
	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
	"github.com/SagDeap/CTF-ProxyUtils/internal/scan"
)

//go:embed static/index.html static/style.css static/app.js static/traffic-utils.js
var staticFS embed.FS

const cookieName = "cpu_token"

// Server — панель управления: REST API плюс вшитый одностраничник.
type Server struct {
	cfg     *config.Config
	mgr     *proxy.Manager
	scanner *scan.Scanner
	version string
	started time.Time
	mux     *http.ServeMux
	metrics *metricsHistory
}

func NewServer(cfg *config.Config, mgr *proxy.Manager, sc *scan.Scanner, version string) *Server {
	s := &Server{
		cfg:     cfg,
		mgr:     mgr,
		scanner: sc,
		version: version,
		started: time.Now(),
		mux:     http.NewServeMux(),
	}
	s.routes()
	s.metrics = newMetricsHistory(mgr)
	return s
}

// Close stops background metric sampling; it is safe to call repeatedly.
func (s *Server) Close() { s.metrics.close() }

func (s *Server) routes() {
	ping := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "только GET")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":       true,
			"version":  s.version,
			"auth":     s.cfg.Web.Token != "",
			"uptime_s": int(time.Since(s.started).Seconds()),
			"api":      "v1",
		})
	}
	for _, prefix := range []string{"/api", "/api/v1"} {
		s.mux.HandleFunc(prefix+"/ping", ping)
		s.mux.HandleFunc(prefix+"/login", s.handleLogin)
		s.mux.HandleFunc(prefix+"/state", s.auth(s.handleState))
		s.mux.HandleFunc(prefix+"/interfaces", s.auth(s.handleInterfaces))
		s.mux.HandleFunc(prefix+"/rules", s.auth(s.handleRules))
		s.mux.HandleFunc(prefix+"/rules/", s.auth(s.handleRuleItem))
		s.mux.HandleFunc(prefix+"/scan", s.auth(s.handleScan))
	}
	s.mux.HandleFunc("/api/v1/detectors", s.auth(s.handleDetectors))
	s.mux.HandleFunc("/api/v1/detectors/", s.auth(s.handleDetectorItem))
	s.mux.HandleFunc("/api/v1/findings", s.auth(s.handleFindings))
	s.mux.HandleFunc("/api/v1/profile", s.auth(s.handleProfile))

	s.mux.HandleFunc("/", s.handleStatic)
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(s.mux)
}

// securityHeaders запрещает встраивание панели в чужие фреймы и утечку
// адреса панели через Referer.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		// Remove the legacy token cookie: cookies are shared across ports.
		if _, err := r.Cookie(cookieName); err == nil {
			http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
		next.ServeHTTP(w, r)
	})
}

// tokenOK сравнивает предъявленный токен с настроенным за постоянное время.
func (s *Server) tokenOK(given string) bool {
	want := s.cfg.Web.Token
	if want == "" {
		return true // авторизация выключена
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

// presentedToken only accepts explicit headers, never cross-port cookies.
func presentedToken(r *http.Request) string {
	if t := r.Header.Get("X-Auth-Token"); t != "" {
		return t
	}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	return ""
}

// auth закрывает обработчик токеном.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenOK(presentedToken(r)) {
			writeErr(w, http.StatusUnauthorized, "требуется авторизация")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "только POST")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !decode(w, r, &body) {
		return
	}
	if !s.tokenOK(body.Token) {
		// Небольшая задержка обесценивает перебор токена по сети.
		time.Sleep(400 * time.Millisecond)
		writeErr(w, http.StatusUnauthorized, "неверный токен")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleStatic отдаёт вшитый фронтенд.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, "только GET или HEAD")
		return
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "статика недоступна")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	data, err := fs.ReadFile(sub, path)
	if err != nil {
		// Одностраничник: неизвестный путь — это маршрут фронтенда.
		path = "index.html"
		data, err = fs.ReadFile(sub, path)
		if err != nil {
			writeErr(w, http.StatusNotFound, "не найдено")
			return
		}
	}
	// Панель управления не должна кэшироваться прокси между нами и браузером.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", contentType(path))
	w.Write(data)
}

// contentType определяет MIME по расширению: mime.TypeByExtension зависит
// от системных таблиц, которых на голой виртуалке может не оказаться.
func contentType(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(path, ".json"):
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
