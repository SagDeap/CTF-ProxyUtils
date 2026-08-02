package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/SagDeap/CTF-ProxyUtils/internal/config"
	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
	"github.com/SagDeap/CTF-ProxyUtils/internal/scan"
)

//go:embed static
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
	return s
}

func (s *Server) routes() {
	// Проверка живости — единственное, что доступно без токена.
	s.mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":       true,
			"version":  s.version,
			"auth":     s.cfg.Web.Token != "",
			"uptime_s": int(time.Since(s.started).Seconds()),
		})
	})
	s.mux.HandleFunc("/api/login", s.handleLogin)

	s.mux.HandleFunc("/api/state", s.auth(s.handleState))
	s.mux.HandleFunc("/api/interfaces", s.auth(s.handleInterfaces))
	s.mux.HandleFunc("/api/rules", s.auth(s.handleRules))
	s.mux.HandleFunc("/api/rules/", s.auth(s.handleRuleItem))
	s.mux.HandleFunc("/api/scan", s.auth(s.handleScan))

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

// presentedToken достаёт токен из заголовка или куки.
func presentedToken(r *http.Request) string {
	if t := r.Header.Get("X-Auth-Token"); t != "" {
		return t
	}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "некорректный запрос")
		return
	}
	if !s.tokenOK(body.Token) {
		// Небольшая задержка обесценивает перебор токена по сети.
		time.Sleep(400 * time.Millisecond)
		writeErr(w, http.StatusUnauthorized, "неверный токен")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    body.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 3600,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleStatic отдаёт вшитый фронтенд.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
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
