package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SagDeap/CTF-ProxyUtils/internal/config"
	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
	"github.com/SagDeap/CTF-ProxyUtils/internal/scan"
)

func testServer(t *testing.T, token string) (*Server, *proxy.Manager, *httptest.Server) {
	t.Helper()
	cfg := config.Default()
	cfg.Web.Token = token
	mgr := proxy.NewManager()
	srv := NewServer(cfg, mgr, scan.NewScanner(), "test")
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		httpSrv.Close()
		srv.Close()
		mgr.StopAll()
	})
	return srv, mgr, httpSrv
}

func request(t *testing.T, client *http.Client, method, url, token string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Auth-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestTokenCookieRejectedAndDeleted(t *testing.T) {
	_, _, httpSrv := testServer(t, "secret")
	req, _ := http.NewRequest(http.MethodGet, httpSrv.URL+"/api/state", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "secret"})
	resp, err := httpSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cookie authenticated request: %d", resp.StatusCode)
	}
	foundDeletion := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieName && cookie.MaxAge < 0 {
			foundDeletion = true
		}
	}
	if !foundDeletion {
		t.Fatal("legacy token cookie was not deleted")
	}

	resp = request(t, httpSrv.Client(), http.MethodGet, httpSrv.URL+"/api/state", "secret", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("header token rejected: %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP")
	}
}

func TestLoginValidatesJSONWithoutSettingCookie(t *testing.T) {
	_, _, httpSrv := testServer(t, "secret")
	resp := request(t, httpSrv.Client(), http.MethodPost, httpSrv.URL+"/api/login", "", []byte(`{"token":"secret"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieName && cookie.Value != "" {
			t.Fatal("login leaked token into cookie")
		}
	}

	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/login", strings.NewReader(`{"token":"secret","extra":1}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown JSON accepted: %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, httpSrv.URL+"/api/login", strings.NewReader(`{"token":"secret"}`))
	resp, err = httpSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content type accepted: %d", resp.StatusCode)
	}
}

func startEchoForWebTest(t *testing.T) (proxy.Endpoint, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	return proxy.Endpoint{Host: host, Port: port}, func() { _ = ln.Close() }
}

func freeWebTestPort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	return port
}

func TestTrafficSearchPinDetailAndClearAPI(t *testing.T) {
	_, mgr, httpSrv := testServer(t, "secret")
	target, stopEcho := startEchoForWebTest(t)
	defer stopEcho()
	port := freeWebTestPort(t)
	rule, err := mgr.Add(proxy.RuleSpec{ID: "traffic", Enabled: true, ListenHost: "127.0.0.1", ListenPort: port, Target: target,
		Dump: proxy.DumpSpec{Enabled: true, MaxConns: 10, MaxBytesPer: 1024}})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("GET /flag?id=42")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 15)
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	deadline := time.Now().Add(time.Second)
	for rule.Snapshot().DumpCount != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	resp := request(t, httpSrv.Client(), http.MethodGet, httpSrv.URL+"/api/rules/traffic/dumps?summary=1&q=flag&mode=text&dir=in", "secret", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search failed: %d", resp.StatusCode)
	}
	var page proxy.DumpPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || len(page.Items[0].Chunks) != 0 {
		t.Fatalf("unexpected search page: %#v", page)
	}
	id := page.Items[0].ID

	resp = request(t, httpSrv.Client(), http.MethodGet, fmt.Sprintf("%s/api/rules/traffic/dumps/%d", httpSrv.URL, id), "secret", nil)
	defer resp.Body.Close()
	var detail proxy.ConnDump
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Chunks) == 0 {
		t.Fatal("detail omitted traffic chunks")
	}

	resp = request(t, httpSrv.Client(), http.MethodPost, fmt.Sprintf("%s/api/rules/traffic/dumps/%d/pin", httpSrv.URL, id), "secret", []byte(`{"pinned":true}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pin failed: %d", resp.StatusCode)
	}
	resp = request(t, httpSrv.Client(), http.MethodDelete, httpSrv.URL+"/api/rules/traffic/dumps", "secret", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || rule.Snapshot().DumpCount != 1 {
		t.Fatal("clear removed pinned capture")
	}
}

func TestMethodsAndTrafficParametersRejected(t *testing.T) {
	_, mgr, httpSrv := testServer(t, "secret")
	_, err := mgr.Add(proxy.RuleSpec{ID: "off", ListenHost: "127.0.0.1", ListenPort: freeWebTestPort(t), Target: proxy.Endpoint{Host: "127.0.0.1", Port: 1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/ping", "/api/state", "/api/interfaces"} {
		resp := request(t, httpSrv.Client(), http.MethodPost, httpSrv.URL+path, "secret", []byte(`{}`))
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s: %d", path, resp.StatusCode)
		}
	}
	resp := request(t, httpSrv.Client(), http.MethodGet, httpSrv.URL+"/api/rules/off/dumps?summary=1&mode=invalid", "secret", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid search mode accepted: %d", resp.StatusCode)
	}
}
