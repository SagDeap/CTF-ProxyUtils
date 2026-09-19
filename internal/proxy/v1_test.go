package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestDetectorAggregatesCrossChunkSignals(t *testing.T) {
	config := DefaultDetectionConfig()
	config.Builtins = false
	config.Threshold = 20
	config.AutoPinScore = 60
	config.Detectors = []DetectorSpec{
		{ID: "flag", Name: "Флаг", Enabled: true, Mode: "regex", Pattern: `FLAG\{[A-Z0-9]+\}`, Direction: DirIn, Scope: "stream", Score: 70, Sensitive: true},
	}
	engine, err := NewDetectorEngine(config)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	result := make(chan Finding, 1)
	engine.SetHook(func(finding Finding, created, autoPin bool) {
		if created && autoPin {
			result <- finding
		}
	})
	engine.Begin("rule", "Service", 7, "10.0.0.4:1234", "127.0.0.1:7001", "tcp", true)
	engine.Observe("rule", "Service", 7, "10.0.0.4:1234", "127.0.0.1:7001", "tcp", DirIn, []byte("POST / HTTP/1.1\r\n\r\nFLAG{"), true)
	engine.Observe("rule", "Service", 7, "10.0.0.4:1234", "127.0.0.1:7001", "tcp", DirIn, []byte("ABC123}"), true)
	select {
	case finding := <-result:
		if finding.Score != 70 || finding.Severity != "high" || !finding.AutoPinned {
			t.Fatalf("unexpected finding: %+v", finding)
		}
		if got := finding.Signals[0].Excerpt; got != "[скрыто: чувствительный шаблон]" {
			t.Fatalf("sensitive excerpt leaked: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("detector did not emit a finding")
	}
}

func TestBuiltinAutomationDetector(t *testing.T) {
	engine, err := NewDetectorEngine(DefaultDetectionConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engine.Begin("r", "svc", 1, "127.0.0.1:1", "127.0.0.1:2", "tcp", false)
	engine.Observe("r", "svc", 1, "127.0.0.1:1", "127.0.0.1:2", "tcp", DirIn, []byte("GET / HTTP/1.1\r\nUser-Agent: python-requests/2.32\r\n\r\n"), false)
	waitFor(t, time.Second, func() bool { return len(engine.Findings()) == 1 }, "builtin detector did not match")
	if got := engine.Findings()[0].Signals[0].DetectorID; got != "builtin-automation" {
		t.Fatalf("unexpected detector %q", got)
	}
}

func TestBuiltinDetectorNormalizesURLEncoding(t *testing.T) {
	engine, err := NewDetectorEngine(DefaultDetectionConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engine.Begin("rule-1", "web", 9, "[::1]:9000", "127.0.0.1:80", "tcp", false)
	engine.Observe("rule-1", "web", 9, "[::1]:9000", "127.0.0.1:80", "tcp", DirIn, []byte("GET /files/%252e%252e%252fetc/passwd HTTP/1.1\r\n\r\n"), false)

	waitFor(t, time.Second, func() bool {
		findings := engine.Findings()
		return len(findings) == 1 && findings[0].Signals[0].DetectorID == "builtin-traversal"
	}, "ожидание нормализованного traversal")
}

func TestPayloadAndHTTPHealthChecks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 4)
		_, _ = io.ReadFull(conn, buffer)
		_, _ = conn.Write([]byte("PONG ready"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	spec := RuleSpec{Protocol: "tcp", Health: HealthSpec{Mode: "payload", Request: "PING", RequestMode: "text", Expect: `PONG\s+ready`, ExpectMode: "regex", TimeoutMS: 500}}
	if err := runHealthProbe(ctx, spec, endpointOf(t, ln.Addr())); err != nil {
		t.Fatalf("payload probe failed: %v", err)
	}

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" || r.Header.Get("X-Probe") != "yes" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer httpSrv.Close()
	parsed, _ := url.Parse(httpSrv.URL)
	host, portText, _ := net.SplitHostPort(parsed.Host)
	port, _ := strconv.Atoi(portText)
	spec.Health = HealthSpec{Mode: "http", HTTPMethod: "GET", HTTPPath: "/health", HTTPStatus: http.StatusNoContent, HTTPHeaders: map[string]string{"X-Probe": "yes"}, TimeoutMS: 500}
	if err := runHealthProbe(ctx, spec, Endpoint{Host: host, Port: port}); err != nil {
		t.Fatalf("HTTP probe failed: %v", err)
	}
}

func TestUDPHealthRequiresChallengeResponse(t *testing.T) {
	spec := RuleSpec{
		Protocol: "udp", ListenHost: "127.0.0.1", ListenPort: 19010,
		Target: Endpoint{Host: "127.0.0.1", Port: 19011},
		Health: HealthSpec{Enabled: true, Mode: "tcp"},
	}
	spec.applyDefaults()
	if err := spec.Validate(); err == nil {
		t.Fatal("UDP connect-only health-check was accepted")
	}
	spec.Health.Mode, spec.Health.Request, spec.Health.Expect = "payload", "PING", "PONG"
	if err := spec.Validate(); err != nil {
		t.Fatalf("UDP challenge-response health-check rejected: %v", err)
	}
}

func TestUDPForwardingCaptureAndStats(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, remote, readErr := upstream.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			_, _ = upstream.WriteTo(append([]byte("echo:"), buffer[:n]...), remote)
		}
	}()

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyEndpoint := endpointOf(t, probe.LocalAddr())
	probe.Close()
	mgr := NewManager()
	defer mgr.Close()
	defer mgr.StopAll()
	rule, err := mgr.Add(RuleSpec{Name: "udp", Enabled: true, Protocol: "udp", ListenHost: proxyEndpoint.Host, ListenPort: proxyEndpoint.Port, Target: endpointOf(t, upstream.LocalAddr()), UDPIdleSec: 1, Dump: DumpSpec{Enabled: true, MaxConns: 5, MaxBytesPer: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("udp", net.JoinHostPort(proxyEndpoint.Host, strconv.Itoa(proxyEndpoint.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "echo:hello" {
		t.Fatalf("unexpected reply %q", got)
	}
	waitFor(t, time.Second, func() bool { return rule.Snapshot().BytesOut == 10 }, "UDP stats were not updated")
	dumps := rule.Dumps()
	if len(dumps) != 1 || dumps[0].Protocol != "udp" || len(dumps[0].Chunks) != 2 {
		t.Fatalf("unexpected UDP capture: %+v", dumps)
	}
}
