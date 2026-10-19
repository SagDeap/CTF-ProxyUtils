package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
)

// call performs an authorized request and returns the status with the whole body.
func call(t *testing.T, client *http.Client, method, endpoint, body string) (int, []byte) {
	t.Helper()
	var payload []byte
	if body != "" {
		payload = []byte(body)
	}
	resp := request(t, client, method, endpoint, "secret", payload)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func expectStatus(t *testing.T, client *http.Client, method, endpoint, body string, want int) []byte {
	t.Helper()
	status, data := call(t, client, method, endpoint, body)
	if status != want {
		t.Fatalf("%s %s: status %d, want %d; body %s", method, endpoint, status, want, data)
	}
	return data
}

func decodeInto(t *testing.T, data []byte, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}

// echoThrough sends payload through the proxy and waits for the echoed reply.
func echoThrough(t *testing.T, port int, payload string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != payload {
		t.Fatalf("echo through proxy = %q, %v", reply, err)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRuleCreateRejectsMalformedRequests(t *testing.T) {
	_, mgr, httpSrv := testServer(t, "secret")
	client, rules := httpSrv.Client(), httpSrv.URL+"/api/v1/rules"
	cases := []struct{ name, body string }{
		{"truncated JSON", `{"listen_port":`},
		{"unknown field", `{"listen_port":7000,"target":{"host":"10.0.0.1","port":80},"surprise":1}`},
		{"two objects", `{} {}`},
		{"invalid spec", `{"listen_port":0,"target":{"host":"10.0.0.1","port":80}}`},
		{"listen host is not an IP", `{"listen_host":"localhost","listen_port":7000,"target":{"host":"10.0.0.1","port":80}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectStatus(t, client, http.MethodPost, rules, tc.body, http.StatusBadRequest)
		})
	}

	req, _ := http.NewRequest(http.MethodPost, rules, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Auth-Token", "secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON content type: %d", resp.StatusCode)
	}
	if len(mgr.Specs()) != 0 {
		t.Fatalf("rejected requests created rules: %+v", mgr.Specs())
	}
}

func TestRuleLifecycleAPI(t *testing.T) {
	_, mgr, httpSrv := testServer(t, "secret")
	client, api := httpSrv.Client(), httpSrv.URL+"/api/v1"
	primary, stopPrimary := startEchoForWebTest(t)
	defer stopPrimary()
	backup, stopBackup := startEchoForWebTest(t)
	defer stopBackup()
	port := freeWebTestPort(t)
	spec := fmt.Sprintf(`{"id":"svc","name":"service","enabled":true,"listen_host":"127.0.0.1","listen_port":%d,`+
		`"target":{"host":%q,"port":%d},"backup":{"host":%q,"port":%d}}`, port, primary.Host, primary.Port, backup.Host, backup.Port)

	var created proxy.Snapshot
	decodeInto(t, expectStatus(t, client, http.MethodPost, api+"/rules", spec, http.StatusCreated), &created)
	if created.Spec.ID != "svc" || !created.Running || created.Spec.RoutingMode != "auto" || created.Spec.Dump.MaxConns != 50 {
		t.Fatalf("created rule = %+v", created)
	}
	expectStatus(t, client, http.MethodPost, api+"/rules", spec, http.StatusBadRequest) // duplicate ID
	echoThrough(t, port, "ping")

	var list []proxy.Snapshot
	decodeInto(t, expectStatus(t, client, http.MethodGet, api+"/rules", "", http.StatusOK), &list)
	if len(list) != 1 || list[0].Spec.ID != "svc" {
		t.Fatalf("rule list = %+v", list)
	}
	// The legacy prefix serves the same handlers.
	expectStatus(t, client, http.MethodGet, httpSrv.URL+"/api/rules/svc", "", http.StatusOK)

	renamed := strings.Replace(spec, `"name":"service"`, `"name":"renamed"`, 1)
	var updated proxy.Snapshot
	decodeInto(t, expectStatus(t, client, http.MethodPut, api+"/rules/svc", renamed, http.StatusOK), &updated)
	if updated.Spec.Name != "renamed" || !updated.Running || updated.TotalConns == 0 {
		t.Fatalf("rename lost state: %+v", updated)
	}
	invalid := strings.Replace(renamed, fmt.Sprintf(`"listen_port":%d`, port), `"listen_port":0`, 1)
	expectStatus(t, client, http.MethodPut, api+"/rules/svc", invalid, http.StatusConflict)
	if rule, _ := mgr.Get("svc"); rule.Spec().Name != "renamed" || rule.Spec().ListenPort != port {
		t.Fatalf("rejected update changed the rule: %+v", rule.Spec())
	}

	var routed proxy.Snapshot
	expectStatus(t, client, http.MethodPost, api+"/rules/svc/switch", `{}`, http.StatusBadRequest)
	expectStatus(t, client, http.MethodPost, api+"/rules/svc/switch", `{"mode":"sideways"}`, http.StatusBadRequest)
	decodeInto(t, expectStatus(t, client, http.MethodPost, api+"/rules/svc/switch", `{"mode":"backup"}`, http.StatusOK), &routed)
	if routed.Spec.RoutingMode != "backup" || !routed.UsingBackup {
		t.Fatalf("manual backup = %+v", routed)
	}
	decodeInto(t, expectStatus(t, client, http.MethodPost, api+"/rules/svc/switch", `{"backup":false}`, http.StatusOK), &routed)
	if routed.Spec.RoutingMode != "primary" || routed.UsingBackup {
		t.Fatalf("legacy switch to primary = %+v", routed)
	}
	expectStatus(t, client, http.MethodGet, api+"/rules/svc/switch", "", http.StatusMethodNotAllowed)

	var stats proxy.Snapshot
	decodeInto(t, expectStatus(t, client, http.MethodPost, api+"/rules/svc/reset", "", http.StatusOK), &stats)
	if stats.TotalConns != 0 || stats.BytesIn != 0 {
		t.Fatalf("reset kept counters: %+v", stats)
	}
	expectStatus(t, client, http.MethodGet, api+"/rules/svc/reset", "", http.StatusMethodNotAllowed)

	var toggled proxy.Snapshot
	decodeInto(t, expectStatus(t, client, http.MethodPost, api+"/rules/svc/toggle", `{"enabled":false}`, http.StatusOK), &toggled)
	if toggled.Running || toggled.Spec.Enabled {
		t.Fatalf("disabled rule still running: %+v", toggled)
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
		t.Fatal("disabled rule still accepts connections")
	}
	decodeInto(t, expectStatus(t, client, http.MethodPost, api+"/rules/svc/toggle", `{"enabled":true}`, http.StatusOK), &toggled)
	if !toggled.Running {
		t.Fatalf("enabled rule is not running: %+v", toggled)
	}
	expectStatus(t, client, http.MethodGet, api+"/rules/svc/toggle", "", http.StatusMethodNotAllowed)

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/rules/svc/unknown", http.StatusNotFound},
		{http.MethodPost, "/rules/svc/toggle/extra", http.StatusNotFound},
		{http.MethodGet, "/rules/missing", http.StatusNotFound},
		{http.MethodGet, "/rules/", http.StatusBadRequest},
		{http.MethodPatch, "/rules/svc", http.StatusMethodNotAllowed},
		{http.MethodPatch, "/rules", http.StatusMethodNotAllowed},
	} {
		expectStatus(t, client, tc.method, api+tc.path, "", tc.want)
	}

	expectStatus(t, client, http.MethodDelete, api+"/rules/svc", "", http.StatusOK)
	expectStatus(t, client, http.MethodGet, api+"/rules/svc", "", http.StatusNotFound)
	expectStatus(t, client, http.MethodDelete, api+"/rules/svc", "", http.StatusNotFound)
	if len(mgr.Specs()) != 0 {
		t.Fatalf("deleted rule remains: %+v", mgr.Specs())
	}
}

func TestRuleCreateReportsBusyPort(t *testing.T) {
	_, _, httpSrv := testServer(t, "secret")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port
	spec := fmt.Sprintf(`{"id":"busy","enabled":true,"listen_host":"127.0.0.1","listen_port":%d,"target":{"host":"127.0.0.1","port":%d}}`, port, port+1)
	var body struct {
		Error string         `json:"error"`
		Rule  proxy.Snapshot `json:"rule"`
	}
	decodeInto(t, expectStatus(t, httpSrv.Client(), http.MethodPost, httpSrv.URL+"/api/v1/rules", spec, http.StatusConflict), &body)
	if body.Error == "" || body.Rule.Spec.ID != "busy" || body.Rule.Running || body.Rule.Spec.Enabled {
		t.Fatalf("busy port response = %+v", body)
	}
}

func TestTrafficSearchAPIListsPinnedFirst(t *testing.T) {
	_, mgr, httpSrv := testServer(t, "secret")
	client, dumps := httpSrv.Client(), httpSrv.URL+"/api/v1/rules/traffic/dumps"
	target, stopEcho := startEchoForWebTest(t)
	defer stopEcho()
	port := freeWebTestPort(t)
	rule, err := mgr.Add(proxy.RuleSpec{ID: "traffic", Enabled: true, ListenHost: "127.0.0.1", ListenPort: port, Target: target,
		Dump: proxy.DumpSpec{Enabled: true, MaxConns: 10, MaxBytesPer: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		echoThrough(t, port, fmt.Sprintf("request-%d", i))
		waitUntil(t, "capture", func() bool { return rule.Snapshot().DumpCount == i })
	}
	search := func(query string) []proxy.ConnDump {
		t.Helper()
		var page struct {
			Items []proxy.ConnDump `json:"items"`
			Total int              `json:"total"`
		}
		decodeInto(t, expectStatus(t, client, http.MethodGet, dumps+"?summary=1"+query, "", http.StatusOK), &page)
		if page.Total < len(page.Items) {
			t.Fatalf("total %d is below page size %d", page.Total, len(page.Items))
		}
		return page.Items
	}
	items := search("")
	if len(items) != 3 {
		t.Fatalf("captures = %+v", items)
	}
	newest, middle, oldest := items[0].ID, items[1].ID, items[2].ID

	expectStatus(t, client, http.MethodPost, fmt.Sprintf("%s/%d/pin", dumps, oldest), `{"pinned":true}`, http.StatusOK)
	items = search("")
	if items[0].ID != oldest || !items[0].Pinned || items[1].ID != newest || items[2].ID != middle {
		t.Fatalf("pinned capture is not first: %+v", items)
	}
	if first := search("&limit=1"); len(first) != 1 || first[0].ID != oldest {
		t.Fatalf("first page lost the pin: %+v", first)
	}
	if text := search("&q=request-1&mode=text&dir=in"); len(text) != 1 || text[0].ID != oldest {
		t.Fatalf("text search = %+v", text)
	}

	expectStatus(t, client, http.MethodPost, fmt.Sprintf("%s/%d/pin", dumps, oldest), `{"pinned":false}`, http.StatusOK)
	items = search("")
	if items[0].ID != newest || items[2].ID != oldest || items[2].Pinned {
		t.Fatalf("unpinned capture did not return to time order: %+v", items)
	}
}

func TestDumpEndpointsRejectBadInput(t *testing.T) {
	_, mgr, httpSrv := testServer(t, "secret")
	if _, err := mgr.Add(proxy.RuleSpec{ID: "rec", ListenHost: "127.0.0.1", ListenPort: freeWebTestPort(t),
		Target: proxy.Endpoint{Host: "127.0.0.1", Port: 1}, Dump: proxy.DumpSpec{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	client, dumps := httpSrv.Client(), httpSrv.URL+"/api/v1/rules/rec/dumps"
	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"offset is not a number", http.MethodGet, "?summary=1&offset=abc", "", http.StatusBadRequest},
		{"negative offset", http.MethodGet, "?summary=1&offset=-1", "", http.StatusBadRequest},
		{"limit above maximum", http.MethodGet, "?summary=1&limit=501", "", http.StatusBadRequest},
		{"bad start time", http.MethodGet, "?summary=1&from=yesterday", "", http.StatusBadRequest},
		{"inverted interval", http.MethodGet, "?summary=1&from=2026-09-02T00:00:00Z&to=2026-09-01T00:00:00Z", "", http.StatusBadRequest},
		{"bad direction", http.MethodGet, "?summary=1&dir=sideways", "", http.StatusBadRequest},
		{"bad hex", http.MethodGet, "?summary=1&mode=hex&q=zz", "", http.StatusBadRequest},
		{"bad regex", http.MethodGet, "?summary=1&mode=regex&q=" + url.QueryEscape("["), "", http.StatusBadRequest},
		{"valid empty search", http.MethodGet, "?summary=1&limit=500", "", http.StatusOK},
		{"full list", http.MethodGet, "", "", http.StatusOK},
		{"unsupported method", http.MethodPut, "", "", http.StatusMethodNotAllowed},
		{"connection ID is not a number", http.MethodGet, "/abc", "", http.StatusBadRequest},
		{"missing connection", http.MethodGet, "/999", "", http.StatusNotFound},
		{"detail is read-only", http.MethodPost, "/999", "", http.StatusMethodNotAllowed},
		{"unknown action", http.MethodPost, "/1/star", "", http.StatusNotFound},
		{"path too deep", http.MethodPost, "/1/pin/extra", "", http.StatusNotFound},
		{"pin requires POST", http.MethodGet, "/1/pin", "", http.StatusMethodNotAllowed},
		{"pin requires a value", http.MethodPost, "/1/pin", `{}`, http.StatusBadRequest},
		{"pin missing connection", http.MethodPost, "/1/pin", `{"pinned":true}`, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectStatus(t, client, tc.method, dumps+tc.path, tc.body, tc.want)
		})
	}
}

func TestDetectorItemAPI(t *testing.T) {
	_, mgr, httpSrv := testServer(t, "secret")
	client, detectors := httpSrv.Client(), httpSrv.URL+"/api/v1/detectors"
	var created proxy.DetectorSpec
	decodeInto(t, expectStatus(t, client, http.MethodPost, detectors,
		`{"name":"Flag","enabled":true,"mode":"text","pattern":"FLAG{","direction":"out","scope":"stream","score":80}`, http.StatusCreated), &created)
	if created.ID == "" {
		t.Fatal("created detector has no ID")
	}
	item := detectors + "/" + created.ID

	var config proxy.DetectionConfig
	decodeInto(t, expectStatus(t, client, http.MethodPut, item,
		`{"id":"other","name":"Flag v2","enabled":false,"mode":"text","pattern":"FLAG{","direction":"out","scope":"stream","score":90}`, http.StatusOK), &config)
	if len(config.Detectors) != 1 || config.Detectors[0].ID != created.ID || config.Detectors[0].Enabled || config.Detectors[0].Score != 90 {
		t.Fatalf("detector update = %+v", config.Detectors)
	}
	expectStatus(t, client, http.MethodPut, item, `{"name":"Broken","enabled":true,"mode":"regex","pattern":"[","scope":"stream","score":10}`, http.StatusBadRequest)
	if got := mgr.DetectionConfig().Detectors[0]; got.Name != "Flag v2" || got.Mode != "text" {
		t.Fatalf("rejected update replaced detector: %+v", got)
	}
	expectStatus(t, client, http.MethodPatch, item, "", http.StatusMethodNotAllowed)
	expectStatus(t, client, http.MethodDelete, detectors+"/missing", "", http.StatusNotFound)
	expectStatus(t, client, http.MethodDelete, item+"/extra", "", http.StatusNotFound)
	expectStatus(t, client, http.MethodDelete, detectors+"/", "", http.StatusNotFound)

	decodeInto(t, expectStatus(t, client, http.MethodDelete, item, "", http.StatusOK), &config)
	if len(config.Detectors) != 0 || len(mgr.DetectionConfig().Detectors) != 0 {
		t.Fatalf("detector was not deleted: %+v", config.Detectors)
	}

	defaults := proxy.DefaultDetectionConfig()
	defaults.Threshold = 0 // filled in by defaults
	body, _ := json.Marshal(defaults)
	decodeInto(t, expectStatus(t, client, http.MethodPut, detectors, string(body), http.StatusOK), &config)
	if config.Threshold != 25 {
		t.Fatalf("defaults were not applied: %+v", config)
	}
	expectStatus(t, client, http.MethodPut, detectors, `{"enabled":true,"threshold":101}`, http.StatusBadRequest)
	expectStatus(t, client, http.MethodDelete, detectors, "", http.StatusMethodNotAllowed)
}

func TestFindingsAPIFiltersAndClears(t *testing.T) {
	_, mgr, httpSrv := testServer(t, "secret")
	client, findings := httpSrv.Client(), httpSrv.URL+"/api/v1/findings"
	target, stopEcho := startEchoForWebTest(t)
	defer stopEcho()
	port := freeWebTestPort(t)
	if _, err := mgr.Add(proxy.RuleSpec{ID: "web", Name: "Web-Svc", Enabled: true, ListenHost: "127.0.0.1", ListenPort: port, Target: target,
		Inspect: proxy.InspectSpec{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	echoThrough(t, port, "GET / HTTP/1.1\r\nUser-Agent: python-requests/2.32\r\n\r\n")

	type page struct {
		Items []proxy.Finding `json:"items"`
		Total int             `json:"total"`
	}
	get := func(query string) page {
		t.Helper()
		var p page
		decodeInto(t, expectStatus(t, client, http.MethodGet, findings+query, "", http.StatusOK), &p)
		if p.Total != len(p.Items) {
			t.Fatalf("total %d does not match %d items", p.Total, len(p.Items))
		}
		return p
	}
	waitUntil(t, "finding", func() bool { return get("").Total == 1 })
	finding := get("").Items[0]
	if finding.RuleID != "web" || finding.Score < 45 || finding.Signals[0].DetectorID != "builtin-automation" {
		t.Fatalf("finding = %+v", finding)
	}
	for query, want := range map[string]int{
		"?rule_id=web":   1,
		"?rule_id=other": 0,
		fmt.Sprintf("?min_score=%d", finding.Score):   1,
		fmt.Sprintf("?min_score=%d", finding.Score+1): 0,
		"?q=WEB-SVC": 1,
		"?q=" + url.QueryEscape("автоматизированный"): 1,
		"?q=no-such-client":               0,
		"?limit=0&min_score=not-a-number": 1,
	} {
		if got := get(query).Total; got != want {
			t.Errorf("findings%s: %d results, want %d", query, got, want)
		}
	}

	expectStatus(t, client, http.MethodPost, findings, `{}`, http.StatusMethodNotAllowed)
	expectStatus(t, client, http.MethodDelete, findings, "", http.StatusOK)
	if got := get("").Total; got != 0 {
		t.Fatalf("findings after clear: %d", got)
	}
}

func TestStaticFrontendServing(t *testing.T) {
	_, _, httpSrv := testServer(t, "secret")
	client := httpSrv.Client()
	fetch := func(method, path string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, httpSrv.URL+path, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp, data
	}
	index, indexBody := fetch(http.MethodGet, "/")
	if index.StatusCode != http.StatusOK || !bytes.Contains(indexBody, []byte("<title>CTF-ProxyUtils</title>")) {
		t.Fatalf("index: %d", index.StatusCode)
	}
	for header, want := range map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'self'; script-src 'self'",
	} {
		if got := index.Header.Get(header); !strings.HasPrefix(got, want) {
			t.Errorf("%s = %q, want prefix %q", header, got, want)
		}
	}
	for path, want := range map[string]string{
		"/app.js":           "application/javascript; charset=utf-8",
		"/traffic-utils.js": "application/javascript; charset=utf-8",
		"/style.css":        "text/css; charset=utf-8",
	} {
		resp, data := fetch(http.MethodGet, path)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != want || len(data) == 0 || bytes.Equal(data, indexBody) {
			t.Errorf("%s: %d %q", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
	// Unknown paths are frontend routes; the Node test file is not embedded.
	for _, path := range []string{"/traffic/123", "/_traffic-utils.test.js"} {
		resp, data := fetch(http.MethodGet, path)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(data, indexBody) {
			t.Errorf("%s did not fall back to index.html", path)
		}
	}
	if resp, data := fetch(http.MethodHead, "/"); resp.StatusCode != http.StatusOK || len(data) != 0 {
		t.Errorf("HEAD /: %d with %d body bytes", resp.StatusCode, len(data))
	}
	if resp, _ := fetch(http.MethodPost, "/"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /: %d", resp.StatusCode)
	}
}

func TestContentTypeByExtension(t *testing.T) {
	for path, want := range map[string]string{
		"index.html":  "text/html; charset=utf-8",
		"style.css":   "text/css; charset=utf-8",
		"app.js":      "application/javascript; charset=utf-8",
		"network.svg": "image/svg+xml",
		"data.json":   "application/json; charset=utf-8",
		"archive.bin": "application/octet-stream",
		"noext":       "application/octet-stream",
	} {
		if got := contentType(path); got != want {
			t.Errorf("contentType(%q) = %q, want %q", path, got, want)
		}
	}
}
