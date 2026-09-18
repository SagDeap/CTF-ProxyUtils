package web

import (
	"testing"
	"time"

	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
)

func TestMetricsRatesResetAndRuleRemoval(t *testing.T) {
	h := &metricsHistory{previous: make(map[string]metricCounters)}
	start := time.Unix(1000, 0)
	a := proxy.Snapshot{Spec: proxy.RuleSpec{ID: "a"}, BytesIn: 100, TotalConns: 10}
	b := proxy.Snapshot{Spec: proxy.RuleSpec{ID: "b"}, BytesIn: 500, TotalConns: 20}
	h.observe([]proxy.Snapshot{a, b}, start)
	a.BytesIn = 300
	a.TotalConns = 14
	a.ActiveConns = 2
	h.observe([]proxy.Snapshot{a}, start.Add(2*time.Second))
	points := h.snapshot()
	if points[0].BytesInPerSec != 0 || points[1].BytesInPerSec != 100 || points[1].ConnectionsPerSec != 2 || points[1].ActiveConns != 2 {
		t.Fatalf("incorrect rates after removal: %#v", points)
	}
	a.BytesIn = 30
	a.TotalConns = 1
	h.observe([]proxy.Snapshot{a}, start.Add(3*time.Second))
	points = h.snapshot()
	if points[2].BytesInPerSec != 30 || points[2].ConnectionsPerSec != 1 {
		t.Fatalf("negative/reset rates: %#v", points[2])
	}
	points[2].ActiveConns = 999
	if h.snapshot()[2].ActiveConns == 999 {
		t.Fatal("snapshot aliases history")
	}
}

func TestMetricsHistoryIsBounded(t *testing.T) {
	h := &metricsHistory{previous: make(map[string]metricCounters)}
	for n := 0; n < metricSamples+10; n++ {
		h.observe(nil, time.Unix(int64(n), 0))
	}
	points := h.snapshot()
	if len(points) != metricSamples || points[0].At.Unix() != 10 {
		t.Fatalf("unbounded or incorrect history: %d points", len(points))
	}
}
