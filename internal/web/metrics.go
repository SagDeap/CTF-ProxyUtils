package web

import (
	"sync"
	"time"

	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
)

const metricSamples = 300

type metricSample struct {
	At                time.Time `json:"at"`
	BytesInPerSec     float64   `json:"bytes_in_per_sec"`
	BytesOutPerSec    float64   `json:"bytes_out_per_sec"`
	ConnectionsPerSec float64   `json:"connections_per_sec"`
	FailedPerSec      float64   `json:"failed_per_sec"`
	ActiveConns       int64     `json:"active_conns"`
}

type metricCounters struct{ in, out, connections, failed int64 }

type metricsHistory struct {
	mu       sync.Mutex
	samples  []metricSample
	previous map[string]metricCounters
	last     time.Time
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

func newMetricsHistory(mgr *proxy.Manager) *metricsHistory {
	h := &metricsHistory{previous: make(map[string]metricCounters), stop: make(chan struct{}), done: make(chan struct{})}
	h.observe(mgr.Snapshots(), time.Now())
	go func() {
		defer close(h.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-h.stop:
				return
			case now := <-ticker.C:
				h.observe(mgr.Snapshots(), now)
			}
		}
	}()
	return h
}

func (h *metricsHistory) close() {
	h.once.Do(func() { close(h.stop) })
	<-h.done
}

// Counter deltas are tracked per rule: removing/resetting one rule must not
// subtract another rule's traffic or introduce negative graph values.
func (h *metricsHistory) observe(rules []proxy.Snapshot, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	elapsed := now.Sub(h.last).Seconds()
	sample := metricSample{At: now}
	next := make(map[string]metricCounters, len(rules))
	for _, rule := range rules {
		current := metricCounters{rule.BytesIn, rule.BytesOut, rule.TotalConns, rule.FailedConns}
		previous := h.previous[rule.Spec.ID]
		next[rule.Spec.ID] = current
		sample.ActiveConns += rule.ActiveConns
		if !h.last.IsZero() && elapsed > 0 {
			sample.BytesInPerSec += counterDelta(current.in, previous.in) / elapsed
			sample.BytesOutPerSec += counterDelta(current.out, previous.out) / elapsed
			sample.ConnectionsPerSec += counterDelta(current.connections, previous.connections) / elapsed
			sample.FailedPerSec += counterDelta(current.failed, previous.failed) / elapsed
		}
	}
	h.previous = next
	h.last = now
	if len(h.samples) == metricSamples {
		copy(h.samples, h.samples[1:])
		h.samples[len(h.samples)-1] = sample
	} else {
		h.samples = append(h.samples, sample)
	}
}

func counterDelta(current, previous int64) float64 {
	if current < previous {
		return float64(current)
	}
	return float64(current - previous)
}

func (h *metricsHistory) snapshot() []metricSample {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]metricSample{}, h.samples...)
}
