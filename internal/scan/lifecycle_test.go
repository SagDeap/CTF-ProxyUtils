package scan

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStateOwnsPortsAndLargeCounters(t *testing.T) {
	s := NewScanner()
	s.addPort("127.0.0.1", PortResult{Port: 8000, Service: "http"})
	atomic.StoreInt64(&s.total, 4294770690)
	state := s.State()
	state.Hosts[0].Ports[0].Service = "changed"
	next := s.State()
	if next.Hosts[0].Ports[0].Service != "http" {
		t.Fatal("State exposes mutable port storage")
	}
	if next.Total != 4294770690 {
		t.Fatalf("counter overflow: %d", next.Total)
	}
}

func TestConcurrentStateAndEnrichment(t *testing.T) {
	s := NewScanner()
	s.addPort("127.0.0.1", PortResult{Port: 8080})
	s.addPort("127.0.0.1", PortResult{Port: 80})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for n := 0; n < 500; n++ {
			snapshot := s.State()
			snapshot.Hosts[0].Ports[0].Service = "private"
		}
	}()
	go func() {
		defer wg.Done()
		for n := 0; n < 500; n++ {
			s.mu.Lock()
			ports := s.hosts["127.0.0.1"].Ports
			ports[0], ports[1] = ports[1], ports[0]
			s.mu.Unlock()
		}
	}()
	wg.Wait()
}

func TestStopCancelsSilentFingerprint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	s := NewScanner()
	defer s.Stop()
	if err := s.Start(Options{CIDR: "127.0.0.1", Ports: strconv.Itoa(port), TimeoutMS: 10000, Concurrency: 1, Fingerprint: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("probe never connected")
	}
	s.Stop()
	deadline := time.Now().Add(time.Second)
	for s.State().Running && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.State().Running {
		t.Fatal("Stop waited for fingerprint timeout")
	}
}

func TestCIDRSizeDoesNotOverflowOn32Bit(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "0.0.0.0/1", "10.0.0.0/8"} {
		if _, err := expandCIDR(cidr); err == nil {
			t.Fatalf("accepted oversized %s", cidr)
		}
	}
}
