package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal(message)
	}
}

func TestMaxConnsIncludesPendingDial(t *testing.T) {
	port := freePort(t)
	rule, err := newRule(RuleSpec{Enabled: true, ListenHost: "127.0.0.1", ListenPort: port,
		Target: Endpoint{Host: "192.0.2.1", Port: 1}, MaxConns: 1, DialTimeoutMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	var calls int32
	rule.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		atomic.AddInt32(&calls, 1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := rule.Start(); err != nil {
		t.Fatal(err)
	}
	defer rule.Stop()
	first, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	waitFor(t, time.Second, func() bool { return rule.Snapshot().ActiveConns == 1 }, "pending dial did not reserve a slot")
	second, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := second.Read(one[:]); err == nil {
		t.Fatal("connection above MaxConns stayed open")
	}
	waitFor(t, time.Second, func() bool { return rule.Snapshot().DeniedConns == 1 }, "rejected connection was not counted")
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("started %d upstream dials with MaxConns=1", got)
	}
}

func TestStopCancelsPendingDial(t *testing.T) {
	port := freePort(t)
	rule, err := newRule(RuleSpec{Enabled: true, ListenHost: "127.0.0.1", ListenPort: port,
		Target: Endpoint{Host: "192.0.2.1", Port: 1}, DialTimeoutMS: 60000})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	rule.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := rule.Start(); err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	done := make(chan struct{})
	go func() { rule.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop waited for dial timeout")
	}
	if rule.Snapshot().ActiveConns != 0 {
		t.Fatal("reserved slot survived Stop")
	}
}

func TestBlockedWriteUsesIdleDeadline(t *testing.T) {
	source, sourcePeer := net.Pipe()
	destination, destinationPeer := net.Pipe()
	defer sourcePeer.Close()
	defer destinationPeer.Close()
	rule := &Rule{}
	stream := &relay{client: source, upstream: destination, idle: 50 * time.Millisecond}
	stream.touch()
	done := make(chan struct{})
	go func() {
		rule.pipe(destination, source, DirIn, nil, stream, &rule.bytesIn)
		close(done)
	}()
	go func() { _, _ = sourcePeer.Write(make([]byte, 1024)) }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked write ignored idle deadline")
	}
	if atomic.LoadInt64(&rule.bytesIn) != 0 {
		t.Fatal("counted bytes that were not written to destination")
	}
}

func TestTCPHalfCloseDeliversResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		payload, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("response:"), payload...))
	}()
	target := endpointOf(t, ln.Addr())
	port := freePort(t)
	mgr := NewManager()
	defer mgr.StopAll()
	if _, err := mgr.Add(RuleSpec{Enabled: true, ListenHost: "127.0.0.1", ListenPort: port, Target: target}); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response:request" {
		t.Fatalf("half-close response = %q", response)
	}
}

func TestHealthUpdatePreservesActiveConnection(t *testing.T) {
	target, stopEcho := startEcho(t)
	defer stopEcho()
	port := freePort(t)
	mgr := NewManager()
	defer mgr.StopAll()
	rule, err := mgr.Add(RuleSpec{Enabled: true, ListenHost: "127.0.0.1", ListenPort: port, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	exchange := func(payload string) {
		t.Helper()
		_ = client.SetDeadline(time.Now().Add(time.Second))
		if _, err := client.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(client, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != payload {
			t.Fatalf("echo = %q", buf)
		}
	}
	exchange("before")
	spec := rule.Spec()
	spec.Health = HealthSpec{Enabled: true, IntervalSec: 1, TimeoutMS: 100, FailAfter: 1, RiseAfter: 1}
	if err := mgr.Update(rule.ID(), spec); err != nil {
		t.Fatal(err)
	}
	exchange("after")
	if rule.Snapshot().ActiveConns != 1 {
		t.Fatal("health update replaced the active connection")
	}
}

func TestManualRoutingModeIsSticky(t *testing.T) {
	backup := Endpoint{Host: "127.0.0.2", Port: 8000}
	mgr := NewManager()
	rule, err := mgr.Add(RuleSpec{ID: "route", ListenHost: "127.0.0.1", ListenPort: freePort(t),
		Target: Endpoint{Host: "127.0.0.1", Port: 8000}, Backup: &backup,
		Health: HealthSpec{Enabled: true, AutoFail: true, AutoBack: true, FailAfter: 1, RiseAfter: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetRoutingMode(rule.ID(), "backup"); err != nil {
		t.Fatal(err)
	}
	rule.noteProbe(true, true)
	if !rule.Snapshot().UsingBackup || rule.Spec().RoutingMode != "backup" {
		t.Fatal("automatic failback overrode manual backup")
	}
	if err := mgr.SetRoutingMode(rule.ID(), "auto"); err != nil {
		t.Fatal(err)
	}
	if rule.Snapshot().UsingBackup {
		t.Fatal("auto mode did not return to healthy primary")
	}
	if mgr.Specs()[0].RoutingMode != "auto" {
		t.Fatal("routing mode was not persisted in manager spec")
	}
}

func TestFailedListenerUpdateKeepsOldRule(t *testing.T) {
	target, stopEcho := startEcho(t)
	defer stopEcho()
	port := freePort(t)
	mgr := NewManager()
	defer mgr.StopAll()
	rule, err := mgr.Add(RuleSpec{Enabled: true, ListenHost: "127.0.0.1", ListenPort: port, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	occupiedEndpoint := endpointOf(t, occupied.Addr())
	spec := rule.Spec()
	spec.ListenPort = occupiedEndpoint.Port
	if err := mgr.Update(rule.ID(), spec); err == nil {
		t.Fatal("update to occupied port succeeded")
	}
	if got := rule.Spec().ListenPort; got != port {
		t.Fatalf("failed update changed port to %d", got)
	}
	if got, err := roundTrip(t, fmt.Sprintf("127.0.0.1:%d", port), "still alive"); err != nil || got != "still alive" {
		t.Fatalf("old listener was lost: %q, %v", got, err)
	}
}

func TestEventJournalIsBoundedNewestFirst(t *testing.T) {
	mgr := NewManager()
	for n := 0; n < 110; n++ {
		id := fmt.Sprintf("r%d", n)
		_, err := mgr.Add(RuleSpec{ID: id, Name: id, ListenHost: "127.0.0.1", ListenPort: 10000 + n,
			Target: Endpoint{Host: "127.0.0.1", Port: 1}})
		if err != nil {
			t.Fatal(err)
		}
		if err := mgr.Delete(id); err != nil {
			t.Fatal(err)
		}
	}
	events := mgr.Events()
	if len(events) != maxEvents {
		t.Fatalf("journal contains %d events", len(events))
	}
	for i := 1; i < len(events); i++ {
		if events[i-1].ID <= events[i].ID {
			t.Fatal("events are not newest first")
		}
	}
	if events[0].RuleID != "r109" || events[0].Kind != "deleted" {
		t.Fatalf("unexpected newest event: %#v", events[0])
	}
	events[0].Message = "mutated"
	if mgr.Events()[0].Message == "mutated" {
		t.Fatal("Events exposed journal storage")
	}
}
