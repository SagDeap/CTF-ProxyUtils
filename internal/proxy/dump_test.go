package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func dumpStream(d *ConnDump, dir string) []byte {
	var out []byte
	for _, c := range d.Chunks {
		if c.Dir == dir {
			out = append(out, c.Data...)
		}
	}
	return out
}

func TestRecorderSearchAcrossChunkBoundaries(t *testing.T) {
	rec := NewRecorder(8, 1024)
	w := rec.Begin(1, "10.0.0.1:123", "service:80")
	w.Write(DirIn, []byte("prefix FL"))
	w.Write(DirOut, []byte("server "))
	w.Write(DirIn, []byte("AG{42} suffix"))
	w.Write(DirOut, []byte("reply"))
	w.Finish(25, 12)
	binary := rec.Begin(2, "10.0.0.2:123", "service:80")
	binary.Write(DirIn, []byte{0x00})
	binary.Write(DirOut, []byte("response"))
	binary.Write(DirIn, []byte{0xff, 0x01})
	separate := rec.Begin(3, "10.0.0.3:123", "service:80")
	separate.Write(DirIn, []byte("abc"))
	separate.Write(DirOut, []byte("def"))

	cases := []struct {
		name, mode, query, direction string
		want                         uint64
	}{
		{"text", "text", "FLAG{42}", "any", 1},
		{"hex", "hex", "46 4c 41 47 7b 34 32 7d", "in", 1},
		{"regex", "regex", `FLAG\{[0-9]+\}`, "in", 1},
		{"response", "text", "server reply", "out", 1},
		{"binary", "hex", "00 ff 01", "in", 2},
		{"wrong direction", "text", "FLAG{42}", "out", 0},
		{"directions are separate", "text", "abcdef", "any", 0},
		{"case sensitive", "text", "flag{42}", "in", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := rec.Search(DumpQuery{Mode: tc.mode, Query: tc.query, Direction: tc.direction})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == 0 {
				if page.Total != 0 || len(page.Items) != 0 {
					t.Fatalf("unexpected matches: %+v", page)
				}
				return
			}
			if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != tc.want {
				t.Fatalf("search result = %+v, want ID %d", page, tc.want)
			}
			if page.Items[0].Chunks != nil {
				t.Fatal("search must return metadata without captured payload")
			}
		})
	}
}

func TestRecorderSearchFiltersAndPagination(t *testing.T) {
	rec := NewRecorder(10, 64)
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		w := rec.Begin(uint64(i), fmt.Sprintf("10.0.0.%d:80", i%2+1), "service:80")
		w.Write(DirIn, []byte("request"))
		w.Finish(7, 0)
		rec.dumps[i-1].StartedAt = base.Add(time.Duration(i) * time.Second)
	}
	if err := rec.SetPinned(3, true); err != nil {
		t.Fatal(err)
	}
	page, err := rec.Search(DumpQuery{Remote: "10.0.0.2", Offset: 1, Limit: 1})
	if err != nil || page.Total != 3 || len(page.Items) != 1 || page.Items[0].ID != 3 {
		t.Fatalf("filtered page = %+v, %v", page, err)
	}
	page, err = rec.Search(DumpQuery{From: base.Add(2 * time.Second), To: base.Add(4 * time.Second)})
	if err != nil || page.Total != 3 || len(page.Items) != 3 || page.Items[0].ID != 4 || page.Items[2].ID != 2 {
		t.Fatalf("inclusive date range = %+v, %v", page, err)
	}
	page, err = rec.Search(DumpQuery{PinnedOnly: true})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != 3 || !page.Items[0].Pinned {
		t.Fatalf("pin filter = %+v, %v", page, err)
	}
	page, err = rec.Search(DumpQuery{Offset: 100})
	if err != nil || page.Total != 5 || len(page.Items) != 0 || page.Items == nil {
		t.Fatalf("out-of-range page = %+v, %v", page, err)
	}
	page, err = rec.Search(DumpQuery{Remote: "missing"})
	if err != nil || page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("missing client = %+v, %v", page, err)
	}
}

func TestRecorderSearchRejectsInvalidQueries(t *testing.T) {
	now := time.Now()
	cases := []DumpQuery{
		{Mode: "unknown"}, {Direction: "both"}, {Offset: -1}, {Limit: -1}, {Limit: 501},
		{Mode: "hex", Query: "a"}, {Mode: "hex", Query: "gg"}, {Mode: "regex", Query: "["},
		{Query: strings.Repeat("x", 4097)}, {From: now, To: now.Add(-time.Second)},
	}
	rec := NewRecorder(2, 8)
	for _, q := range cases {
		if _, err := rec.Search(q); err == nil {
			t.Errorf("query %+v should fail", q)
		}
	}
}

func TestRecorderPinsSurviveEvictionAndClear(t *testing.T) {
	rec := NewRecorder(2, 64)
	first := rec.Begin(1, "client1", "target")
	first.Write(DirIn, []byte("keep"))
	if err := rec.SetPinned(1, true); err != nil {
		t.Fatal(err)
	}
	second := rec.Begin(2, "client2", "target")
	second.Write(DirIn, []byte("evict"))
	third := rec.Begin(3, "client3", "target")
	if _, ok := rec.Get(2); ok {
		t.Fatal("oldest unpinned capture survived eviction")
	}
	if err := rec.SetPinned(3, true); err != nil {
		t.Fatal(err)
	}
	skipped := rec.Begin(4, "client4", "target")
	if skipped != nil {
		t.Fatal("all pinned slots must skip new captures")
	}
	skipped.Write(DirIn, []byte("safe no-op"))
	skipped.Finish(9, 0)
	if err := rec.Resize(1, 1); err == nil {
		t.Fatal("resize below pin count must fail")
	}
	if rec.maxConns != 2 || rec.maxBytesPer != 64 {
		t.Fatal("failed resize changed limits")
	}
	rec.Clear()
	if rec.Count() != 2 {
		t.Fatal("Clear removed pinned captures")
	}
	first.Write(DirIn, []byte(" writing"))
	third.Write(DirOut, []byte("alive"))
	if err := rec.SetPinned(3, false); err != nil {
		t.Fatal(err)
	}
	rec.Clear()
	if rec.Count() != 1 {
		t.Fatal("Clear did not remove unpinned captures")
	}
	if err := rec.SetPinned(3, true); !errors.Is(err, ErrDumpNotFound) {
		t.Fatalf("missing pin result = %v", err)
	}
	rec.ClearAll()
	first.Write(DirIn, []byte("discarded"))
	first.Finish(100, 0)
	if rec.Count() != 0 || len(rec.active) != 0 {
		t.Fatal("ClearAll retained pinned data or active capture handles")
	}
}

func TestRecorderResizeUpdatesLiveWriters(t *testing.T) {
	rec := NewRecorder(4, 16)
	w := rec.Begin(1, "client", "target")
	w.Write(DirIn, []byte("abc"))
	w.Write(DirOut, []byte("0123456789"))
	w.Write(DirIn, []byte("defghi"))
	if err := rec.SetPinned(1, true); err != nil {
		t.Fatal(err)
	}
	if err := rec.Resize(1, 4); err != nil {
		t.Fatal(err)
	}
	w.Write(DirIn, []byte("next"))
	w.Write(DirOut, []byte("tail"))
	d, _ := rec.Get(1)
	if string(dumpStream(d, DirIn)) != "abcd" || string(dumpStream(d, DirOut)) != "0123" || !d.Truncated || !d.Pinned {
		t.Fatalf("resize lost prefixes, pin or truncation marker: %+v", d)
	}
	if d.BytesIn != 13 || d.BytesOut != 14 {
		t.Fatalf("live totals must include uncaptured traffic: %+v", d)
	}
	// Once bytes are missing, growing the limit must not join later bytes onto
	// an incomplete prefix and create false stream-search matches.
	if err := rec.Resize(1, 32); err != nil {
		t.Fatal(err)
	}
	w.Write(DirIn, []byte("GAP"))
	d, _ = rec.Get(1)
	if string(dumpStream(d, DirIn)) != "abcd" {
		t.Fatal("capture resumed after a missing stream segment")
	}
	w.Finish(16, 14)
	if len(rec.active) != 0 {
		t.Fatal("finished writer remained active")
	}
	w.Write(DirIn, []byte("after finish"))
	d, _ = rec.Get(1)
	if !d.Closed || d.EndedAt.IsZero() || d.BytesIn != 16 {
		t.Fatalf("finish state changed after late write: %+v", d)
	}
}

func TestRecorderResizeGrowsBeforeTruncation(t *testing.T) {
	rec := NewRecorder(3, 4)
	w := rec.Begin(1, "client", "target")
	w.Write(DirIn, []byte("ab"))
	if err := rec.Resize(3, 8); err != nil {
		t.Fatal(err)
	}
	w.Write(DirIn, []byte("cdefgh"))
	d, _ := rec.Get(1)
	if string(dumpStream(d, DirIn)) != "abcdefgh" || d.Truncated {
		t.Fatalf("live writer ignored increased limit: %+v", d)
	}
	if err := rec.Resize(0, 8); err == nil {
		t.Fatal("zero capture count should fail")
	}
	if err := rec.Resize(3, -1); err == nil {
		t.Fatal("negative capture byte limit should fail")
	}
}

func TestRecorderEvictedWritersCannotRetainCaptures(t *testing.T) {
	rec := NewRecorder(2, 4096)
	writers := make([]*connWriter, 0, 500)
	for i := 0; i < 500; i++ {
		w := rec.Begin(uint64(i), "client", "target")
		w.Write(DirIn, bytes.Repeat([]byte("x"), 4096))
		writers = append(writers, w)
	}
	for _, w := range writers[:498] {
		w.Write(DirOut, bytes.Repeat([]byte("y"), 4096))
		w.Finish(4096, 4096)
	}
	if rec.Count() != 2 || len(rec.active) != 2 {
		t.Fatalf("evicted active writers retained records: captures=%d active=%d", rec.Count(), len(rec.active))
	}
	for _, d := range rec.List() {
		if d.Closed || d.BytesOut != 0 || len(dumpStream(d, DirIn)) != 4096 {
			t.Fatalf("stale writer modified another capture: %+v", d)
		}
	}
	rec.ClearAll()
	replacement := rec.Begin(0, "new", "target")
	replacement.Write(DirIn, []byte("new data"))
	writers[0].Write(DirIn, []byte("stale"))
	writers[0].Finish(999, 999)
	d, _ := rec.Get(0)
	if d.Closed || d.BytesIn != 8 || string(dumpStream(d, DirIn)) != "new data" {
		t.Fatalf("reused ID accepted old writer: %+v", d)
	}
}

func TestRecorderBoundsChunkMetadataAndCoalescesWrites(t *testing.T) {
	rec := NewRecorder(2, 4096)
	w := rec.Begin(1, "client", "target")
	for i := 0; i < 1024; i++ {
		w.Write(DirIn, []byte("x"))
	}
	d, _ := rec.Get(1)
	if len(d.Chunks) != 1 || len(d.Chunks[0].Data) != 1024 || d.Truncated {
		t.Fatal("adjacent writes should coalesce without truncation")
	}
	w = rec.Begin(2, "client", "target")
	for i := 0; i < maxDumpChunks+100; i++ {
		dir := DirIn
		if i%2 != 0 {
			dir = DirOut
		}
		w.Write(dir, []byte("x"))
	}
	d, _ = rec.Get(2)
	if len(d.Chunks) != maxDumpChunks || !d.Truncated || d.BytesIn+d.BytesOut != maxDumpChunks+100 {
		t.Fatalf("chunk metadata unbounded or totals stopped: chunks=%d total=%d truncated=%v", len(d.Chunks), d.BytesIn+d.BytesOut, d.Truncated)
	}
}

func TestRecorderSnapshotsAreIndependent(t *testing.T) {
	rec := NewRecorder(2, 64)
	w := rec.Begin(1, "client", "target")
	input := []byte("payload")
	w.Write(DirIn, input)
	input[0] = '!'
	listed := rec.List()
	listed[0].Chunks[0].Data[0] = '?'
	listed[0].Chunks[0].Dir = DirOut
	listed[0].RemoteAddr = "changed"
	got, ok := rec.Get(1)
	if !ok || got.RemoteAddr != "client" || string(dumpStream(got, DirIn)) != "payload" {
		t.Fatalf("List or input mutation changed recorder: %+v", got)
	}
	got.Chunks[0].Data[0] = '!'
	page, err := rec.Search(DumpQuery{})
	if err != nil {
		t.Fatal(err)
	}
	page.Items[0].Pinned = true
	got, _ = rec.Get(1)
	if got.Pinned || string(dumpStream(got, DirIn)) != "payload" {
		t.Fatal("Get or Search returned shared state")
	}
	if missing, ok := rec.Get(999); ok || missing != nil {
		t.Fatal("missing ID should return nil, false")
	}
}

func TestRecorderConcurrentOperations(t *testing.T) {
	rec := NewRecorder(16, 256)
	var wg sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := uint64(worker*1000 + i + 1)
				w := rec.Begin(id, "127.0.0.1:80", "service:80")
				w.Write(DirIn, []byte("request"))
				w.Write(DirOut, []byte("reply"))
				if i%3 == 0 {
					_ = rec.SetPinned(id, true)
				}
				if _, err := rec.Search(DumpQuery{Query: "quest"}); err != nil {
					t.Error(err)
				}
				rec.Get(id)
				rec.Count()
				rec.List()
				_ = rec.Resize(8+i%9, 64+i%128)
				_ = rec.SetPinned(id, false)
				if i%11 == 0 {
					rec.Clear()
				}
				if i%31 == 0 {
					rec.ClearAll()
				}
				w.Finish(7, 5)
			}
		}(worker)
	}
	wg.Wait()
	if rec.Count() > rec.maxConns || len(rec.active) > rec.Count() {
		t.Fatal("concurrent operations exceeded record bounds")
	}
	for _, d := range rec.List() {
		if len(d.Chunks) > maxDumpChunks || len(dumpStream(d, DirIn)) > rec.maxBytesPer || len(dumpStream(d, DirOut)) > rec.maxBytesPer {
			t.Fatal("concurrent operations exceeded payload bounds")
		}
	}
}
