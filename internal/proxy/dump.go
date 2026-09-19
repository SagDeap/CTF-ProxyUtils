package proxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	DirIn  = "in"  // клиент -> таргет
	DirOut = "out" // таргет -> клиент

	// Alternating one-byte writes must not create unbounded chunk metadata.
	maxDumpChunks = 256
)

var ErrDumpNotFound = errors.New("запись трафика не найдена")

type Chunk struct {
	At   time.Time `json:"at"`
	Dir  string    `json:"dir"`
	Data []byte    `json:"data"`
}

type ConnDump struct {
	ID         uint64    `json:"id"`
	RemoteAddr string    `json:"remote_addr"`
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at,omitempty"`
	Closed     bool      `json:"closed"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	Chunks     []Chunk   `json:"chunks,omitempty"`
	Truncated  bool      `json:"truncated"`
	Pinned     bool      `json:"pinned"`
	RiskScore  int       `json:"risk_score,omitempty"`
	Findings   int       `json:"findings,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
}

// DumpQuery searches captured stream prefixes independently in each direction.
// From and To include connections started at either boundary; Remote is a
// substring of the client address. Limit defaults to 100 and cannot exceed 500.
type DumpQuery struct {
	Query      string
	Mode       string
	Direction  string
	Remote     string
	From       time.Time
	To         time.Time
	PinnedOnly bool
	Offset     int
	Limit      int
}

type DumpPage struct {
	Items []*ConnDump `json:"items"`
	Total int         `json:"total"`
}

type recordedConn struct {
	ConnDump
	token        uint64
	writtenIn    int
	writtenOut   int
	metadataFull bool
	truncatedIn  bool
	truncatedOut bool
}

// Recorder stores at most maxConns records, each with at most maxBytesPer bytes
// per direction and maxDumpChunks chunks. Pinned records occupy normal slots.
// Writers hold only a token, so evicted or cleared captures release their data
// immediately even when the associated network connections are still open.
type Recorder struct {
	mu          sync.Mutex
	maxConns    int
	maxBytesPer int
	sequence    uint64
	dumps       []*recordedConn // oldest first
	active      map[uint64]*recordedConn
}

func NewRecorder(maxConns, maxBytesPer int) *Recorder {
	if maxConns <= 0 {
		maxConns = 50
	}
	if maxBytesPer <= 0 {
		maxBytesPer = 64 * 1024
	}
	return &Recorder{maxConns: maxConns, maxBytesPer: maxBytesPer, active: make(map[uint64]*recordedConn)}
}

// Resize preserves pins and refuses a connection limit smaller than their count.
// Reducing the byte limit keeps only the prefix of each captured direction.
func (r *Recorder) Resize(maxConns, maxBytesPer int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if maxConns <= 0 || maxBytesPer <= 0 {
		return errors.New("лимиты записи трафика должны быть положительными")
	}
	pinned := 0
	for _, d := range r.dumps {
		if d.Pinned {
			pinned++
		}
	}
	if pinned > maxConns {
		return fmt.Errorf("закреплено %d записей: сначала открепите лишние или установите лимит не меньше %d", pinned, pinned)
	}
	r.maxConns, r.maxBytesPer = maxConns, maxBytesPer
	for len(r.dumps) > maxConns {
		r.evictOldestUnpinned()
	}
	if cap(r.dumps) > maxConns {
		retained := make([]*recordedConn, len(r.dumps))
		copy(retained, r.dumps)
		r.dumps = retained
		active := make(map[uint64]*recordedConn, len(r.dumps))
		for _, d := range r.dumps {
			if !d.Closed {
				active[d.token] = d
			}
		}
		r.active = active
	}
	for _, d := range r.dumps {
		if d.writtenIn <= maxBytesPer && d.writtenOut <= maxBytesPer {
			continue
		}
		chunks := make([]Chunk, 0, len(d.Chunks))
		in, out := 0, 0
		for _, c := range d.Chunks {
			written := &in
			truncated := &d.truncatedIn
			if c.Dir == DirOut {
				written, truncated = &out, &d.truncatedOut
			}
			n := len(c.Data)
			if n > maxBytesPer-*written {
				n = maxBytesPer - *written
				d.Truncated = true
				*truncated = true
			}
			if n > 0 {
				// Copy even complete chunks, releasing any oversized backing array.
				c.Data = append([]byte(nil), c.Data[:n]...)
				chunks = append(chunks, c)
				*written += n
			}
		}
		d.Chunks, d.writtenIn, d.writtenOut = chunks, in, out
	}
	return nil
}

func (r *Recorder) evictOldestUnpinned() bool {
	for i, d := range r.dumps {
		if !d.Pinned {
			r.remove(i)
			return true
		}
	}
	return false
}

func (r *Recorder) remove(i int) {
	delete(r.active, r.dumps[i].token)
	copy(r.dumps[i:], r.dumps[i+1:])
	r.dumps[len(r.dumps)-1] = nil
	r.dumps = r.dumps[:len(r.dumps)-1]
}

// Begin skips capturing new connections when every available slot is pinned.
// A nil writer is safe to use through Write and Finish.
func (r *Recorder) Begin(id uint64, remote, target string) *connWriter {
	return r.BeginProtocol(id, remote, target, "tcp")
}

func (r *Recorder) BeginProtocol(id uint64, remote, target, protocol string) *connWriter {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, d := range r.dumps {
		if d.ID == id {
			if d.Pinned {
				return nil
			}
			r.remove(i)
			break
		}
	}
	if len(r.dumps) >= r.maxConns && !r.evictOldestUnpinned() {
		return nil
	}
	r.sequence++
	d := &recordedConn{ConnDump: ConnDump{
		ID: id, RemoteAddr: remote, Target: target, Protocol: protocol, StartedAt: time.Now(),
	}, token: r.sequence}
	r.dumps = append(r.dumps, d)
	r.active[d.token] = d
	return &connWriter{rec: r, token: d.token}
}

func (r *Recorder) MarkFinding(id uint64, score int, pin bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.dumps {
		if d.ID != id {
			continue
		}
		d.Findings++
		if score > d.RiskScore {
			d.RiskScore = score
		}
		if pin {
			d.Pinned = true
		}
		return nil
	}
	return ErrDumpNotFound
}

// Count reads only metadata; polling the panel never copies captured traffic.
func (r *Recorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.dumps)
}

func cloneDump(src *ConnDump, withChunks bool) *ConnDump {
	cp := *src
	cp.Chunks = nil
	if withChunks {
		cp.Chunks = make([]Chunk, len(src.Chunks))
		for i, c := range src.Chunks {
			cp.Chunks[i] = Chunk{At: c.At, Dir: c.Dir, Data: append([]byte(nil), c.Data...)}
		}
	}
	return &cp
}

// List returns independent, complete captures, newest first.
func (r *Recorder) List() []*ConnDump {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*ConnDump, 0, len(r.dumps))
	for i := len(r.dumps) - 1; i >= 0; i-- {
		out = append(out, cloneDump(&r.dumps[i].ConnDump, true))
	}
	return out
}

func (r *Recorder) Get(id uint64) (*ConnDump, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.dumps {
		if d.ID == id {
			return cloneDump(&d.ConnDump, true), true
		}
	}
	return nil, false
}

func (r *Recorder) SetPinned(id uint64, pinned bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.dumps {
		if d.ID == id {
			d.Pinned = pinned
			return nil
		}
	}
	return ErrDumpNotFound
}

func (r *Recorder) Search(q DumpQuery) (DumpPage, error) {
	page := DumpPage{Items: make([]*ConnDump, 0)}
	if q.Offset < 0 || q.Limit < 0 || q.Limit > 500 {
		return page, errors.New("offset должен быть неотрицательным, limit — от 0 до 500")
	}
	if len(q.Query) > 4096 {
		return page, errors.New("поисковый запрос длиннее 4096 байт")
	}
	if !q.From.IsZero() && !q.To.IsZero() && q.To.Before(q.From) {
		return page, errors.New("начало интервала позже окончания")
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	if q.Direction == "" {
		q.Direction = "any"
	}
	if q.Direction != "any" && q.Direction != DirIn && q.Direction != DirOut {
		return page, errors.New("направление поиска: any, in или out")
	}
	var match func([]byte) bool
	switch q.Mode {
	case "", "text":
		needle := []byte(q.Query)
		match = func(data []byte) bool { return bytes.Contains(data, needle) }
	case "hex":
		needle, err := hex.DecodeString(strings.Join(strings.Fields(q.Query), ""))
		if err != nil {
			return page, fmt.Errorf("неверная hex-строка: %w", err)
		}
		match = func(data []byte) bool { return bytes.Contains(data, needle) }
	case "regex":
		re, err := regexp.Compile(q.Query)
		if err != nil {
			return page, fmt.Errorf("неверное регулярное выражение: %w", err)
		}
		match = re.Match
	default:
		return page, errors.New("режим поиска: text, hex или regex")
	}
	remote := strings.ToLower(strings.TrimSpace(q.Remote))
	// Keep only stable record pointers while matching. A search may inspect up to
	// 256 MiB, so it must not hold the recorder lock and stall live forwarding.
	r.mu.Lock()
	candidates := append([]*recordedConn(nil), r.dumps...)
	r.mu.Unlock()
	for i := len(candidates) - 1; i >= 0; i-- {
		d := candidates[i]
		r.mu.Lock()
		summary := cloneDump(&d.ConnDump, false)
		r.mu.Unlock()
		if q.PinnedOnly && !summary.Pinned || !q.From.IsZero() && summary.StartedAt.Before(q.From) ||
			!q.To.IsZero() && summary.StartedAt.After(q.To) || !strings.Contains(strings.ToLower(summary.RemoteAddr), remote) {
			continue
		}
		if q.Query != "" {
			r.mu.Lock()
			full := cloneDump(&d.ConnDump, true)
			r.mu.Unlock()
			matched := false
			for _, dir := range []string{DirIn, DirOut} {
				if q.Direction != "any" && q.Direction != dir {
					continue
				}
				stream := make([]byte, 0)
				for _, c := range full.Chunks {
					if c.Dir == dir {
						stream = append(stream, c.Data...)
					}
				}
				if match(stream) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if page.Total >= q.Offset && len(page.Items) < q.Limit {
			page.Items = append(page.Items, summary)
		}
		page.Total++
	}
	return page, nil
}

// Clear keeps pinned captures. ClearAll explicitly removes pinned captures too.
func (r *Recorder) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.dumps) - 1; i >= 0; i-- {
		if !r.dumps[i].Pinned {
			r.remove(i)
		}
	}
}

func (r *Recorder) ClearAll() {
	r.mu.Lock()
	r.dumps = nil
	r.active = make(map[uint64]*recordedConn)
	r.mu.Unlock()
}

type connWriter struct {
	rec      *Recorder
	token    uint64
	observe  func(string, []byte)
	onFinish func()
}

func (w *connWriter) Write(dir string, b []byte) {
	w.write(dir, b, false)
}

func (w *connWriter) WriteDatagram(dir string, b []byte) {
	w.write(dir, b, true)
}

func (w *connWriter) write(dir string, b []byte, datagram bool) {
	if w == nil || len(b) == 0 || (dir != DirIn && dir != DirOut) {
		return
	}
	if w.observe != nil {
		w.observe(dir, b)
	}
	if w.rec == nil {
		return
	}
	w.rec.mu.Lock()
	defer w.rec.mu.Unlock()
	d := w.rec.active[w.token]
	if d == nil || d.Closed {
		return
	}
	written, total, truncated := &d.writtenIn, &d.BytesIn, &d.truncatedIn
	if dir == DirOut {
		written, total, truncated = &d.writtenOut, &d.BytesOut, &d.truncatedOut
	}
	*total += int64(len(b))
	if *truncated || d.metadataFull {
		return
	}
	room := w.rec.maxBytesPer - *written
	if room < len(b) {
		d.Truncated, *truncated = true, true
		b = b[:room]
	}
	if len(b) == 0 {
		return
	}
	last := len(d.Chunks) - 1
	if !datagram && last >= 0 && d.Chunks[last].Dir == dir {
		d.Chunks[last].Data = append(d.Chunks[last].Data, b...)
	} else {
		if len(d.Chunks) >= maxDumpChunks {
			d.Truncated, d.metadataFull = true, true
			return
		}
		d.Chunks = append(d.Chunks, Chunk{At: time.Now(), Dir: dir, Data: append([]byte(nil), b...)})
	}
	*written += len(b)
}

func (w *connWriter) Finish(bytesIn, bytesOut int64) {
	if w == nil {
		return
	}
	if w.onFinish != nil {
		w.onFinish()
		w.onFinish = nil
	}
	if w.rec == nil {
		return
	}
	w.rec.mu.Lock()
	defer w.rec.mu.Unlock()
	d := w.rec.active[w.token]
	if d == nil || d.Closed {
		return
	}
	d.Closed, d.EndedAt = true, time.Now()
	d.BytesIn, d.BytesOut = bytesIn, bytesOut
	delete(w.rec.active, w.token)
}
