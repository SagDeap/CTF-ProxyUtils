package proxy

import (
	"sync"
	"time"
)

// Направление куска трафика.
const (
	DirIn  = "in"  // клиент -> таргет (то, чем нас атакуют)
	DirOut = "out" // таргет -> клиент (то, что утекает в ответ)
)

// Chunk — один прочитанный кусок данных с меткой времени и направлением.
type Chunk struct {
	At   time.Time `json:"at"`
	Dir  string    `json:"dir"`
	Data []byte    `json:"data"`
}

// ConnDump — запись одного соединения через правило.
type ConnDump struct {
	ID         uint64    `json:"id"`
	RemoteAddr string    `json:"remote_addr"`
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at,omitempty"`
	Closed     bool      `json:"closed"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	Chunks     []Chunk   `json:"chunks"`
	// Truncated говорит, что часть данных не записана из-за лимита.
	Truncated bool `json:"truncated"`
}

// Recorder хранит последние N соединений правила в кольцевом буфере.
// Память ограничена сверху: maxConns * maxBytesPer * 2 направления.
type Recorder struct {
	mu          sync.Mutex
	maxConns    int
	maxBytesPer int
	dumps       []*ConnDump // кольцевой буфер, dumps[0] — самый старый
}

func NewRecorder(maxConns, maxBytesPer int) *Recorder {
	if maxConns <= 0 {
		maxConns = 50
	}
	if maxBytesPer <= 0 {
		maxBytesPer = 64 * 1024
	}
	return &Recorder{maxConns: maxConns, maxBytesPer: maxBytesPer}
}

// Resize меняет лимиты на лету, подрезая уже накопленное.
func (r *Recorder) Resize(maxConns, maxBytesPer int) {
	if maxConns <= 0 || maxBytesPer <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxConns = maxConns
	r.maxBytesPer = maxBytesPer
	if len(r.dumps) > maxConns {
		r.dumps = r.dumps[len(r.dumps)-maxConns:]
	}
}

// Begin заводит запись под новое соединение и вытесняет самое старое.
func (r *Recorder) Begin(id uint64, remote, target string) *connWriter {
	d := &ConnDump{
		ID:         id,
		RemoteAddr: remote,
		Target:     target,
		StartedAt:  time.Now(),
	}
	r.mu.Lock()
	r.dumps = append(r.dumps, d)
	if len(r.dumps) > r.maxConns {
		r.dumps = r.dumps[len(r.dumps)-r.maxConns:]
	}
	limit := r.maxBytesPer
	r.mu.Unlock()
	return &connWriter{rec: r, dump: d, limit: limit}
}

// List отдаёт копию накопленных дампов, свежие — первыми.
// data каждого чанка копируется, чтобы вызывающий не держал наши буферы.
func (r *Recorder) List() []*ConnDump {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*ConnDump, 0, len(r.dumps))
	for i := len(r.dumps) - 1; i >= 0; i-- {
		src := r.dumps[i]
		cp := *src
		cp.Chunks = make([]Chunk, len(src.Chunks))
		for j, c := range src.Chunks {
			data := make([]byte, len(c.Data))
			copy(data, c.Data)
			cp.Chunks[j] = Chunk{At: c.At, Dir: c.Dir, Data: data}
		}
		out = append(out, &cp)
	}
	return out
}

// Clear выбрасывает всё записанное.
func (r *Recorder) Clear() {
	r.mu.Lock()
	r.dumps = nil
	r.mu.Unlock()
}

// connWriter — ручка записи для одного соединения. Лимит считается
// отдельно по каждому направлению, чтобы болтливый ответ не вытеснил запрос.
type connWriter struct {
	rec     *Recorder
	dump    *ConnDump
	limit   int
	writtenIn  int
	writtenOut int
}

func (w *connWriter) Write(dir string, b []byte) {
	if w == nil || len(b) == 0 {
		return
	}
	w.rec.mu.Lock()
	defer w.rec.mu.Unlock()

	written := &w.writtenIn
	if dir == DirOut {
		written = &w.writtenOut
	}
	room := w.limit - *written
	if room <= 0 {
		w.dump.Truncated = true
		return
	}
	if len(b) > room {
		b = b[:room]
		w.dump.Truncated = true
	}
	data := make([]byte, len(b))
	copy(data, b)
	*written += len(data)
	w.dump.Chunks = append(w.dump.Chunks, Chunk{At: time.Now(), Dir: dir, Data: data})
}

// Finish закрывает запись соединения и фиксирует итоговые счётчики.
func (w *connWriter) Finish(bytesIn, bytesOut int64) {
	if w == nil {
		return
	}
	w.rec.mu.Lock()
	w.dump.Closed = true
	w.dump.EndedAt = time.Now()
	w.dump.BytesIn = bytesIn
	w.dump.BytesOut = bytesOut
	w.rec.mu.Unlock()
}
