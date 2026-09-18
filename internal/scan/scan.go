package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// maxHosts не даёт случайно запустить скан /8 и повесить утилиту.
const maxHosts = 65536

// Options — параметры одного запуска скана.
type Options struct {
	CIDR        string `json:"cidr"`
	Ports       string `json:"ports"`
	TimeoutMS   int    `json:"timeout_ms"`
	Concurrency int    `json:"concurrency"`
	Fingerprint bool   `json:"fingerprint"`
}

func (o *Options) applyDefaults() {
	if o.TimeoutMS <= 0 {
		o.TimeoutMS = 500
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 256
	}
	if o.Concurrency > 2048 {
		o.Concurrency = 2048
	}
}

// PortResult — открытый порт с тем, что удалось о нём узнать.
type PortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// Host — найденная машина.
type Host struct {
	IP       string       `json:"ip"`
	MAC      string       `json:"mac,omitempty"`
	Vendor   string       `json:"vendor,omitempty"`
	Hostname string       `json:"hostname,omitempty"`
	IsSelf   bool         `json:"is_self"`
	Ports    []PortResult `json:"ports"`
	// Reachable=true и пустой Ports означает «хост жив, но все порты закрыты»:
	// такой ответ даёт TCP RST, и это тоже полезный сигнал.
	Reachable bool `json:"reachable"`
}

// State — состояние скана, каким его видит веб-интерфейс.
type State struct {
	Running    bool      `json:"running"`
	CIDR       string    `json:"cidr,omitempty"`
	Ports      string    `json:"ports,omitempty"`
	Total      int64     `json:"total"`
	Done       int64     `json:"done"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Hosts      []Host    `json:"hosts"`
	Error      string    `json:"error,omitempty"`
}

// Scanner держит состояние текущего/последнего скана. Одновременно
// выполняется только один — параллельные сканы только мешали бы друг другу.
type Scanner struct {
	// Keep 64-bit atomic counters aligned on 32-bit targets.
	total   int64
	done    int64
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc

	cidr      string
	portsSpec string
	startedAt time.Time
	finished  time.Time
	hosts     map[string]*Host
	errMsg    string
}

func NewScanner() *Scanner {
	return &Scanner{hosts: make(map[string]*Host)}
}

// Start запускает скан в фоне. Возвращает ошибку, если параметры кривые
// или скан уже идёт.
func (s *Scanner) Start(opts Options) error {
	opts.applyDefaults()

	ips, err := expandCIDR(opts.CIDR)
	if err != nil {
		return err
	}
	ports, err := ParsePorts(opts.Ports)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("скан уже выполняется")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.running = true
	s.cancel = cancel
	s.cidr = opts.CIDR
	s.portsSpec = opts.Ports
	s.hosts = make(map[string]*Host)
	s.startedAt = time.Now()
	s.finished = time.Time{}
	s.errMsg = ""
	atomic.StoreInt64(&s.total, int64(len(ips))*int64(len(ports)))
	atomic.StoreInt64(&s.done, 0)
	s.mu.Unlock()

	go s.run(ctx, ips, ports, opts)
	return nil
}

// Stop прерывает текущий скан; уже найденное остаётся.
func (s *Scanner) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Scanner) run(ctx context.Context, ips []string, ports []int, opts Options) {
	defer func() {
		s.mu.Lock()
		s.running = false
		s.cancel = nil
		s.finished = time.Now()
		s.mu.Unlock()
	}()

	timeout := time.Duration(opts.TimeoutMS) * time.Millisecond
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				wg.Wait()
				s.enrich(ctx)
				return
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				s.probe(ctx, ip, port, timeout, opts.Fingerprint)
				atomic.AddInt64(&s.done, 1)
			}(ip, port)
		}
	}
	wg.Wait()
	s.enrich(ctx)
}

// probe — один TCP-connect. Ключевая деталь: «connection refused» значит,
// что хост жив и ответил RST. Молчание (таймаут) не говорит ничего.
func (s *Scanner) probe(ctx context.Context, ip string, port int, timeout time.Duration, fp bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if isRefused(err) {
			s.markReachable(ip)
		}
		return
	}
	defer conn.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-finished:
		}
	}()

	res := PortResult{Port: port}
	if fp {
		res.Service, res.Banner = fingerprint(conn, timeout)
	}
	if res.Service == "" {
		res.Service = guessByPort(port)
	}
	s.addPort(ip, res)
}

// isRefused отличает активный отказ от таймаута.
func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

func (s *Scanner) markReachable(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[ip]
	if !ok {
		h = &Host{IP: ip}
		s.hosts[ip] = h
	}
	h.Reachable = true
}

func (s *Scanner) addPort(ip string, res PortResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[ip]
	if !ok {
		h = &Host{IP: ip}
		s.hosts[ip] = h
	}
	h.Reachable = true
	h.Ports = append(h.Ports, res)
}

// enrich дополняет найденные хосты тем, что дёшево узнать постфактум:
// MAC из ARP-таблицы (она уже заполнилась во время скана), обратный DNS
// и пометку собственных адресов.
func (s *Scanner) enrich(ctx context.Context) {
	s.mu.Lock()
	ips := make([]string, 0, len(s.hosts))
	for ip := range s.hosts {
		ips = append(ips, ip)
	}
	s.mu.Unlock()

	arp := readARP()
	self := LocalIPs()

	// Обратный DNS может тормозить, поэтому параллельно и с коротким сроком.
	var wg sync.WaitGroup
	names := make(map[string]string)
	var nameMu sync.Mutex
	sem := make(chan struct{}, 32)
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			lookupCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
			defer cancel()
			var r net.Resolver
			addrs, err := r.LookupAddr(lookupCtx, ip)
			if err != nil || len(addrs) == 0 {
				return
			}
			nameMu.Lock()
			names[ip] = strings.TrimSuffix(addrs[0], ".")
			nameMu.Unlock()
		}(ip)
	}
	wg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, h := range s.hosts {
		if e, ok := arp[ip]; ok {
			h.MAC = e.MAC
			h.Vendor = lookupVendor(e.MAC)
		}
		if n, ok := names[ip]; ok {
			h.Hostname = n
		}
		if self[ip] {
			h.IsSelf = true
		}
		sort.Slice(h.Ports, func(i, j int) bool { return h.Ports[i].Port < h.Ports[j].Port })
	}
}

// State отдаёт снимок текущего состояния, хосты отсортированы по адресу.
func (s *Scanner) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()

	hosts := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		cp := *h
		cp.Ports = append([]PortResult(nil), h.Ports...)
		hosts = append(hosts, cp)
	}
	sort.Slice(hosts, func(i, j int) bool {
		return ipLess(hosts[i].IP, hosts[j].IP)
	})

	return State{
		Running:    s.running,
		CIDR:       s.cidr,
		Ports:      s.portsSpec,
		Total:      atomic.LoadInt64(&s.total),
		Done:       atomic.LoadInt64(&s.done),
		StartedAt:  s.startedAt,
		FinishedAt: s.finished,
		Hosts:      hosts,
		Error:      s.errMsg,
	}
}

// expandCIDR разворачивает подсеть в список адресов для перебора.
func expandCIDR(cidr string) ([]string, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, errors.New("не указана подсеть для скана")
	}
	// Одиночный адрес — тоже допустимая цель.
	if ip := net.ParseIP(cidr); ip != nil {
		if ip.To4() == nil {
			return nil, errors.New("поддерживается только IPv4")
		}
		return []string{ip.String()}, nil
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("некорректная подсеть %q", cidr)
	}
	if ipnet.IP.To4() == nil {
		return nil, errors.New("поддерживается только IPv4")
	}

	ones, bits := ipnet.Mask.Size()
	size64 := uint64(1) << uint(bits-ones)
	if size64 > maxHosts {
		return nil, fmt.Errorf("подсеть /%d слишком большая — максимум %d адресов", ones, maxHosts)
	}
	size := int(size64)

	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	out := make([]string, 0, size)
	for i := 0; i < size; i++ {
		// В сетях шире /31 адреса сети и широковещательный не опрашиваем.
		if size > 2 && (i == 0 || i == size-1) {
			continue
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base+uint32(i))
		out = append(out, net.IP(b[:]).String())
	}
	return out, nil
}

// ipLess сравнивает адреса численно, чтобы .10 не оказался перед .9.
func ipLess(a, b string) bool {
	ipa, ipb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ipa == nil || ipb == nil {
		return a < b
	}
	return binary.BigEndian.Uint32(ipa) < binary.BigEndian.Uint32(ipb)
}

// guessByPort — запасной вариант, когда фингерпринт выключен или служба молчит.
var wellKnown = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
	3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http",
	8443: "https", 27017: "mongodb",
}

func guessByPort(port int) string {
	if s, ok := wellKnown[port]; ok {
		return s
	}
	return ""
}
