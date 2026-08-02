package proxy

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startEcho поднимает эхо-сервер и возвращает его адрес.
func startEcho(t *testing.T) (Endpoint, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не удалось поднять эхо-сервер: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return endpointOf(t, ln.Addr()), func() { ln.Close() }
}

func endpointOf(t *testing.T, addr net.Addr) Endpoint {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("некорректный адрес %v: %v", addr, err)
	}
	port, _ := strconv.Atoi(portStr)
	return Endpoint{Host: host, Port: port}
}

// freePort занимает и сразу освобождает порт, чтобы узнать свободный номер.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не удалось найти свободный порт: %v", err)
	}
	defer ln.Close()
	return endpointOf(t, ln.Addr()).Port
}

// roundTrip отправляет строку через прокси и возвращает ответ.
func roundTrip(t *testing.T, addr, msg string) (string, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	buf := make([]byte, len(msg))
	n, err := io.ReadFull(c, buf)
	if err != nil {
		return string(buf[:n]), err
	}
	return string(buf[:n]), nil
}

func TestForwardingAndStats(t *testing.T) {
	echo, stopEcho := startEcho(t)
	defer stopEcho()

	port := freePort(t)
	m := NewManager()
	defer m.StopAll()

	rule, err := m.Add(RuleSpec{
		Name: "тест", Enabled: true,
		ListenHost: "127.0.0.1", ListenPort: port,
		Target: echo,
	})
	if err != nil {
		t.Fatalf("правило не создалось: %v", err)
	}

	const msg = "hello ctf"
	got, err := roundTrip(t, fmt.Sprintf("127.0.0.1:%d", port), msg)
	if err != nil {
		t.Fatalf("проброс не работает: %v", err)
	}
	if got != msg {
		t.Fatalf("через прокси пришло %q, ожидалось %q", got, msg)
	}

	// Счётчики обновляются в горутинах пайпа — дадим им завершиться.
	time.Sleep(150 * time.Millisecond)
	s := rule.Snapshot()
	if s.TotalConns != 1 {
		t.Errorf("всего соединений = %d, ожидалось 1", s.TotalConns)
	}
	if s.BytesIn != int64(len(msg)) {
		t.Errorf("принято %d байт, ожидалось %d", s.BytesIn, len(msg))
	}
	if s.BytesOut != int64(len(msg)) {
		t.Errorf("отдано %d байт, ожидалось %d", s.BytesOut, len(msg))
	}
	if !s.Running {
		t.Error("правило должно быть запущено")
	}
}

func TestStopClosesListener(t *testing.T) {
	echo, stopEcho := startEcho(t)
	defer stopEcho()

	port := freePort(t)
	m := NewManager()
	defer m.StopAll()

	if _, err := m.Add(RuleSpec{
		Enabled: true, ListenHost: "127.0.0.1", ListenPort: port, Target: echo,
	}); err != nil {
		t.Fatalf("правило не создалось: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if _, err := roundTrip(t, addr, "ping"); err != nil {
		t.Fatalf("проброс должен работать до остановки: %v", err)
	}

	rules := m.List()
	rules[0].Stop()

	if _, err := roundTrip(t, addr, "ping"); err == nil {
		t.Fatal("после Stop порт обязан быть свободен")
	}

	// Порт должен освободиться полностью — иначе перезапуск правила упадёт.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("порт не освободился после Stop: %v", err)
	}
	ln.Close()
}

func TestACLBlocksForeignClients(t *testing.T) {
	echo, stopEcho := startEcho(t)
	defer stopEcho()

	port := freePort(t)
	m := NewManager()
	defer m.StopAll()

	// Пускаем только 10.0.0.0/8 — наш 127.0.0.1 в список не входит.
	rule, err := m.Add(RuleSpec{
		Enabled: true, ListenHost: "127.0.0.1", ListenPort: port,
		Target: echo, AllowCIDR: []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("правило не создалось: %v", err)
	}

	if _, err := roundTrip(t, fmt.Sprintf("127.0.0.1:%d", port), "ping"); err == nil {
		t.Fatal("клиент вне белого списка не должен получить ответ")
	}
	time.Sleep(100 * time.Millisecond)
	if s := rule.Snapshot(); s.DeniedConns == 0 {
		t.Error("отклонённое соединение не попало в счётчик")
	}
}

func TestFailoverToBackup(t *testing.T) {
	primary, stopPrimary := startEcho(t)
	backup, stopBackup := startEcho(t)
	defer stopBackup()

	port := freePort(t)
	m := NewManager()
	defer m.StopAll()

	rule, err := m.Add(RuleSpec{
		Enabled: true, ListenHost: "127.0.0.1", ListenPort: port,
		Target: primary, Backup: &backup,
		Health: HealthSpec{
			Enabled: true, IntervalSec: 1, TimeoutMS: 200,
			FailAfter: 1, RiseAfter: 1, AutoFail: true, AutoBack: true,
		},
	})
	if err != nil {
		t.Fatalf("правило не создалось: %v", err)
	}

	// Роняем основной адрес — так же выглядит уснувший ноутбук.
	stopPrimary()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := rule.Snapshot(); s.UsingBackup {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	s := rule.Snapshot()
	if !s.UsingBackup {
		t.Fatalf("не переключились на резерв: target_up=%v backup_up=%v", s.TargetUp, s.BackupUp)
	}

	// И трафик обязан пойти на резерв, а не в никуда.
	got, err := roundTrip(t, fmt.Sprintf("127.0.0.1:%d", port), "via backup")
	if err != nil {
		t.Fatalf("резерв не принимает трафик: %v", err)
	}
	if got != "via backup" {
		t.Errorf("через резерв пришло %q", got)
	}
}

func TestDumpCapturesTraffic(t *testing.T) {
	echo, stopEcho := startEcho(t)
	defer stopEcho()

	port := freePort(t)
	m := NewManager()
	defer m.StopAll()

	rule, err := m.Add(RuleSpec{
		Enabled: true, ListenHost: "127.0.0.1", ListenPort: port,
		Target: echo,
		Dump:   DumpSpec{Enabled: true, MaxConns: 10, MaxBytesPer: 1024},
	})
	if err != nil {
		t.Fatalf("правило не создалось: %v", err)
	}

	const payload = "GET /flag HTTP/1.0"
	if _, err := roundTrip(t, fmt.Sprintf("127.0.0.1:%d", port), payload); err != nil {
		t.Fatalf("проброс не работает: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	dumps := rule.Dumps()
	if len(dumps) != 1 {
		t.Fatalf("записей дампа %d, ожидалась 1", len(dumps))
	}
	var seen []string
	for _, c := range dumps[0].Chunks {
		seen = append(seen, string(c.Data))
	}
	joined := strings.Join(seen, "")
	if !strings.Contains(joined, payload) {
		t.Errorf("в дампе нет отправленных данных, записано: %q", joined)
	}
}

func TestDumpRespectsByteLimit(t *testing.T) {
	rec := NewRecorder(2, 8)
	w := rec.Begin(1, "1.2.3.4:1000", "5.6.7.8:80")
	w.Write(DirIn, []byte("0123456789ABCDEF")) // вдвое больше лимита
	w.Finish(16, 0)

	dumps := rec.List()
	if len(dumps) != 1 {
		t.Fatalf("записей %d, ожидалась 1", len(dumps))
	}
	total := 0
	for _, c := range dumps[0].Chunks {
		total += len(c.Data)
	}
	if total != 8 {
		t.Errorf("записано %d байт, лимит 8", total)
	}
	if !dumps[0].Truncated {
		t.Error("обрезанная запись не помечена флагом Truncated")
	}
}

func TestRecorderEvictsOldest(t *testing.T) {
	rec := NewRecorder(2, 64)
	for i := 1; i <= 3; i++ {
		w := rec.Begin(uint64(i), "client", "target")
		w.Finish(0, 0)
	}
	dumps := rec.List()
	if len(dumps) != 2 {
		t.Fatalf("в буфере %d записей, ожидалось 2", len(dumps))
	}
	// List отдаёт свежие первыми: должны остаться 3 и 2.
	if dumps[0].ID != 3 || dumps[1].ID != 2 {
		t.Errorf("вытеснение сработало неверно: %d, %d", dumps[0].ID, dumps[1].ID)
	}
}

func TestPortConflictRejected(t *testing.T) {
	echo, stopEcho := startEcho(t)
	defer stopEcho()

	port := freePort(t)
	m := NewManager()
	defer m.StopAll()

	if _, err := m.Add(RuleSpec{
		Enabled: true, ListenHost: "127.0.0.1", ListenPort: port, Target: echo,
	}); err != nil {
		t.Fatalf("первое правило не создалось: %v", err)
	}
	_, err := m.Add(RuleSpec{
		Enabled: true, ListenHost: "127.0.0.1", ListenPort: port, Target: echo,
	})
	if err == nil {
		t.Fatal("второе правило на тот же порт должно быть отклонено")
	}
}

func TestValidateRejectsBadSpec(t *testing.T) {
	cases := []struct {
		name string
		spec RuleSpec
	}{
		{"нулевой порт", RuleSpec{ListenPort: 0, Target: Endpoint{Host: "1.1.1.1", Port: 80}}},
		{"нет цели", RuleSpec{ListenPort: 8080}},
		{"порт вне диапазона", RuleSpec{ListenPort: 70000, Target: Endpoint{Host: "1.1.1.1", Port: 80}}},
		{"кривой ACL", RuleSpec{ListenPort: 8080, Target: Endpoint{Host: "1.1.1.1", Port: 80}, AllowCIDR: []string{"не-сеть"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := c.spec
			spec.applyDefaults()
			if err := spec.Validate(); err == nil {
				t.Error("ожидалась ошибка валидации")
			}
		})
	}
}

func TestUpdateKeepsStatsWhenPortUnchanged(t *testing.T) {
	echo, stopEcho := startEcho(t)
	defer stopEcho()

	port := freePort(t)
	m := NewManager()
	defer m.StopAll()

	rule, err := m.Add(RuleSpec{
		Name: "было", Enabled: true,
		ListenHost: "127.0.0.1", ListenPort: port, Target: echo,
	})
	if err != nil {
		t.Fatalf("правило не создалось: %v", err)
	}
	if _, err := roundTrip(t, fmt.Sprintf("127.0.0.1:%d", port), "ping"); err != nil {
		t.Fatalf("проброс не работает: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	spec := rule.Spec()
	spec.Name = "стало"
	if err := m.Update(rule.ID(), spec); err != nil {
		t.Fatalf("обновление не прошло: %v", err)
	}

	s := rule.Snapshot()
	if s.Spec.Name != "стало" {
		t.Errorf("имя не обновилось: %q", s.Spec.Name)
	}
	if s.TotalConns == 0 {
		t.Error("правка имени не должна сбрасывать статистику")
	}
	if !s.Running {
		t.Error("правило должно остаться запущенным")
	}
}
