package proxy

import (
	"net"
	"strings"
	"testing"
)

// baseSpec — корректное правило, которое каждый случай портит по-своему.
func baseSpec() RuleSpec {
	return RuleSpec{ListenHost: "0.0.0.0", ListenPort: 7000, Target: Endpoint{Host: "10.0.0.5", Port: 7000}}
}

func TestValidateExplainsRejectedSpecs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RuleSpec)
		want   string // фрагмент текста ошибки
	}{
		{"неизвестный протокол", func(s *RuleSpec) { s.Protocol = "sctp" }, "протокол"},
		{"слишком долгий TTL UDP", func(s *RuleSpec) { s.Protocol = "udp"; s.UDPIdleSec = 3601 }, "TTL"},
		{"неизвестный режим маршрутизации", func(s *RuleSpec) { s.RoutingMode = "sideways" }, "режим маршрутизации"},
		{"режим резерва без резерва", func(s *RuleSpec) { s.RoutingMode = "backup" }, "резервный адрес"},
		{"отрицательный лимит", func(s *RuleSpec) { s.MaxConns = -1 }, "отрицательными"},
		{"неизвестный health-check", func(s *RuleSpec) { s.Health.Mode = "icmp" }, "health-check"},
		{"HTTP-статус вне диапазона", func(s *RuleSpec) { s.Health.HTTPStatus = 600 }, "HTTP-статус"},
		{"HTTP-метод с пробелом", func(s *RuleSpec) { s.Health.HTTPMethod = "GE T" }, "HTTP-метод"},
		{"перевод строки в пути", func(s *RuleSpec) { s.Health.HTTPPath = "/\r\nX-Injected: 1" }, "перевод строки"},
		{"перевод строки в заголовке", func(s *RuleSpec) { s.Health.HTTPHeaders = map[string]string{"X-Probe": "a\nb"} }, "HTTP-заголовок"},
		{"двоеточие в имени заголовка", func(s *RuleSpec) { s.Health.HTTPHeaders = map[string]string{"X:Probe": "a"} }, "HTTP-заголовок"},
		{"кривой hex запроса", func(s *RuleSpec) { s.Health.RequestMode = "hex"; s.Health.Request = "zz" }, "hex"},
		{"кривой regex ответа", func(s *RuleSpec) { s.Health.ExpectMode = "regex"; s.Health.Expect = "[" }, "regex"},
		{"HTTP health-check для UDP", func(s *RuleSpec) { s.Protocol = "udp"; s.Health.Mode = "http" }, "UDP"},
		{"UDP health-check без ответа", func(s *RuleSpec) {
			s.Protocol = "udp"
			s.Health = HealthSpec{Enabled: true, Mode: "payload", Request: "ping"}
		}, "UDP health-check"},
		{"дамп сверх 256 МиБ", func(s *RuleSpec) { s.Dump = DumpSpec{Enabled: true, MaxConns: 33, MaxBytesPer: 4 << 20} }, "лимит дампов"},
		{"порт цели вне диапазона", func(s *RuleSpec) { s.Target.Port = 65536 }, "порт назначения"},
		{"слушатель не IP", func(s *RuleSpec) { s.ListenHost = "localhost" }, "не является IP"},
		{"пустой хост цели", func(s *RuleSpec) { s.Target.Host = "   " }, "пустой хост"},
		{"петля через localhost", func(s *RuleSpec) { s.Target = Endpoint{Host: "localhost.", Port: 7000} }, "совпадает со слушателем"},
		{"петля через loopback", func(s *RuleSpec) { s.Target = Endpoint{Host: "127.0.0.1", Port: 7000} }, "совпадает со слушателем"},
		{"петля на тот же IP", func(s *RuleSpec) { s.ListenHost = "10.0.0.5" }, "совпадает со слушателем"},
		{"резерв смотрит на слушателя", func(s *RuleSpec) { s.Backup = &Endpoint{Host: "::1", Port: 7000} }, "резервный адрес совпадает"},
		{"порт резерва вне диапазона", func(s *RuleSpec) { s.Backup = &Endpoint{Host: "10.0.0.6", Port: 70000} }, "порт резервного"},
		{"кривая подсеть ACL", func(s *RuleSpec) { s.AllowCIDR = []string{"10.0.0.0/33"} }, "белом списке"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := baseSpec()
			c.mutate(&spec)
			spec.applyDefaults()
			err := spec.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ошибка %v, ожидался фрагмент %q", err, c.want)
			}
		})
	}
}

func TestValidateAcceptsLegitimateSpecs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RuleSpec)
	}{
		{"значения по умолчанию", func(s *RuleSpec) {}},
		{"другой порт на loopback", func(s *RuleSpec) { s.Target = Endpoint{Host: "127.0.0.1", Port: 7001} }},
		{"другой loopback при конкретном слушателе", func(s *RuleSpec) {
			s.ListenHost = "127.0.0.1"
			s.Target = Endpoint{Host: "127.0.0.2", Port: 7000}
		}},
		{"имя хоста без DNS-проверки", func(s *RuleSpec) { s.Target = Endpoint{Host: "service.local", Port: 7000} }},
		{"ACL из IP, IPv6 и пустых строк", func(s *RuleSpec) { s.AllowCIDR = []string{"10.0.0.7", " ", "fd00::/8", "::1"} }},
		{"UDP с payload health-check", func(s *RuleSpec) {
			s.Protocol = "udp"
			s.Health = HealthSpec{Enabled: true, Mode: "payload", Request: "70 69 6e 67", RequestMode: "hex", Expect: "^pong", ExpectMode: "regex"}
		}},
		{"HTTP health-check с заголовками", func(s *RuleSpec) {
			s.Health = HealthSpec{Enabled: true, Mode: "http", HTTPMethod: "PROPFIND", HTTPPath: "/health",
				HTTPHeaders: map[string]string{"Authorization": "Bearer a:b"}, HTTPStatus: 204}
		}},
		{"ручной резерв", func(s *RuleSpec) {
			s.Backup = &Endpoint{Host: "10.0.0.6", Port: 7000}
			s.RoutingMode = "backup"
		}},
		{"дамп ровно на лимите", func(s *RuleSpec) { s.Dump = DumpSpec{Enabled: true, MaxConns: 32, MaxBytesPer: 4 << 20} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := baseSpec()
			c.mutate(&spec)
			spec.applyDefaults()
			if err := spec.Validate(); err != nil {
				t.Fatalf("корректное правило отклонено: %v", err)
			}
		})
	}
}

func TestValidateRejectsLoopToLocalInterface(t *testing.T) {
	addresses, _ := net.InterfaceAddrs()
	for _, address := range addresses {
		local, ok := address.(*net.IPNet)
		if !ok || local.IP.IsLoopback() || local.IP.To4() == nil {
			continue
		}
		spec := baseSpec()
		spec.Target = Endpoint{Host: local.IP.String(), Port: spec.ListenPort}
		spec.applyDefaults()
		if err := spec.Validate(); err == nil {
			t.Fatalf("слушатель 0.0.0.0 пропустил петлю на свой адрес %s", local.IP)
		}
		return
	}
	t.Skip("нет внешнего IPv4-адреса на интерфейсах")
}

func TestParseACLNormalizesAddresses(t *testing.T) {
	nets, err := parseACL([]string{" 10.0.0.7 ", "", "192.168.0.0/24", "fd00::1"})
	if err != nil || len(nets) != 3 {
		t.Fatalf("ACL = %v, %v", nets, err)
	}
	for ip, want := range map[string]bool{
		"10.0.0.7": true, "10.0.0.8": false,
		"192.168.0.200": true, "192.168.1.1": false,
		"fd00::1": true, "fd00::2": false,
	} {
		got := false
		for _, n := range nets {
			got = got || n.Contains(net.ParseIP(ip))
		}
		if got != want {
			t.Errorf("%s разрешён=%v, ожидалось %v", ip, got, want)
		}
	}
	if nets, err := parseACL(nil); nets != nil || err != nil {
		t.Fatalf("пустой ACL = %v, %v", nets, err)
	}
	if _, err := parseACL([]string{"10.0.0.0/8", "сеть"}); err == nil {
		t.Fatal("некорректная запись принята")
	}
}

func TestEndpointFormatting(t *testing.T) {
	for _, c := range []struct {
		endpoint Endpoint
		want     string
	}{
		{Endpoint{Host: "10.0.0.1", Port: 80}, "10.0.0.1:80"},
		{Endpoint{Host: "::1", Port: 443}, "[::1]:443"},
		{Endpoint{Host: "service", Port: 0}, ""},
		{Endpoint{Port: 80}, ""},
	} {
		if got := c.endpoint.String(); got != c.want {
			t.Errorf("%+v.String() = %q, ожидалось %q", c.endpoint, got, c.want)
		}
	}
}
