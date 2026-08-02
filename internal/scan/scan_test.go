package scan

import (
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"80", []int{80}},
		{"80,443", []int{80, 443}},
		{"7000-7003", []int{7000, 7001, 7002, 7003}},
		{"443,80,443", []int{80, 443}},          // дубликаты схлопываются
		{"22, 80 , 443", []int{22, 80, 443}},    // пробелы игнорируются
		{"7003-7000", []int{7000, 7001, 7002, 7003}}, // перевёрнутый диапазон
	}
	for _, c := range cases {
		got, err := ParsePorts(c.in)
		if err != nil {
			t.Errorf("ParsePorts(%q) вернул ошибку: %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("ParsePorts(%q) = %v, ожидалось %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("ParsePorts(%q) = %v, ожидалось %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestParsePortsDefaults(t *testing.T) {
	got, err := ParsePorts("")
	if err != nil {
		t.Fatalf("пустая строка должна давать набор по умолчанию: %v", err)
	}
	if len(got) != len(DefaultPorts) {
		t.Errorf("портов по умолчанию %d, ожидалось %d", len(got), len(DefaultPorts))
	}
}

func TestParsePortsRejectsGarbage(t *testing.T) {
	for _, in := range []string{"abc", "0", "65536", "80-", "-80", "1-20000"} {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) должен был вернуть ошибку", in)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	// /24 — без адреса сети и широковещательного.
	ips, err := expandCIDR("192.168.0.0/24")
	if err != nil {
		t.Fatalf("expandCIDR вернул ошибку: %v", err)
	}
	if len(ips) != 254 {
		t.Errorf("для /24 получено %d адресов, ожидалось 254", len(ips))
	}
	if ips[0] != "192.168.0.1" {
		t.Errorf("первый адрес %s, ожидался 192.168.0.1", ips[0])
	}
	if ips[len(ips)-1] != "192.168.0.254" {
		t.Errorf("последний адрес %s, ожидался 192.168.0.254", ips[len(ips)-1])
	}

	// Одиночный IP — тоже валидная цель.
	one, err := expandCIDR("10.1.2.3")
	if err != nil || len(one) != 1 || one[0] != "10.1.2.3" {
		t.Errorf("одиночный адрес разобран неверно: %v, %v", one, err)
	}

	// /30 — две используемые машины.
	four, err := expandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("expandCIDR(/30): %v", err)
	}
	if len(four) != 2 {
		t.Errorf("для /30 получено %d адресов, ожидалось 2", len(four))
	}
}

func TestExpandCIDRRejectsHugeAndBroken(t *testing.T) {
	for _, in := range []string{"10.0.0.0/8", "", "не-сеть", "192.168.0.0/33"} {
		if _, err := expandCIDR(in); err == nil {
			t.Errorf("expandCIDR(%q) должен был вернуть ошибку", in)
		}
	}
}

func TestIPLess(t *testing.T) {
	// Численное сравнение: .9 обязан идти раньше .10.
	if !ipLess("192.168.0.9", "192.168.0.10") {
		t.Error("192.168.0.9 должен сортироваться раньше 192.168.0.10")
	}
	if ipLess("192.168.0.10", "192.168.0.9") {
		t.Error("сравнение адресов несимметрично")
	}
}

func TestMatchBanner(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_9.2p1 Debian":  "ssh",
		"HTTP/1.1 200 OK\r\n":           "http",
		"RFB 003.008\n":                 "vnc",
		"-ERR unknown command":          "redis",
		"220 ProFTPD Server ready":      "ftp",
		"220 mail.example.com ESMTP":    "smtp",
		"случайный мусор":                "",
	}
	for banner, want := range cases {
		if got := matchBanner(banner); got != want {
			t.Errorf("matchBanner(%q) = %q, ожидалось %q", banner, got, want)
		}
	}
}

func TestHTTPSummary(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n" +
		"<html><head><title>Служба доставки</title></head><body>ok</body></html>"
	got := httpSummary(resp)
	for _, want := range []string{"200", "nginx/1.24.0", "Служба доставки"} {
		if !contains(got, want) {
			t.Errorf("в сводке %q нет %q", got, want)
		}
	}
}

func TestCleanBannerStripsControlChars(t *testing.T) {
	got := cleanBanner("SSH-2.0 OpenSSH_9.2p1 Debian-2\x00\x01")
	if contains(got, "\x00") || contains(got, "\n") {
		t.Errorf("управляющие символы не вычищены: %q", got)
	}
	if !contains(got, "OpenSSH") {
		t.Errorf("полезная часть баннера потеряна: %q", got)
	}
}

func TestCleanBannerDropsBinary(t *testing.T) {
	// Ответ TLS-сервера — сплошные двоичные байты; в таблице ему не место.
	if got := cleanBanner("\x16\x03\x03\x00\x5a\x02\x00\x00\x56\x03\x03"); got != "" {
		t.Errorf("двоичный ответ должен давать пустой баннер, получено %q", got)
	}
}

func TestMatchBannerDetectsTLS(t *testing.T) {
	if got := matchBanner("\x16\x03\x03\x00\x5a\x02"); got != "tls" {
		t.Errorf("TLS-рукопожатие определилось как %q", got)
	}
	// Ответ на открытый HTTP-запрос в TLS-порт — alert-запись.
	if got := matchBanner("\x15\x03\x01\x00\x02\x02\x16"); got != "tls" {
		t.Errorf("TLS-alert определился как %q", got)
	}
	// Похожий по первому байту, но не TLS текст не должен ловиться.
	if got := matchBanner("\x16 обычный текст"); got == "tls" {
		t.Error("не-TLS данные приняты за TLS")
	}
}

func TestLookupVendor(t *testing.T) {
	if got := lookupVendor("52:54:00:12:34:56"); got != "QEMU/KVM" {
		t.Errorf("52:54:00 определился как %q, ожидалось QEMU/KVM", got)
	}
	if got := lookupVendor("08:00:27:aa:bb:cc"); got != "VirtualBox" {
		t.Errorf("08:00:27 определился как %q, ожидалось VirtualBox", got)
	}
	// Второй бит первого октета — признак случайного MAC.
	if got := lookupVendor("a6:11:22:33:44:55"); got != "случайный MAC" {
		t.Errorf("локально администрируемый адрес определился как %q", got)
	}
	if got := lookupVendor("зз"); got != "" {
		t.Errorf("мусор должен давать пустую строку, получено %q", got)
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
