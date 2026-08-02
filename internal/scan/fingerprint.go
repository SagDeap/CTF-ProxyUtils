package scan

import (
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	reHTTPServer = regexp.MustCompile(`(?i)^Server:\s*(.+)$`)
	reHTTPTitle  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reHTTPStatus = regexp.MustCompile(`^HTTP/1\.[01] (\d{3})`)
)

// fingerprint определяет, что за служба сидит на уже открытом порту.
// Сначала слушаем — многие протоколы (SSH, FTP, SMTP, Redis) представляются
// сами. Если собеседник молчит, пробуем заговорить с ним по HTTP: на CTF
// в подавляющем большинстве случаев там именно веб-сервис.
func fingerprint(conn net.Conn, timeout time.Duration) (service, banner string) {
	buf := make([]byte, 4096)

	conn.SetReadDeadline(time.Now().Add(timeout))
	n, _ := conn.Read(buf)
	if n > 0 {
		data := string(buf[:n])
		if svc := matchBanner(data); svc != "" {
			return svc, cleanBanner(data)
		}
		return "", cleanBanner(data)
	}

	// Молчит — спросим по HTTP.
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\nHost: scan\r\nUser-Agent: ctf-proxyutils\r\n\r\n")); err != nil {
		return "", ""
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, _ = conn.Read(buf)
	if n == 0 {
		return "", ""
	}
	data := string(buf[:n])
	if strings.HasPrefix(data, "HTTP/1.") {
		return "http", httpSummary(data)
	}
	if svc := matchBanner(data); svc != "" {
		return svc, cleanBanner(data)
	}
	return "", cleanBanner(data)
}

// matchBanner опознаёт протокол по первым байтам приветствия.
func matchBanner(data string) string {
	// TLS выдаёт себя заголовком записи: версия 0x03 0x0X во втором байте,
	// а в первом — рукопожатие (0x16) либо alert (0x15). Alert прилетает
	// как раз тогда, когда мы отправили открытый HTTP-запрос в TLS-порт.
	// Без этой проверки в баннер попадал бы бинарный мусор.
	if len(data) >= 3 && (data[0] == 0x16 || data[0] == 0x15) && data[1] == 0x03 {
		return "tls"
	}
	switch {
	case strings.HasPrefix(data, "SSH-"):
		return "ssh"
	case strings.HasPrefix(data, "HTTP/1."):
		return "http"
	case strings.HasPrefix(data, "RFB "):
		return "vnc"
	case strings.HasPrefix(data, "-ERR"), strings.HasPrefix(data, "+PONG"),
		strings.HasPrefix(data, "+OK Redis"):
		return "redis"
	case strings.HasPrefix(data, "220"):
		low := strings.ToLower(data)
		if strings.Contains(low, "ftp") {
			return "ftp"
		}
		if strings.Contains(low, "smtp") || strings.Contains(low, "esmtp") {
			return "smtp"
		}
		return "smtp/ftp"
	case strings.Contains(data, "mysql_native_password"),
		strings.Contains(data, "MariaDB"):
		return "mysql"
	case strings.HasPrefix(data, "*"), strings.HasPrefix(data, "$"):
		return "redis"
	}
	// PostgreSQL и MongoDB без корректного рукопожатия молчат либо шлют
	// бинарный мусор — по одному чтению их надёжно не отличить.
	return ""
}

// httpSummary вытаскивает из ответа то, что реально помогает опознать сервис:
// код, Server и <title>.
func httpSummary(data string) string {
	var parts []string
	if m := reHTTPStatus.FindStringSubmatch(data); m != nil {
		parts = append(parts, m[1])
	}
	headEnd := strings.Index(data, "\r\n\r\n")
	head := data
	if headEnd > 0 {
		head = data[:headEnd]
	}
	for _, line := range strings.Split(head, "\r\n") {
		if m := reHTTPServer.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			parts = append(parts, strings.TrimSpace(m[1]))
			break
		}
	}
	if m := reHTTPTitle.FindStringSubmatch(data); m != nil {
		title := strings.TrimSpace(m[1])
		if title != "" {
			parts = append(parts, "«"+truncate(title, 60)+"»")
		}
	}
	return strings.Join(parts, " · ")
}

// cleanBanner делает баннер пригодным для показа в таблице. Двоичный ответ
// возвращается пустым: строка из точек в выдаче только мешает.
func cleanBanner(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	binary := 0
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			b.WriteRune(' ')
		case r < 32 || r == 127:
			b.WriteRune('.')
			binary++
		default:
			b.WriteRune(r)
		}
	}
	if binary*4 > len([]rune(s)) { // больше четверти нечитаемого — это не баннер
		return ""
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	return truncate(out, 120)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
