package scan

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// arpEntry — строка из системной ARP-таблицы.
type arpEntry struct {
	MAC    string
	Device string
}

// readARP читает /proc/net/arp. Таблица заполняется ядром при любом обмене
// с соседом, поэтому после скана портов там оказываются все, кто ответил, —
// MAC достаётся бесплатно и без raw-сокетов, то есть без root.
func readARP() map[string]arpEntry {
	out := make(map[string]arpEntry)
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out // не Linux или нет доступа — просто останемся без MAC
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first { // заголовок таблицы
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		ip, flags, mac, device := fields[0], fields[2], fields[3], fields[5]
		// Флаг 0x0 — неполная запись: сосед не ответил, MAC мусорный.
		if n, err := strconv.ParseUint(strings.TrimPrefix(flags, "0x"), 16, 32); err == nil && n == 0 {
			continue
		}
		if mac == "00:00:00:00:00:00" {
			continue
		}
		out[ip] = arpEntry{MAC: strings.ToLower(mac), Device: device}
	}
	return out
}

// ouiVendors — намеренно короткая таблица: только те префиксы, за которые
// можно ручаться. Больше всего пользы от гипервизоров — они сразу говорят,
// что перед нами виртуалка, а не чей-то ноутбук.
var ouiVendors = map[string]string{
	"00:05:69": "VMware",
	"00:0c:29": "VMware",
	"00:1c:14": "VMware",
	"00:50:56": "VMware",
	"08:00:27": "VirtualBox",
	"0a:00:27": "VirtualBox (host-only)",
	"52:54:00": "QEMU/KVM",
	"00:16:3e": "Xen",
	"00:15:5d": "Hyper-V",
	"02:42:ac": "Docker",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"28:cd:c1": "Raspberry Pi",
}

// lookupVendor определяет вендора по MAC. Кроме таблицы OUI распознаёт
// локально администрируемые адреса — так выглядит рандомизированный MAC,
// который телефоны и ноутбуки подставляют в Wi-Fi ради приватности.
func lookupVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToLower(mac[:8])
	if v, ok := ouiVendors[prefix]; ok {
		return v
	}
	// Второй бит первого октета = locally administered.
	if b, err := strconv.ParseUint(mac[:2], 16, 8); err == nil {
		if b&0x02 != 0 {
			return "случайный MAC"
		}
	}
	return ""
}
