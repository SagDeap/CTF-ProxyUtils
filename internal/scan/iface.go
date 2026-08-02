package scan

import (
	"net"
	"strings"
)

// Iface — локальный интерфейс с подсетью, которую можно просканировать.
type Iface struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	CIDR      string `json:"cidr"`
	HostCount int    `json:"host_count"`
	Up        bool   `json:"up"`
	Loopback  bool   `json:"loopback"`
	// Suggested — стоит ли предлагать эту сеть для скана по умолчанию.
	Suggested bool `json:"suggested"`
}

// Interfaces собирает IPv4-подсети локальных интерфейсов. Именно из этого
// списка веб-интерфейс предлагает, что сканировать.
func Interfaces() []Iface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []Iface
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		up := ifi.Flags&net.FlagUp != 0
		loop := ifi.Flags&net.FlagLoopback != 0
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue // IPv6 в CTF-локалке не нужен
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 {
				continue
			}
			network := &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}
			count := 0
			if ones <= 30 {
				count = (1 << uint(32-ones)) - 2
			} else {
				count = 1 << uint(32-ones)
			}
			out = append(out, Iface{
				Name:      ifi.Name,
				IP:        ipnet.IP.String(),
				CIDR:      network.String(),
				HostCount: count,
				Up:        up,
				Loopback:  loop,
				// Предлагаем только живые не-loopback сети разумного размера:
				// сканировать /8 докера или мостов смысла нет.
				Suggested: up && !loop && ones >= 22 && !isDockerBridge(ifi.Name),
			})
		}
	}
	return out
}

// isDockerBridge отсеивает мосты контейнеров — команда сидит не там.
func isDockerBridge(name string) bool {
	return strings.HasPrefix(name, "docker") ||
		strings.HasPrefix(name, "br-") ||
		strings.HasPrefix(name, "veth") ||
		strings.HasPrefix(name, "virbr")
}

// LocalIPs — множество собственных адресов, чтобы пометить себя в выдаче скана.
func LocalIPs() map[string]bool {
	out := make(map[string]bool)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			out[ipnet.IP.String()] = true
		}
	}
	return out
}

// DefaultCIDR — самая правдоподобная сеть для скана: первая подходящая
// не-loopback подсеть.
func DefaultCIDR() string {
	for _, ifi := range Interfaces() {
		if ifi.Suggested {
			return ifi.CIDR
		}
	}
	return ""
}
