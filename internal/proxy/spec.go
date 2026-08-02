package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Endpoint — адрес назначения, куда правило гонит трафик.
type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (e Endpoint) Addr() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

func (e Endpoint) IsZero() bool {
	return e.Host == "" || e.Port == 0
}

func (e Endpoint) String() string {
	if e.IsZero() {
		return ""
	}
	return e.Addr()
}

// HealthSpec описывает, как проверять живость таргета.
type HealthSpec struct {
	Enabled     bool `json:"enabled"`
	IntervalSec int  `json:"interval_sec"` // как часто проверять
	TimeoutMS   int  `json:"timeout_ms"`   // таймаут одной проверки
	FailAfter   int  `json:"fail_after"`   // сколько подряд неудач до пометки down
	RiseAfter   int  `json:"rise_after"`   // сколько подряд успехов до возврата в up
	AutoFail    bool `json:"auto_failover"` // переключаться на backup автоматически
	AutoBack    bool `json:"auto_failback"` // возвращаться на основной, когда он ожил
}

func (h *HealthSpec) applyDefaults() {
	if h.IntervalSec <= 0 {
		h.IntervalSec = 3
	}
	if h.TimeoutMS <= 0 {
		h.TimeoutMS = 1000
	}
	if h.FailAfter <= 0 {
		h.FailAfter = 2
	}
	if h.RiseAfter <= 0 {
		h.RiseAfter = 2
	}
}

// DumpSpec — настройки записи трафика, проходящего через правило.
type DumpSpec struct {
	Enabled     bool `json:"enabled"`
	MaxConns    int  `json:"max_conns"`     // сколько последних соединений держать
	MaxBytesPer int  `json:"max_bytes_per"` // сколько байт писать на соединение (в каждую сторону)
}

func (d *DumpSpec) applyDefaults() {
	if d.MaxConns <= 0 {
		d.MaxConns = 50
	}
	if d.MaxBytesPer <= 0 {
		d.MaxBytesPer = 64 * 1024
	}
}

// RuleSpec — сериализуемая конфигурация одного проброса. Всё, что попадает
// в config.json, лежит здесь; рантайм-состояние живёт в Rule.
type RuleSpec struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Enabled    bool       `json:"enabled"`
	ListenHost string     `json:"listen_host"`
	ListenPort int        `json:"listen_port"`
	Target     Endpoint   `json:"target"`
	Backup     *Endpoint  `json:"backup,omitempty"`
	Health     HealthSpec `json:"health"`
	Dump       DumpSpec   `json:"dump"`

	// AllowCIDR — если непусто, принимаются только клиенты из этих подсетей.
	AllowCIDR []string `json:"allow_cidr,omitempty"`
	// MaxConns — предел одновременных соединений, 0 = без предела.
	MaxConns int `json:"max_conns"`
	// IdleTimeoutSec рвёт соединение, если в нём давно не было байт. 0 = никогда.
	IdleTimeoutSec int `json:"idle_timeout_sec"`
	// DialTimeoutMS — таймаут подключения к таргету.
	DialTimeoutMS int `json:"dial_timeout_ms"`
}

func (s *RuleSpec) applyDefaults() {
	if s.ListenHost == "" {
		s.ListenHost = "0.0.0.0"
	}
	if s.DialTimeoutMS <= 0 {
		s.DialTimeoutMS = 3000
	}
	s.Health.applyDefaults()
	s.Dump.applyDefaults()
}

// ListenAddr — адрес, который слушает правило.
func (s RuleSpec) ListenAddr() string {
	return net.JoinHostPort(s.ListenHost, strconv.Itoa(s.ListenPort))
}

// Validate проверяет спеку до того, как ей дадут поднять слушатель.
func (s *RuleSpec) Validate() error {
	if s.ListenPort < 1 || s.ListenPort > 65535 {
		return fmt.Errorf("порт прослушивания %d вне диапазона 1-65535", s.ListenPort)
	}
	if s.Target.IsZero() {
		return fmt.Errorf("не задан адрес назначения")
	}
	if s.Target.Port < 1 || s.Target.Port > 65535 {
		return fmt.Errorf("порт назначения %d вне диапазона 1-65535", s.Target.Port)
	}
	if s.ListenHost != "" {
		if ip := net.ParseIP(s.ListenHost); ip == nil {
			return fmt.Errorf("адрес прослушивания %q не является IP", s.ListenHost)
		}
	}
	if strings.TrimSpace(s.Target.Host) == "" {
		return fmt.Errorf("пустой хост назначения")
	}
	if s.Backup != nil && !s.Backup.IsZero() {
		if s.Backup.Port < 1 || s.Backup.Port > 65535 {
			return fmt.Errorf("порт резервного адреса %d вне диапазона 1-65535", s.Backup.Port)
		}
	}
	for _, c := range s.AllowCIDR {
		if _, _, err := net.ParseCIDR(c); err != nil {
			// Разрешаем и голый IP — превратим его в /32 при компиляции ACL.
			if net.ParseIP(c) == nil {
				return fmt.Errorf("некорректная подсеть в белом списке: %q", c)
			}
		}
	}
	return nil
}

// parseACL превращает список CIDR/IP в набор подсетей.
func parseACL(list []string) ([]*net.IPNet, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]*net.IPNet, 0, len(list))
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(item); err == nil {
			out = append(out, ipnet)
			continue
		}
		ip := net.ParseIP(item)
		if ip == nil {
			return nil, fmt.Errorf("некорректная запись %q", item)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}
