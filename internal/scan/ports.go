package scan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// DefaultPorts — то, что имеет смысл искать на машинах команды.
// Верхний диапазон — типичные порты сервисов на A/D-соревнованиях,
// нижний — стандартные службы, по которым опознаётся сама машина.
var DefaultPorts = []int{
	22, 80, 443, 445, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8081, 8443, 9000,
	5555, 27017,
}

// CTFPortRange — диапазон, в который чаще всего попадают сервисы на A/D.
const CTFPortRange = "3000-3010,5000-5010,7000-7020,8000-8010,9000-9010"

// ParsePorts разбирает список вида "22,80,7000-7100" в набор портов.
func ParsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		out := make([]int, len(DefaultPorts))
		copy(out, DefaultPorts)
		sort.Ints(out)
		return out, nil
	}

	seen := make(map[int]bool)
	var out []int
	add := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("порт %d вне диапазона 1-65535", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
		return nil
	}

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "-"); i > 0 {
			lo, err := strconv.Atoi(strings.TrimSpace(part[:i]))
			if err != nil {
				return nil, fmt.Errorf("некорректный диапазон %q", part)
			}
			hi, err := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if err != nil {
				return nil, fmt.Errorf("некорректный диапазон %q", part)
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			if hi-lo > 10000 {
				return nil, fmt.Errorf("диапазон %q слишком широкий (максимум 10000 портов)", part)
			}
			for p := lo; p <= hi; p++ {
				if err := add(p); err != nil {
					return nil, err
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("некорректный порт %q", part)
		}
		if err := add(p); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("не указано ни одного порта")
	}
	sort.Ints(out)
	return out, nil
}
