package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
)

// WebConfig — настройки панели управления.
type WebConfig struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

// ScanDefaults — что подставлять в форму скана при открытии.
type ScanDefaults struct {
	CIDR        string `json:"cidr"`
	Ports       string `json:"ports"`
	TimeoutMS   int    `json:"timeout_ms"`
	Concurrency int    `json:"concurrency"`
	Fingerprint bool   `json:"fingerprint"`
}

// Config — всё, что переживает перезапуск.
type Config struct {
	Web   WebConfig        `json:"web"`
	Scan  ScanDefaults     `json:"scan"`
	Rules []proxy.RuleSpec `json:"rules"`

	path string
	mu   sync.Mutex
}

// Default — конфигурация чистой установки. Панель слушает только localhost:
// на боевой машине с публичным адресом открытая наружу панель управления
// пробросами — это подарок соперникам.
func Default() *Config {
	return &Config{
		Web: WebConfig{Addr: "127.0.0.1:8420"},
		Scan: ScanDefaults{
			Ports:       "",
			TimeoutMS:   500,
			Concurrency: 256,
			Fingerprint: true,
		},
	}
}

// GenerateToken создаёт случайный токен доступа к панели.
func GenerateToken() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Load читает конфиг. Отсутствующий файл — не ошибка: это первый запуск,
// возвращаем значения по умолчанию.
func Load(path string) (*Config, error) {
	cfg := Default()
	cfg.path = path

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("не удалось прочитать %s: %w", path, err)
	}
	if len(data) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("битый конфиг %s: %w", path, err)
	}
	if cfg.Web.Addr == "" {
		cfg.Web.Addr = Default().Web.Addr
	}
	cfg.path = path
	return cfg, nil
}

func (c *Config) Path() string { return c.path }

// SetRules подменяет набор правил и сохраняет конфиг.
func (c *Config) SetRules(rules []proxy.RuleSpec) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Rules = make([]proxy.RuleSpec, len(rules))
	for i, rule := range rules {
		c.Rules[i] = rule
		c.Rules[i].AllowCIDR = append([]string(nil), rule.AllowCIDR...)
		if rule.Backup != nil {
			backup := *rule.Backup
			c.Rules[i].Backup = &backup
		}
	}
	return c.saveLocked()
}

func (c *Config) ScanSnapshot() ScanDefaults {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Scan
}

func (c *Config) SetScan(scan ScanDefaults) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Scan = scan
	return c.saveLocked()
}

// Save пишет конфиг атомарно: сначала во временный файл рядом, потом rename.
// Прерванная запись не оставит обрубок вместо рабочей конфигурации.
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

func (c *Config) saveLocked() error {
	if c.path == "" {
		return nil // конфиг не привязан к файлу — работаем только в памяти
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op, если rename уже прошёл

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil { // в файле лежит токен доступа
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, c.path)
}
