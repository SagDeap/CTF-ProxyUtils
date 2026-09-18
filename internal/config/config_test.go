package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
)

func TestSaveLoadAndOwnedRuleCopies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Web.Token = "roundtrip-test-token"
	backup := &proxy.Endpoint{Host: "127.0.0.2", Port: 8080}
	rules := []proxy.RuleSpec{{ID: "one", Name: "service", ListenPort: 7010, Target: proxy.Endpoint{Host: "127.0.0.1", Port: 8080}, Backup: backup, AllowCIDR: []string{"127.0.0.0/8"}}}
	if err := cfg.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	rules[0].Name = "mutated"
	backup.Host = "bad"
	rules[0].AllowCIDR[0] = "bad"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Web.Token != cfg.Web.Token || loaded.Rules[0].Name != "service" || loaded.Rules[0].Backup.Host != "127.0.0.2" || loaded.Rules[0].AllowCIDR[0] != "127.0.0.0/8" {
		t.Fatalf("saved config aliased caller state: %#v", loaded.Rules)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".config-*.tmp"))
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary files left: %v, %v", files, err)
	}
}

func TestConcurrentScanRuleAndDiskUpdates(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for n := 0; n < 12; n++ {
				var err error
				switch worker {
				case 0:
					err = cfg.SetScan(ScanDefaults{CIDR: "127.0.0.1", Ports: fmt.Sprint(n + 1), TimeoutMS: 100})
				case 1:
					err = cfg.SetRules([]proxy.RuleSpec{{ID: fmt.Sprint(n)}})
				case 2:
					err = cfg.Save()
				case 3:
					_ = cfg.ScanSnapshot()
				}
				if err != nil {
					t.Error(err)
				}
			}
		}(worker)
	}
	wg.Wait()
	loaded, err := Load(cfg.Path())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Scan.Ports != "12" || len(loaded.Rules) != 1 || loaded.Rules[0].ID != "11" {
		t.Fatalf("updates lost: %#v", loaded)
	}
}

func TestLoadRejectsBrokenConfigWithoutOverwriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	broken := []byte(`{"rules":`)
	if err := os.WriteFile(path, broken, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("broken config accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(broken) {
		t.Fatal("broken config was overwritten")
	}
}
