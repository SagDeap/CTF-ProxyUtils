package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/SagDeap/CTF-ProxyUtils/internal/config"
	"github.com/SagDeap/CTF-ProxyUtils/internal/proxy"
	"github.com/SagDeap/CTF-ProxyUtils/internal/scan"
	"github.com/SagDeap/CTF-ProxyUtils/internal/web"
)

var version = "0.2.0"

func main() {
	var (
		cfgPath = flag.String("config", defaultConfigPath(), "путь к файлу конфигурации")
		addr    = flag.String("addr", "", "адрес панели управления (по умолчанию 127.0.0.1:8420)")
		bindAll = flag.Bool("bind-all", false, "слушать панель на всех интерфейсах (0.0.0.0)")
		token   = flag.String("token", "", "задать токен доступа явно")
		noAuth  = flag.Bool("no-auth", false, "отключить авторизацию (только для доверенной сети!)")
		showVer = flag.Bool("version", false, "показать версию и выйти")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("ctf-proxyutils %s\n", version)
		return
	}

	log.SetFlags(log.Ltime)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("конфигурация: %v", err)
	}

	// Токен: явный флаг > сохранённый > свежесгенерированный.
	freshToken := false
	switch {
	case *noAuth:
		cfg.Web.Token = ""
	case *token != "":
		cfg.Web.Token = *token
	case cfg.Web.Token == "":
		t, err := config.GenerateToken()
		if err != nil {
			log.Fatalf("не удалось сгенерировать токен: %v", err)
		}
		cfg.Web.Token = t
		freshToken = true
	}

	if *addr != "" {
		cfg.Web.Addr = *addr
	}
	if *bindAll {
		_, port, err := net.SplitHostPort(cfg.Web.Addr)
		if err != nil {
			log.Fatalf("некорректный адрес панели %q: %v", cfg.Web.Addr, err)
		}
		cfg.Web.Addr = net.JoinHostPort("0.0.0.0", port)
	}

	mgr := proxy.NewManager()
	scanner := scan.NewScanner()

	// Любое изменение правил сразу уходит на диск: если утилиту прибьют,
	// пробросы поднимутся заново в том же виде.
	mgr.SetOnChange(func() {
		if err := cfg.SetRules(mgr.Specs()); err != nil {
			log.Printf("не удалось сохранить конфиг: %v", err)
		}
	})

	if errs := mgr.LoadSpecs(cfg.Rules); len(errs) > 0 {
		for _, e := range errs {
			log.Printf("при загрузке правил: %v", e)
		}
	}
	if n := len(mgr.List()); n > 0 {
		log.Printf("загружено правил: %d", n)
	}

	if err := cfg.Save(); err != nil {
		log.Printf("не удалось сохранить конфиг: %v", err)
	}

	srv := web.NewServer(cfg, mgr, scanner, version)
	defer srv.Close()
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}

	ln, err := net.Listen("tcp", cfg.Web.Addr)
	if err != nil {
		log.Fatalf("не удалось занять %s: %v", cfg.Web.Addr, err)
	}

	printBanner(cfg, freshToken, *noAuth)

	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("панель управления упала: %v", err)
		}
	}()

	// Ждём Ctrl+C, затем гасим всё аккуратно.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Println("останавливаюсь…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)
	scanner.Stop()
	mgr.StopAll()
	log.Println("все пробросы остановлены")
}

func printBanner(cfg *config.Config, freshToken, noAuth bool) {
	host, port, _ := net.SplitHostPort(cfg.Web.Addr)
	display := host
	if host == "0.0.0.0" || host == "" {
		display = firstLocalIP()
	}
	url := fmt.Sprintf("http://%s:%s", display, port)

	fmt.Println()
	fmt.Println("  CTF-ProxyUtils " + version)
	fmt.Println("  " + strings.Repeat("─", 46))
	fmt.Printf("  панель:  %s\n", url)
	if noAuth || cfg.Web.Token == "" {
		fmt.Println("  токен:   отключён (-no-auth)")
		if host == "0.0.0.0" {
			fmt.Println("  ВНИМАНИЕ: панель открыта всем без пароля")
		}
	} else {
		fmt.Printf("  токен:   %s\n", cfg.Web.Token)
		fmt.Printf("  ссылка:  %s/#token=%s\n", url, cfg.Web.Token)
		if freshToken {
			fmt.Printf("  (сохранён в %s)\n", cfg.Path())
		}
	}
	fmt.Println("  " + strings.Repeat("─", 46))
	fmt.Println()
}

// firstLocalIP подбирает адрес, по которому панель реально откроют с ноутбука.
func firstLocalIP() string {
	for _, ifi := range scan.Interfaces() {
		if ifi.Suggested {
			return ifi.IP
		}
	}
	return "127.0.0.1"
}

// defaultConfigPath кладёт конфиг рядом с бинарником — так утилита остаётся
// самодостаточной: скопировал файл на виртуалку, запустил, всё рядом.
func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(filepath.Dir(exe), "config.json")
}
