# CTF-ProxyUtils

[![Релиз](https://img.shields.io/github/v/release/SagDeap/CTF-ProxyUtils)](https://github.com/SagDeap/CTF-ProxyUtils/releases/latest)
[![Проверки](https://github.com/SagDeap/CTF-ProxyUtils/actions/workflows/ci.yml/badge.svg)](https://github.com/SagDeap/CTF-ProxyUtils/actions/workflows/ci.yml)

TCP/UDP-прокси для Attack/Defense CTF. Переносит сервис с vulnbox, переключает резерв, записывает трафик и отмечает подозрительные запросы. Веб-панель встроена в один бинарник.

![Поток трафика и управления](docs/network.svg)

## Быстрый запуск

```sh
curl -LO https://github.com/SagDeap/CTF-ProxyUtils/releases/latest/download/ctf-proxyutils-linux-amd64
chmod +x ctf-proxyutils-linux-amd64
./ctf-proxyutils-linux-amd64
```

Программа выведет ссылку с токеном. Панель слушает `127.0.0.1:8420`; открой её через SSH-туннель:

```sh
ssh -L 8420:127.0.0.1:8420 user@vulnbox
```

В панели выбери **Сканер → порт → Пробросить** или создай правило вручную. Конфигурация сохраняется в `config.json` рядом с бинарником.

## Что есть в v1.0

- TCP и UDP-пробросы, ACL, лимиты соединений и таймауты.
- Основной и резервный адрес с ручным или автоматическим переключением.
- TCP, payload и HTTP health-check: метод, путь, Host, заголовки, тело, статус и шаблон ответа.
- Анализ трафика по text/hex/regex, области HTTP и направлению; встроенные сигналы автоматизации, traversal, injection и всплеска соединений.
- Оценка риска с объяснением, маскированием чувствительных совпадений и автозакреплением записи.
- Поиск по записанному трафику, закрепление, JSON-экспорт, журнал и графики.
- Импорт/экспорт профилей без токена панели; предварительная проверка до применения.
- Версионированный REST API `/api/v1`.

![Как формируется оценка риска](docs/detection-pipeline.svg)

## Параметры

| Флаг | Назначение |
|---|---|
| `-addr IP:8420` | адрес панели |
| `-bind-all` | открыть панель на всех интерфейсах |
| `-token TOKEN` | задать токен |
| `-config PATH` | выбрать файл конфигурации |
| `-no-auth` | отключить авторизацию |
| `-version` | вывести версию |

Для портов ниже 1024 на Linux:

```sh
sudo setcap 'cap_net_bind_service=+ep' ./ctf-proxyutils-linux-amd64
```

## Документация

- [Начало работы](docs/getting-started.md)
- [Анализ трафика и детекторы](docs/traffic-analysis.md)
- [Health-check и failover](docs/health-checks.md)
- [UDP-пробросы](docs/udp-forwarding.md)
- [Профили](docs/profiles.md)
- [REST API](docs/api.md) и [OpenAPI 3.1](docs/openapi.yaml)

Трафик, находки, закрепления, журнал и графики находятся в памяти до перезапуска. TLS остаётся зашифрованным. Профили не синхронизируют состояние сервиса между основным и резервным адресом.

## Разработка

```sh
go test ./...
go test -race ./...
go vet ./...
node --test internal/web/static/*.test.js
make dist VERSION=v1.0.0
```

Релизы собираются для Linux, macOS и Windows. Лицензия: [MIT](LICENSE).
