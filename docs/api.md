# REST API v1

Базовый путь: `/api/v1`. Старые маршруты `/api/*` для правил, сканера и состояния остаются алиасами в v1.0.

JSON-запросы требуют `Content-Type: application/json`. Токен передаётся одним из заголовков:

```text
X-Auth-Token: TOKEN
Authorization: Bearer TOKEN
```

`GET /api/v1/ping` и `POST /api/v1/login` доступны без авторизации. Ошибки возвращаются как `{ "error": "..." }`.

## Маршруты

| Метод | Путь | Действие |
|---|---|---|
| GET | `/ping` | версия, uptime и состояние авторизации |
| POST | `/login` | проверить `{ "token": "..." }` |
| GET | `/state` | снимок панели: правила, находки, события, метрики и скан |
| GET / POST | `/rules` | список / создать правило |
| GET / PUT / DELETE | `/rules/{id}` | прочитать / заменить / удалить правило |
| POST | `/rules/{id}/toggle` | `{ "enabled": true }` |
| POST | `/rules/{id}/switch` | `{ "mode": "auto|primary|backup" }` |
| POST | `/rules/{id}/reset` | сбросить счётчики |
| GET / DELETE | `/rules/{id}/dumps` | найти / очистить незакреплённые записи |
| GET | `/rules/{id}/dumps/{conn_id}` | полная запись; `chunks[].data` — base64 |
| POST | `/rules/{id}/dumps/{conn_id}/pin` | `{ "pinned": true }` |
| GET / PUT / POST | `/detectors` | конфигурация / заменить / добавить детектор |
| PUT / DELETE | `/detectors/{id}` | заменить / удалить детектор |
| GET / DELETE | `/findings` | найти / очистить находки |
| GET / POST | `/profile` | экспорт / dry-run или импорт профиля |
| GET / POST / DELETE | `/scan` | состояние / запуск / остановка скана |
| GET | `/interfaces` | сетевые интерфейсы и подсети |

Полная машиночитаемая схема: [OpenAPI 3.1](openapi.yaml).

## Создать TCP-проброс

```sh
curl http://127.0.0.1:8420/api/v1/rules \
  -H 'X-Auth-Token: TOKEN' -H 'Content-Type: application/json' \
  -d '{
    "name":"service",
    "enabled":true,
    "protocol":"tcp",
    "listen_port":7010,
    "target":{"host":"192.168.0.5","port":7010},
    "inspect":{"enabled":true,"auto_pin":true},
    "dump":{"enabled":true}
  }'
```

## Поиск трафика

`GET /rules/{id}/dumps?summary=1` возвращает `{ "items": [...], "total": N }`.

| Параметр | Значения |
|---|---|
| `q` | строка поиска |
| `mode` | `text`, `hex`, `regex` |
| `dir` | `any`, `in`, `out` |
| `remote` | подстрока адреса клиента |
| `from`, `to` | RFC 3339 |
| `pinned` | `1` — только закреплённые |
| `offset`, `limit` | страница, максимум 500 записей |

Поиск идёт по сохранённому потоку каждого направления отдельно.

## Находки

```sh
curl 'http://127.0.0.1:8420/api/v1/findings?min_score=60&limit=100' \
  -H 'X-Auth-Token: TOKEN'
```

Фильтры: `q`, `rule_id`, `min_score`, `limit` (до 1000). Ответ содержит `items`, `total` и число событий, отброшенных при заполненной очереди.

## Импорт профиля

Сначала отправь тот же запрос с `dry_run: true`, затем примени с `false`:

```json
{
  "profile": { "schema_version": 1, "scan": {}, "detection": {}, "rules": [] },
  "mode": "merge",
  "dry_run": true
}
```

`merge` добавляет и обновляет правила по ID. `replace` удаляет правила, которых нет в профиле.
