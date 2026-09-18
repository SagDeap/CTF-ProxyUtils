# API

Базовый адрес: `http://127.0.0.1:8420`. JSON-запросы требуют
`Content-Type: application/json`. Передавай токен в `X-Auth-Token` или
`Authorization: Bearer TOKEN`. Cookie не принимаются.

| Метод | Путь | Действие |
|---|---|---|
| GET | `/api/ping` | Версия и состояние авторизации, без токена |
| POST | `/api/login` | Проверка `{ "token": "..." }`, без создания cookie |
| GET | `/api/state` | Правила, скан, события, графики и настройки |
| GET / POST | `/api/rules` | Список / создание правила |
| GET / PUT / DELETE | `/api/rules/{id}` | Чтение / замена / удаление правила |
| POST | `/api/rules/{id}/toggle` | `{ "enabled": true }` |
| POST | `/api/rules/{id}/switch` | `{ "mode": "auto" }`, также `primary` / `backup` |
| POST | `/api/rules/{id}/reset` | Сброс счётчиков |
| GET | `/api/rules/{id}/dumps?summary=1` | Поиск и страницы метаданных |
| GET | `/api/rules/{id}/dumps/{conn_id}` | Полная запись; `chunks[].data` в base64 |
| POST | `/api/rules/{id}/dumps/{conn_id}/pin` | `{ "pinned": true }` |
| DELETE | `/api/rules/{id}/dumps` | Очистка незакреплённого трафика |
| GET / POST / DELETE | `/api/scan` | Состояние / запуск / остановка скана |
| GET | `/api/interfaces` | Интерфейсы и подсети |

## Создание проброса

```sh
curl http://127.0.0.1:8420/api/rules \
  -H 'X-Auth-Token: TOKEN' -H 'Content-Type: application/json' \
  -d '{"name":"service","enabled":true,"listen_port":7010,
       "target":{"host":"192.168.0.5","port":7010},
       "dump":{"enabled":true}}'
```

## Поиск трафика

`GET /api/rules/{id}/dumps?summary=1` возвращает `{ "items": [...], "total": N }`.
Параметры передаются с URL-кодированием:

| Параметр | Значения |
|---|---|
| `q` | Строка поиска |
| `mode` | `text`, `hex`, `regex` |
| `dir` | `any`, `in` (к сервису), `out` (от сервиса) |
| `remote` | Подстрока адреса клиента |
| `from`, `to` | Время начала соединения в RFC 3339 |
| `pinned` | `1` — только закреплённые |
| `offset`, `limit` | Смещение и размер страницы |

Поиск проверяет сохранённый поток каждого направления целиком. Два направления
не склеиваются; отсутствующие из-за лимита байты не участвуют в поиске.
Без `summary=1` эндпоинт возвращает полный список записей для совместимости.

В `/api/state` массив `events` идёт от новых событий к старым, `metrics` —
по времени. Метрики: `bytes_in_per_sec`, `bytes_out_per_sec`,
`connections_per_sec`, `failed_per_sec`, `active_conns`.
