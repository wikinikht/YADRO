# YADRO

Серверный форк [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy):
MTProto-прокси, который туннелирует трафик Telegram через TLS/WebSocket
к доменам веб-версии (`kws2/kws4.web.telegram.org`). Пара «IP + SNI»
держится в белых списках ТСПУ, полезная нагрузка остаётся зашифрованным
MTProto. Сторонний relay не нужен.

Форк превращает десктопный плагин в **демон для VPS**: бот на Python
(Telethon / Pyrogram) ходит в Telegram из РФ без зарубежного прокси.
В дереве также лежит прототип ядра на Rust (`rust/`).

> Для своих ботов и клиентов. За использование отвечаете вы.

Репозиторий: [github.com/wikinikht/YADRO](https://github.com/wikinikht/YADRO)

---

## Что добавлено относительно апстрима

| Фича | Апстрим | YADRO |
|---|---|---|
| MTProto-фронтенд → WS-туннель | ✅ | ✅ |
| **Мульти-секреты на одном порту** | ❌ | ✅ |
| **Генератор конфига** (`tgws-server gen`) | ❌ | ✅ |
| **SOCKS5-мост** для Telethon/Pyrogram | ❌ | ✅ `socks5://127.0.0.1:1080` |
| **`tgws-server doctor` / `diagnose`** | ❌ | ✅ |
| Headless / systemd / **Docker** | частично | ✅ |
| Rust-прототип ядра | ❌ | ✅ `rust/` |

Диффы против апстрима: [docs/CHANGES.md](docs/CHANGES.md).

---

## Docker (предпочтительный запуск на VPS)

```bash
git clone https://github.com/wikinikht/YADRO.git
cd YADRO
cp .env.example .env
# впишите в .env два секрета по 32 hex:  openssl rand -hex 16

docker compose up -d --build
docker compose logs -f tgws
# в логе будет tg://proxy?... — его в Telegram Desktop / бота
```

Порты с хоста по умолчанию только на loopback: `127.0.0.1:1443` (MTProto)
и `127.0.0.1:1080` (SOCKS5). Если бот в том же compose-network, проброс
на хост не нужен — контейнер бота ходит на `tgws:1443` / `tgws:1080`.

Переменные: см. `.env.example` и [docs/DEPLOY.md](docs/DEPLOY.md).

---

## Быстрый старт без Docker (Debian/Ubuntu)

```bash
git clone https://github.com/wikinikht/YADRO.git && cd YADRO

# вариант 1 — скрипт (venv + пользователь + systemd + конфиг)
sudo bash deploy/install.sh

# вариант 2 — руками
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
tgws-server gen                      # YAML с секретами
tgws-server doctor                   # WS-шлюз, DNS, порты
tgws-server links                    # tg:// + сниппеты для ботов
sudo tgws-server systemd > /etc/systemd/system/tgws-server.service
sudo systemctl enable --now tgws-server

tgws-server diagnose --full
```

## Подключение бота

| Библиотека | Маршрут | Пример |
|---|---|---|
| **Telethon** | MTProto (`('mtproto', '127.0.0.1', 1443, secret)`) | [examples/bot_telethon.py](examples/bot_telethon.py) |
| **Pyrogram / kurigram** | SOCKS5 (`socks5://127.0.0.1:1080`) | [examples/bot_pyrogram.py](examples/bot_pyrogram.py) |
| **aiogram / python-telegram-bot** | ⚠️ Bot API — HTTPS, не MTProto; нужен CF Worker | [examples/cf-worker/api-mirror.js](examples/cf-worker/api-mirror.js), [docs/BOTS.md](docs/BOTS.md) |

Проверка туннеля без учёток: [scripts/golden_connect.py](scripts/golden_connect.py).

## Документация

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — протокол и ТСПУ
- [docs/DEPLOY.md](docs/DEPLOY.md) — Debian/Ubuntu и Docker
- [docs/BOTS.md](docs/BOTS.md) — Telethon / Pyrogram / aiogram
- [docs/TESTING.md](docs/TESTING.md) — doctor, golden, e2e
- [docs/RUST_C.md](docs/RUST_C.md) — Python / Rust
- [docs/CHANGES.md](docs/CHANGES.md) — дифф против апстрима
- Апстрим (tray/Windows/macOS/CF) — [docs/README.md](docs/README.md)

## Структура

```
proxy/        ядро (апстрим + мульти-секреты, [fork])
server/       cli, runner, generator, SOCKS5, doctor, diagnose
tests/        unit + live e2e (TGWS_LIVE=1)
scripts/      golden_connect.py
deploy/       systemd + install.sh
examples/     боты и CF Worker
rust/         прототип ядра
```

## Лицензия

MIT, как апстрим. Протокол — © [Flowseal](https://github.com/Flowseal)
и контрибьюторы tg-ws-proxy; серверный слой — этот форк.
