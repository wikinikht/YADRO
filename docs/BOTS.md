# Выбор маршрута для бота: aiogram / Telethon / Pyrogram / другие языки

Коротко: **важен не язык, а слой API. MTProto-клиенты (Telethon,
Pyrogram, GramJS, gotd, TDLib…) работают через туннель на любом
языке. Bot API (aiogram, python-telegram-bot, telegraf, go-telegram-
bot-api, Telegram.Bot) — это HTTPS к `api.telegram.org`, через
MTProto WS-туннель он не идёт НИ НА ОДНОМ языке — для него нужны
другие решения.**

## Дерево решений

```
Ваш бот ...
├── Telethon (MTProto)
│     → MTProto-фронтенд: proxy=('mtproto','127.0.0.1',1443,secret)
│       или SOCKS5-мост (в т.ч. plain-транспорт по умолчанию)  ✅ РЕШЕНО
├── Pyrogram / kurigram (MTProto)
│     → SOCKS5-мост: socks5://127.0.0.1:1080                   ✅ РЕШЕНО
├── aiogram / python-telegram-bot (Bot API, HTTPS)
│     → CF Worker-зеркало api.telegram.org на своём домене      🟡 (внешний CF)
│     → или оставить HTTPS-релей на зарубежном VPS (как сейчас) 🟡
│     → или перевести бота на Telethon/Pyrogram                ✅ тогда РЕШЕНО
└── несколько ботов/микс
      → поднять tgws-server + CF Worker рядом; секрет на каждого
```

Почему Bot API не проходит туннель: tg-ws-proxy туннелирует
**MTProto** (транспорт клиент↔DC). Запросы aiogram — обычный HTTPS к
`api.telegram.org`, для которого в веб-шлюзе (WebSocket /apiws) просто
нет «языка». Это ограничение протокола Telegram, а не форка — и не
языка: aiogram на Python не работает точно так же, как telegraf на JS.

## Другие языки (JS, Go, C#, Java, Rust…)

Сервер — это обычный TCP: MTProto-фронтенд (секрет, порт 1443) и
SOCKS5-мост (порт 1080, без аутентификации). Подключаться можно из
любого языка, где есть MTProto-библиотека:

| Язык | MTProto-библиотека | Как подключить | Статус |
|---|---|---|---|
| Python | Telethon | `('mtproto',…)` или `('socks5',…)` | ✅ golden-тест |
| Python | Pyrogram/kurigram | `socks5://127.0.0.1:1080` | ✅ golden-тест |
| JS/TS | GramJS (архивир.) / teleproto | SOCKS5 через опцию `proxy`; MTProxy-режим — сверяйте версию | 🟡 по докам |
| Go | gotd/td | встроен MTProxy-режим; либо SOCKS5 через свой `DialFunc` | 🟡 по докам |
| C# | WTelegramClient | встроенные `Proxy` (MTProxy и socks5/http) | 🟡 по докам |
| Java/Kotlin | TDLib (TDLight Java) | `addProxy(proxyTypeSocks5)` — официальное API | 🟡 по докам |
| C++/Swift/etc | TDLib (официальная) | `addProxy` типа socks5 | 🟡 по докам |
| Rust | grammers | прокси из коробки нет — через `proxychains4` + SOCKS5-мост | 🟡 обходной |

Пояснения:

- ✅ проверено реальным `connect()` с полным MTProto-хендшейком
  ([../scripts/golden_connect.py](../scripts/golden_connect.py));
  🟡 — по документации библиотеки, наш golden-тест их не гоняет.
- **Универсальный обходной путь**: любая MTProto-библиотека без
  поддержки прокси работает через `proxychains4` + SOCKS5-мост —
  мосту всё равно, кто делает TCP-подключение, главное чтобы после
  CONNECT пошёл MTProto-транспорт.
- Даже без кода: обычные клиенты Telegram (телефон/десктоп) и
  большинство MTProto-библиотек принимают `tg://proxy?…`-ссылку
  (`tgws-server links`) — секрет настраивается на стороне клиента.
- SOCKS5-мост слушает `127.0.0.1` — бот должен быть на том же хосте
  (или SSH-туннель/открытый порт с файрволом, аутентификации нет!).

### Bot API на любом языке

Для Bot API-ботов (telegraf, grammy, node-telegram-bot-api, go-telegram-
bot-api, Telegram.Bot и т.д.) решение такое же, как для aiogram, и тоже
не зависит от языка бота: CF Worker-зеркало
([../examples/cf-worker/api-mirror.js](../examples/cf-worker/api-mirror.js))
или зарубежный релей, а в боте меняется только base URL — во всех
перечисленных библиотеках это одна опция/строка
(`apiBase`, `basePath`, `base_url`…).

## Telethon

```python
from telethon import TelegramClient

# маршрут A: нативный MTProto-прокси (рекомендуется)
secret = 'ee<32hex><домен-hex>'   # из `tgws-server links` (с префиксом ee/dd!)
proxy = ('mtproto', '127.0.0.1', 1443, secret)
client = TelegramClient('bot', API_ID, API_HASH, proxy=proxy)

# маршрут B: SOCKS5-мост
proxy = ('socks5', '127.0.0.1', 1080)
client = TelegramClient('bot', API_ID, API_HASH, proxy=proxy)
```

Полный рабочий файл: [../examples/bot_telethon.py](../examples/bot_telethon.py).

Замечания:
- dd-секреты Telethon проводит через RandomizedIntermediate
  автоматически; ee-секреты — через abridged MTProxy-режим.
- Проверка туннеля без токена: `client.connect()` уже делает полный
  хендшейк. Готовый скрипт: [../scripts/golden_connect.py](../scripts/golden_connect.py).

## Pyrogram / kurigram

```bash
pip install "kurigram[socks]" tgcrypto
```

```python
from pyrogram import Client

app = Client(
    'bot', api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN,
    proxies={'scheme': 'socks5', 'hostname': '127.0.0.1', 'port': 1080},
)
```

Pyrogram всегда обфусцирует транспорт — мост распознаёт это
автоматически. DC подставляется из цели CONNECT, ничего указывать не
нужно. Полный файл: [../examples/bot_pyrogram.py](../examples/bot_pyrogram.py).

## aiogram / python-telegram-bot (Bot API, Python)

Варианты — те же для Bot API-библиотек на любом языке, отсортированы
по «сколько инфраструктуры останется у РФ-VPS»:

1. **Перевести бота на Telethon/Pyrogram** — тогда всё работает локально.
   Для типового бота (respond + рассылки) это ~50 строк разницы.
2. **CF Worker-зеркало Bot API** (остаётся Cloudflare, но не «ваш
   зарубежный VPS»; free-плана хватает):
   - задеплоить [../examples/cf-worker/api-mirror.js](../examples/cf-worker/api-mirror.js)
     на свой домен за Cloudflare (`workers.dev` из РФ ненадёжен);
   - в aiogram 3.x: `Bot(token, base="https://api.ваш-домен")`.
   Webhook'и тоже идут через зеркало (`setWebhook` вернёт ваш URL).
3. **Оставить текущий зарубежный релей** только для HTTPS Bot API —
   MTProto-боты при этом уже могут ходить напрямую через туннель,
   снижая нагрузку на релей.

Локальный `telegram-bot-api` (open-source сервер Bot API) не спасает:
он сам ходит MTProto к DC, но не умеет подключаться через прокси без
форка tdlib — потому и предложены варианты выше.

## Несколько ботов на одном сервере

- каждому боту — свой секрет (или общий SOCKS5-мост, там секретов не
  требуется вовсе);
- лимиты Telegram считаются на api_id/токен, туннель на них не влияет;
- 1 ядро / 512 МБ спокойно держит десятки сессий: узкое место — сеть.
