# Тестирование: как убедиться, что всё работает

Пирамида проверок: **unit → golden → doctor → живой бот**.

## 1. Unit-тесты (без сети)

```bash
pip install -e . pytest
python -m pytest tests/ -q --ignore=tests/test_live_e2e.py
```

Покрывают: мульти-секреты (хендшейк для каждого секрета), SOCKS5-мост
(парсинг self-obfuscated-init, plain-транспортов, крипто-круговые
тесты), генератор/загрузчик конфигов, и весь тестовый набора апстрима
(fake TLS, пулы, h2, msgsplitter и т.д.).

## 2. Golden-тест — настоящий Telethon (нужна сеть, не нужны учётки)

```bash
pip install -e ".[golden]"
python scripts/golden_connect.py
```

Поднимает туннель в процессе и делает **три** полных MTProto-хендшейка
(req_pq → resPQ → DH) реальным Telethon:

```
mtproto-proxy frontend (dd):        OK in 2.6s
socks5 bridge (abridged):           OK in 0.6s
socks5 bridge (obfuscated):         OK in 2.3s
```

Если все три OK — туннель переносит настоящий трафик Telegram.
Именно этот скрипт прогоняйте первым на новом VPS.
В CI он запускается как `tests/test_live_e2e.py` c `TGWS_LIVE=1`.

## 3. `tgws-server doctor` — диагностика хоста

```bash
tgws-server doctor -c /etc/tgws-server/tgws-server.yaml
```

Что проверяет и как читать:

| Проверка | OK означает | FAIL/WARN означает |
|---|---|---|
| конфиг/секреты | валидны | опечатка в 32-hex |
| порты 1443/1080 | слушаются | сервис не запущен (WARN до старта) |
| DNS kws2/kws4 | резолвятся | «unexpected IP» = возможна подмена DNS (не фатально — IP пинуется из конфига) |
| **WS gateway … via 149.154.167.220** | **TLS+Upgrade → 101: белый список работает с этого хоста** | timeout — ТСПУ режет и этот маршрут с вашего AS (см. ниже); 302 — шлюз редиректит (прокси обработает) |
| Direct MTProto TCP | DC доступен напрямую | внутри РФ ожидаемо blocked (WARN, не ошибка) |
| лог-файл | пишется | права/путь |

Коды выхода: 0 — всё ок, 2 — работает с предупреждениями, 1 — критично.

### Что делать, если doctor красный (WS gateway timeout)

1. `curl -v --resolve kws2.web.telegram.org:443:149.154.167.220
   https://kws2.web.telegram.org/apiws` — если и это висит, хостинговая
   сеть блокирует пиновый IP: попробовать другой VPS/провайдера.
2. Включить CF-фолбэки: `cf_worker_domains: [<свой worker>]` — трафик
   пойдёт через Cloudflare (см. upstream docs/CfWorker.md).
3. Проверить локальный firewall: исходящий 443 не резан?
4. Поменять `dc_ips` местами (только DC4): `4:149.154.167.220`.

## 4. `tgws-server diagnose` — полная диагностика (когда что-то не работает)

`doctor` — быстрый Smoke-тест. Если он красный, или бот отваливается
без понятной причины, запускайте расширенный набор — он проверяет
~35 пунктов в 7 группах и в конце печатает «ВЕРОЯТНЫЕ ПРИЧИНЫ»
с доказательствами и рецептом:

```bash
tgws-server diagnose -c /etc/tgws-server/tgws-server.yaml
```

| Группа | Что проверяет |
|---|---|
| **ENV** | версия python, root/не root, диск, nofile-лимит, UTF-8 |
| **DEPS** | pyyaml, cryptography, импорты ядра (упавшее окружение) |
| **CONFIG** | файл/секреты (в т.ч. слабые и дубликаты), пиннинг dc_ips, открытый наружу SOCKS5, права 600, маска FakeTLS, запись лога |
| **CRYPTO** | офлайн-самопроверка всего конвейера: AES-CTR, парсинг obfuscated-init, полная перекодировка моста (4 потока), рамки abridged |
| **NETWORK** | DNS (+подмена), TCP:443 до пинового IP, **WS-шлюз 101 по пиновому IP и по DNS**, прямой MTProto, api.telegram.org |
| **SOCKS5** | порты; с `--full` — сквозной прогон: синтетический MTProto-клиент через фронтенд и через мост до реального WS-шлюза (стек поднимается сам, если не запущен) |
| **RUNTIME** | systemd-юнит и его состояние, контейнер, **скан хвоста лога** (Traceback/ERROR/bad handshake/WS pool) |

### Режимы

```bash
tgws-server diagnose --offline          # без сети (CI, песочница)
tgws-server diagnose --full             # + сквозные e2e-пробы через живой стек
tgws-server diagnose --group NETWORK    # только одна группа
tgws-server diagnose --json rep.json --report rep.md   # отчёты
```

Коды выхода те же: 0 / 2 / 1. `--report rep.md` удобно приложить к issue.

### Как читать «ВЕРОЯТНЫЕ ПРИЧИНЫ»

Движок сопоставляет комбинации отказов с диагнозом, например:

| Сигнатура | Диагноз |
|---|---|
| TCP 443 FAIL + WS FAIL | исходящий 443 закрыт файрволом/хостером — открыть egress или сменить хостинг |
| TCP OK, WS 4xx | TSPU/шлюз режет SNI-путь: обновить форк, включить `cfproxy_domains` |
| TCP OK, WS timeout | маршрут пинового IP деградировал: другой IP `149.154.167.x`, CF-фолбэк, смена IP |
| DNS kws → чужие IP | подмена DNS (не фатально: IP пиннится из `dc_ips`) |
| мост не слушает | сервис не запущен/упал: `tgws-server run`, смотреть лог-скан |
| CRYPTO FAIL | сломано окружение: `pip install -e . --force-reinstall` |

Пример: у «красного» doctor-а видно только `WS gateway timeout`, а diagnose
покажет, что TCP открыт, CRYPTO зелёный, а в логе — `WS pool empty`,
т.е. виновата сеть, а не конфиг: рецепт — CF-фолбэк или другой IP.

## 5. Живой бот

```bash
python examples/bot_telethon.py    # с вашими API_ID/API_HASH/BOT_TOKEN
# в другом терминале: /ping в чате с ботом
```

Симптомы и где смотреть:

```bash
journalctl -u tgws-server -f       # handshake ok / WS pool hit / fallback
tgws-server doctor                 # быстрая повторная диагностика
tgws-server diagnose --full        # полный разбор с «вероятными причинами»
```

Полезные логи апстрима: `handshake ok: DC2 proto=0xEFEFEFEF` — клиент
принят; `DC2 -> WS pool hit` — туннель работает; `fallback` — WS-шлюз
недоступен и включился резерв.

## 6. Нагрузочная прикидка

Один процесс asyncio держит сотни одновременных сессий (ограничение —
сеть и лимиты открытых файлов: в юните `LimitNOFILE=65536`).

```bash
ss -tn state established '( dport = :443 )' | wc -l   # WS-сессии
```
