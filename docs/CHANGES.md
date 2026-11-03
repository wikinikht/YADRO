# Отличия форка от апстрима (для мержа обновлений)

Форк держит изменения максимально изолированными. Всё, что помечено
`[fork]` в коде, — наше; остальное — апстрим.

## Изменённые файлы апстрима (2 файла)

### `proxy/config.py`
- `ProxyConfig`: добавлено поле `extra_secrets: List[str]` и свойство
  `secrets_list` (нормализация: нижний регистр, дедуп, валидные 32-hex).

### `proxy/tg_ws_proxy.py`
- `_read_client_init(...)`: принимает список секретов; в FakeTLS-ветке
  перебирает `verify_client_hello` по каждому секрету и возвращает
  matched secret 5-м элементом (для совместимости с тестами апстрима
  допускается и старый 4-кортеж).
- `_handle_client(...)`: принимает список секретов (или один `bytes` —
  как раньше), перебирает `_try_handshake` до первого совпадения.
- `_run()`: список `secrets_bytes`, лог «Secrets: N», генерация
  tg://-ссылки по каждому секрету (`_links()`).
- `main()`: `--secret` стал repeatable (action='append'), добавлен
  `--secrets-file` (строки/комментарии).

Обратная совместимость: старые вызовы `_handle_client(r, w, secret_bytes)`
и моки `_read_client_init` с 4-кортежем продолжают работать — тесты
апстрима проходят без правок (кроме окружения `test_linux_update`, которое
и на чистом апстриме зависит от pkexec/дисплея).

## Новые файлы

```
server/                    серверный пакет
├── cli.py                 tgws-server: gen/run/links/secret/doctor/diagnose/systemd
├── config_loader.py       YAML → proxy_config (+ валидация)
├── generator.py           генерация конфига, секретов, tg://-ссылок
├── runner.py              один event-loop: _run() + socks5 + сигналы
├── socks5.py              SOCKS5-мост (plain abridged/intermediate + obfuscated)
├── doctor.py              быстрая диагностика (DNS, WS 101, порты, лог)
├── diagnostics.py         полная диагностика: ~35 проверок в 7 группах,
│                          «вероятные причины», отчёты JSON/Markdown,
│                          e2e-пробы синтетическим MTProto-клиентом (--full)
└── docker_main.py         env-конфигурация для Docker

tests/                     тесты форка
├── test_multi_secret.py   перебор секретов, FakeTLS-перебор
├── test_socks5_bridge.py  парсинг/крипто-круговые тесты моста
├── test_generator.py      генератор, loader, links, apply_config
├── test_diagnostics.py    движок diagnose: группы, коды выхода, отчёты,
│                          вероятные причины; live e2e — под TGWS_LIVE=1
└── test_live_e2e.py       live-тест (TGWS_LIVE=1)

scripts/golden_connect.py  golden-тест реальным Telethon (3 маршрута)
deploy/install.sh          установщик Debian/Ubuntu
deploy/systemd/tgws-server.service
examples/                  bot_telethon.py, bot_pyrogram.py, cf-worker/api-mirror.js
rust/                      прототип ядра на Rust (см. docs/RUST_C.md)
docker-compose.yml
README.md, docs/*.md       документация форка
```

## Диагностика: doctor → diagnose

- `doctor` остаётся быстрым Smoke-тестом (конфиг, DNS, WS 101, порты).
- `diagnose` — расширенный набор (~35 проверок, группы ENV/DEPS/CONFIG/
  CRYPTO/NETWORK/SOCKS5/RUNTIME):
  - офлайн-самопроверка криптоконвейера (AES-CTR, парсинг init,
    перекодировка моста, MsgSplitter) — без сети;
  - DNS + подмена, TCP:443, WS 101 по пиновому IP и по DNS;
  - скан хвоста серверного лога (Traceback/ERROR/bad handshake);
  - `--full`: сквозные e2e-пробы — синтетический MTProto-клиент идёт
    через фронтенд и через SOCKS5-мост до реального WS-шлюза (стек
    поднимается в процессе и корректно восстанавливает proxy_config);
  - движок «вероятных причин»: комбинации отказов → диагноз + рецепт;
  - отчёты: человеко-текст, `--json PATH`, `--report PATH` (Markdown);
  - коды выхода 0/2/1 — пригодно для мониторинга и CI;
  - `--offline` (песочницы), `--group NAME` (одна группа), `--timeout`.

## Изменённые упаковка/CI

- `pyproject.toml`: имя `tg-ws-proxy-server`, + `pyyaml`, entry-point
  `tgws-server`, extra `golden` (telethon, python-socks), пакеты
  `server`.
- `Dockerfile`: + `server/`, SOCKS5-порт, env `TG_WS_PROXY_SECRETS`,
  `TG_WS_PROXY_FTLS_DOMAIN`, entrypoint `server/docker_main.py`.
- `.github/workflows/ci.yml`: ruff + pytest + golden (сеть) + `cargo
  check/test`.

## Правило мержа апстрима

```bash
git fetch upstream && git merge upstream/main
```
Конфликты возможны только в `proxy/tg_ws_proxy.py` (наши блоки помечены
`[fork]`) и `pyproject.toml`/`Dockerfile`. Функциональные проверки после
мержа: `pytest tests/ -q --ignore=tests/test_live_e2e.py` и
`TGWS_LIVE=1 pytest tests/test_live_e2e.py`.
