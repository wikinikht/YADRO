# Локальный прогон на Mac (ветка `develop`)

Эта ветка для экспериментов. В GitHub пушить её не нужно:
`main` остаётся чистым снимком форка.

```bash
git checkout develop          # уже текущая
bash scripts/macos-dev.sh     # venv + конфиг + doctor
```

Конфиг `tgws-server.yaml` в git не попадает (он в `.gitignore`).

## Что можно проверить на Mac без VPN

Протокол — да. ТСПУ — нет, пока выход в интернет не из РФ.

| Проверка | На этом Mac | Нужен хост в РФ |
|---|---|---|
| unit-тесты | да | нет |
| `tgws-server doctor` / WS 101 | да, шлюз `kws2` публичный | нет |
| `scripts/golden_connect.py` (реальный MTProto handshake) | да | нет |
| Telegram Desktop → `127.0.0.1:1443` | да | нет |
| «прямой DC заблокирован, WS проходит» | нет: с зарубежного IP прямой MTProto тоже живой | да: Mac в РФ без VPN **или** VPS в РФ |

Русский сервак нужен не для того, чтобы «вообще потыкать», а только чтобы увидеть поведение за ТСПУ. Для 24/7 бота он тоже нужен — Mac выключается.

## Запуск после doctor

```bash
source .venv/bin/activate
tgws-server run -c tgws-server.yaml -v
tgws-server links -c tgws-server.yaml
```

В Telegram Desktop: прокси MTProto, сервер `127.0.0.1`, порт `1443`, секрет из `links`.

## GitHub

```bash
git checkout main
git push -u origin main      # когда появится remote
# develop не пушить, пока сами не решите
```
