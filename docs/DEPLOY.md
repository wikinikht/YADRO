# Развёртывание на Debian/Ubuntu VPS

Проверено на Debian 12 / Ubuntu 22.04+ (x86_64), 512 МБ RAM достаточно.

## 0. Что понадобится

- VDS/VPS в РФ с root-доступом (если бот — на этом же VPS, ничего
  открывать наружу не нужно: туннель слушает loopback);
- python3 ≥ 3.8, git, openssl;
- ~50 МБ диска.

## 1. Установка

### Вариант А — скрипт (рекомендуется)

```bash
git clone https://github.com/wikinikht/YADRO.git /opt/tg-ws-proxy-server-src
cd /opt/tg-ws-proxy-server-src
sudo bash deploy/install.sh
```

Скрипт: ставит venv в `/opt/tg-ws-proxy-server`, создаёт пользователя
`tgws`, генерирует конфиг с 2 секретами в `/etc/tgws-server/`,
ставит systemd-юнит и запускает сервис.

### Вариант Б — руками

```bash
apt update && apt install -y python3-venv python3-pip git openssl
git clone https://github.com/wikinikht/YADRO.git /opt/tg-ws-proxy-server
cd /opt/tg-ws-proxy-server
python3 -m venv .venv
. .venv/bin/activate
pip install -e .

tgws-server gen -o /etc/tgws-server/tgws-server.yaml \
    --secrets 2 --domain cloudflare.com \
    --log-file /var/log/tgws-server/proxy.log
```

### Вариант В — Docker

```bash
git clone https://github.com/wikinikht/YADRO.git /opt/YADRO
cd /opt/YADRO
cp .env.example .env
# заполните TG_WS_PROXY_SECRET и TG_WS_PROXY_SECRETS (openssl rand -hex 16)
docker compose up -d --build
docker compose logs tgws | grep 'tg://proxy'
```

## 2. Проверка перед запуском

```bash
tgws-server doctor -c /etc/tgws-server/tgws-server.yaml
```

Если doctor красный — расширенная диагностика с вероятными причинами
(см. [TESTING.md](TESTING.md), раздел 4):

```bash
tgws-server diagnose -c /etc/tgws-server/tgws-server.yaml --full \
    --report /tmp/diag.md
```

Ожидаемо с РФ-VPS:

```
[ OK ] WS gateway kws2.web.telegram.org via 149.154.167.220:443: TLS+Upgrade OK (101)
[ OK ] WS gateway kws4...: TLS+Upgrade OK (101)
[WARN] Direct MTProto TCP 149.154.167.51:443: blocked — expected inside RF
```

Красная строка `WS gateway` = маршрут «белого списка» не работает с
этого хоста — см. [TESTING.md](TESTING.md).

## 3. Запуск и автостарт

```bash
# вручную (отладка):
tgws-server run -c /etc/tgws-server/tgws-server.yaml -v

# systemd:
tgws-server systemd --user tgws \
    | sudo tee /etc/systemd/system/tgws-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now tgws-server
journalctl -u tgws-server -f
```

В логе при старте:

```
Listening on   0.0.0.0:1443
Secrets:       2 (a1b2c3d4...)
SOCKS5 bridge listening on 127.0.0.1:1080
```

## 4. Ссылки и секреты

```bash
tgws-server links -c /etc/tgws-server/tgws-server.yaml
```

Печатает `tg://proxy?server=...` для каждого секрета (для Telegram
Desktop/мобильных) и готовые сниппеты для Telethon/Pyrogram.

Добавить/убрать секрет:

```bash
tgws-server secret add laptop     # сгенерирует и допишет в конфиг
tgws-server secret remove old-key
systemctl restart tgws-server
```

Ротация: добавили новый → раздали → убрали старый → restart.

## 5. Файрвол

По умолчанию наружу открывать ничего не нужно (бот ходит на loopback).
Если хотите раздавать прокси другим клиентам:

```bash
ufw allow 1443/tcp          # MTProto-фронтенд
# SOCKS5 наружу НЕ открывайте: он без аутентификации!
```

В конфиге (`host: 0.0.0.0`) и в `socks5.host` оставляйте `127.0.0.1`,
если мост нужен только локальным ботам.

## 6. Обновления форка и апстрима

Апстрим активно развивается. Мержить обновления — легко: все изменения
форка изолированы (список в [CHANGES.md](CHANGES.md)):

```bash
git remote add upstream https://github.com/Flowseal/tg-ws-proxy.git
git fetch upstream
git merge upstream/main        # конфликты возможны только в proxy/tg_ws_proxy.py
pytest tests/ -q --ignore=tests/test_live_e2e.py
systemctl restart tgws-server
```

## 7. Типичные проблемы

| Симптом | Причина / решение |
|---|---|
| `bad handshake` в логах | клиент шлёт не тот секрет; проверьте `tgws-server links` |
| `unsupported MTProto transport` (socks5) | Telethon с ConnectionTcpFull; используйте обычный ConnectionTcpAbridged (по умолчанию у новых версий ок) |
| doctor: `WS gateway ... timeout` | хост/AS заблокирован сильнее обычного; попробуйте `--cfproxy-worker-domain` (свой CF Worker) или другой VPS |
| что-то сломалось, причина непонятна | `tgws-server diagnose --full` — ~35 проверок + «ВЕРОЯТНЫЕ ПРИЧИНЫ»; отчёт `--report diag.md` приложите к issue |
| бот не видит `api.telegram.org` | это Bot API (HTTPS) — см. [BOTS.md](BOTS.md), WS-туннель тут не поможет |
| порты заняты | измените `port:`/`socks5.port` в конфиге |
