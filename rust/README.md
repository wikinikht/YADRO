# tgws-rs — Rust-прототип ядра

Зеркало Python-ядра tg-ws-proxy-server на Rust (см. docs/RUST_C.md).

```bash
cargo test                 # 16 unit-тестов
cargo build --release      # ~1.8 МБ бинарник
./target/release/tgws-rs --config tgws-server.json
```

Пример конфига (JSON — сознательно, чтобы не тянуть yaml-зависимость):

```json
{
  "host": "0.0.0.0",
  "port": 1443,
  "secrets": ["0123456789abcdef0123456789abcdef"],
  "dc_ips": {"2": "149.154.167.220", "4": "149.154.167.220"},
  "socks5": {"enabled": true, "host": "127.0.0.1", "port": 1080}
}
```

Ссылки печатаются как `dd<secret>` (FakeTLS/ee-секреты и CF-фолбэки —
в roadmap, статус в docs/RUST_C.md). Кросс-валидирован с
Python-реализацией: одинаковый формат obfuscation-init и WS-кадров.
