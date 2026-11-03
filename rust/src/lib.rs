//! tgws-rs — Rust prototype of tg-ws-proxy-server.
//!
//! Implements the same wire protocol as the Python core
//! (proxy/tg_ws_proxy.py of Flowseal/tg-ws-proxy):
//!   * MTProto-proxy frontend (dd-secrets, multi-secret)
//!   * TLS+WebSocket tunnel to kws{dc}.web.telegram.org pinned to the
//!     whitelisted DC IP
//!   * transport re-encryption with per-packet splitting
//!   * SOCKS5 bridge for MTProto client libraries (plain + obfuscated)
//!
//! Prototype scope (see docs/RUST_C.md): no FakeTLS (ee) secrets,
//! no CF proxy/worker fallbacks, no connection pooling yet.

pub mod obfuscation;
pub mod splitter;
pub mod bridge;
pub mod socks5;
pub mod config;
pub mod server;
