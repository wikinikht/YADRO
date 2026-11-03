//! Async core: listeners + the bidirectional WS tunnel.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{rustls, TlsConnector};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::bridge::{ClientTransport, CryptoCtx};
use crate::config::Config;
use crate::obfuscation::*;
use crate::socks5 as s5;
use crate::splitter::PacketSplitter;

type Ws = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Connect to kws{dc}.web.telegram.org pinned to the whitelisted IP.
pub async fn ws_connect(dc: u16, cfg: &Config) -> Result<Ws, String> {
    let domain = format!("kws{dc}.web.telegram.org");
    let ip = cfg.dc_ip(dc);

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));

    let tcp = TcpStream::connect((ip.as_str(), 443))
        .await
        .map_err(|e| format!("tcp {ip}:443: {e}"))?;
    let name = ServerName::try_from(domain.clone())
        .map_err(|e| format!("bad sni: {e:?}"))?;
    let tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| format!("tls {domain}: {e}"))?;

    let mut request = format!("wss://{domain}/apiws")
        .into_client_request()
        .map_err(|e| format!("ws request: {e}"))?;
    // Telegram's gateway answers 404 without the binary subprotocol
    // (upstream Python always sends it).
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        http_header_value("binary"),
    );
    let (ws, _resp) = tokio_tungstenite::client_async(request, tls)
        .await
        .map_err(|e| format!("ws upgrade {domain}: {e}"))?;
    Ok(ws)
}

/// Bidirectional bridge: client TCP <-> WS with re-encryption.
/// Up: decrypt client stream, split into packets, send as WS frames.
/// Down: WS frames -> decrypt -> re-encrypt to the client's transport.
async fn bridge(
    client: TcpStream,
    ws: Ws,
    ctx: CryptoCtx,
    proto_int: u32,
) {
    let (mut clt_read, mut clt_write) = client.into_split();
    let (mut ws_tx, mut ws_rx) = ws.split();

    let CryptoCtx {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ctx;

    let mut splitter = PacketSplitter::new(proto_int);
    let mut buf = vec![0u8; 65536];

    let up = async {
        loop {
            let n = clt_read
                .read(&mut buf)
                .await
                .map_err(|e| format!("client read: {e}"))?;
            if n == 0 {
                return Ok::<(), String>(());
            }
            let plain = clt_dec.apply_vec(&buf[..n]);
            let cipher = tg_enc.apply_vec(&plain);
            let parts = match splitter.as_mut() {
                Some(s) => s.split(&cipher, &plain),
                None => vec![cipher],
            };
            for part in parts {
                ws_tx
                    .send(Message::Binary(part))
                    .await
                    .map_err(|e| format!("ws send: {e}"))?;
            }
        }
    };

    let down = async {
        while let Some(msg) = ws_rx.next().await {
            let msg = msg.map_err(|e| format!("ws recv: {e}"))?;
            match msg {
                Message::Binary(data) => {
                    let plain = tg_dec.apply_vec(&data);
                    let to_client = clt_enc.apply_vec(&plain);
                    clt_write
                        .write_all(&to_client)
                        .await
                        .map_err(|e| format!("client write: {e}"))?;
                }
                Message::Close(_) => return Ok::<(), String>(()),
                _ => {}
            }
        }
        Ok(())
    };

    let _ = tokio::select! {
        r = up => r,
        r = down => r,
    };
    let _ = ws_tx.close().await;
}

fn hex_to_secret(hex: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
            .unwrap_or(0);
    }
    out
}

fn http_header_value(v: &'static str) -> tungstenite::http::HeaderValue {
    tungstenite::http::HeaderValue::from_static(v)
}

/// MTProto-proxy frontend: accept -> 64-byte init -> route to WS.
pub async fn run_mtproto_listener(cfg: Arc<Config>) -> Result<(), String> {
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    println!(
        "MTProto frontend listening on {addr} ({} secret(s))",
        cfg.secrets.len()
    );

    loop {
        let (client, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_mtproto_client(client, peer.to_string(), &cfg).await {
                eprintln!("{e}");
            }
        });
    }
}

async fn handle_mtproto_client(
    mut client: TcpStream,
    label: String,
    cfg: &Config,
) -> Result<(), String> {
    let mut init = [0u8; HANDSHAKE_LEN];
    client
        .read_exact(&mut init)
        .await
        .map_err(|e| format!("{label}: init read: {e}"))?;

    let mut matched: Option<ClientHandshake> = None;
    let mut matched_secret: [u8; 16] = [0; 16];
    for s in &cfg.secrets {
        let secret = hex_to_secret(s);
        if let Some(h) = try_handshake(&init, &secret) {
            matched = Some(h);
            matched_secret = secret;
            break;
        }
    }
    let h = matched.ok_or_else(|| format!("{label}: bad handshake"))?;

    let relay =
        generate_relay_init(h.proto_int, if h.is_media { -(h.dc as i16) } else { h.dc as i16 });
    let ctx = CryptoCtx::proxy_transport(&h.dec_prekey_iv, &matched_secret, &relay);

    let mut ws = ws_connect(h.dc as u16, cfg).await?;
    ws.send(Message::Binary(relay.to_vec()))
        .await
        .map_err(|e| format!("{label}: ws init: {e}"))?;
    println!("{label}: DC{} -> WS hit", h.dc);
    bridge(client, ws, ctx, h.proto_int).await;
    Ok(())
}

/// SOCKS5 bridge: Telethon/Pyrogram-style clients.
pub async fn run_socks5_listener(cfg: Arc<Config>) -> Result<(), String> {
    let s5cfg = cfg.socks5.clone().unwrap_or_default();
    let addr = format!("{}:{}", s5cfg.host, s5cfg.port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    println!("SOCKS5 bridge listening on {addr}");

    loop {
        let (client, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5_client(client, peer.to_string(), &cfg).await {
                eprintln!("{e}");
            }
        });
    }
}

async fn handle_socks5_client(
    mut client: TcpStream,
    label: String,
    cfg: &Config,
) -> Result<(), String> {
    // greeting
    let mut buf = [0u8; 2 + 255];
    let n = client.read(&mut buf).await.map_err(|e| format!("{label}: {e}"))?;
    let method = match s5::read_greeting(&buf[..n]) {
        Ok(Some(m)) => m,
        Ok(None) => return Err(format!("{label}: incomplete greeting")),
        Err(e) => {
            let _ = client.write_all(&s5::error_reply(e.0)).await;
            return Err(format!("{label}: greeting rejected ({})", e.0));
        }
    };
    client
        .write_all(&[s5::SOCKS_VER, method])
        .await
        .map_err(|e| format!("{label}: {e}"))?;

    // CONNECT
    let mut buf = [0u8; 5 + 255 + 2];
    let n = client.read(&mut buf).await.map_err(|e| format!("{label}: {e}"))?;
    let (target, _port) = match s5::read_connect(&buf[..n]) {
        Ok(Some((t, p, _used))) => (t, p),
        Ok(None) => return Err(format!("{label}: incomplete connect")),
        Err(e) => {
            let _ = client.write_all(&s5::error_reply(e.0)).await;
            return Err(format!("{label}: connect error {}", e.0));
        }
    };
    client
        .write_all(&s5::success_reply())
        .await
        .map_err(|e| format!("{label}: {e}"))?;

    // stream head: plain tags or a 64-byte self-obfuscated init
    let mut first = [0u8; 1];
    client
        .read_exact(&mut first)
        .await
        .map_err(|e| format!("{label}: stream head: {e}"))?;
    let transport = s5::classify_stream_head(first[0])
        .ok_or_else(|| format!("{label}: unsupported transport"))?;

    let mut init = [0u8; HANDSHAKE_LEN];
    let init_dc: i16;
    let proto_int: u32 = match transport {
        ClientTransport::PlainAbridged => {
            init_dc = 0;
            PROTO_ABRIDGED
        }
        ClientTransport::PlainIntermediate => {
            // consume the remaining 3 bytes of the EEEEEEEE tag
            let mut rest = [0u8; 3];
            client
                .read_exact(&mut rest)
                .await
                .map_err(|e| format!("{label}: tag read: {e}"))?;
            if [first[0], rest[0], rest[1], rest[2]] != s5::PLAIN_INTERMEDIATE_TAG {
                return Err(format!("{label}: unknown transport tag 0xEE.."));
            }
            init_dc = 0;
            PROTO_INTERMEDIATE
        }
        ClientTransport::Obfuscated => {
            init[0] = first[0];
            client
                .read_exact(&mut init[1..])
                .await
                .map_err(|e| format!("{label}: init read: {e}"))?;
            let (proto, dc) =
                parse_self_init(&init).ok_or_else(|| format!("{label}: bad init"))?;
            init_dc = dc;
            proto
        }
    };

    // DC from the SOCKS5 target first (plain transports carry no dc id),
    // fall back to the dc encoded in the obfuscated init.
    let dc = infer_dc(&target)
        .or_else(|| if init_dc == 0 { None } else { Some(init_dc as i32) })
        .ok_or_else(|| format!("{label}: cannot determine DC for {target}"))?;
    let dc = dc.unsigned_abs() as u16;

    let relay = generate_relay_init(proto_int, dc as i16);
    let ctx = if transport == ClientTransport::Obfuscated {
        CryptoCtx::self_transport(&init, &relay)
    } else {
        CryptoCtx::plain_transport(&relay)
    };

    let mut ws = ws_connect(dc, cfg).await?;
    ws.send(Message::Binary(relay.to_vec()))
        .await
        .map_err(|e| format!("{label}: ws init: {e}"))?;
    println!("{label}: DC{dc} ({transport:?}) -> WS hit");
    bridge(client, ws, ctx, proto_int).await;
    Ok(())
}

fn infer_dc(target: &str) -> Option<i32> {
    // production DC IPs (mirror of upstream DC_DEFAULT_IPS)
    let table: &[(&str, i32)] = &[
        ("149.154.175.50", 1),
        ("149.154.167.51", 2),
        ("149.154.175.100", 3),
        ("149.154.167.91", 4),
        ("149.154.171.5", 5),
        ("91.105.192.100", 203),
    ];
    table
        .iter()
        .find(|(ip, _)| *ip == target)
        .map(|(_, dc)| *dc)
}
