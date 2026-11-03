//! tgws-rs — Rust prototype binary of tg-ws-proxy-server.
//!
//! Usage:
//!   tgws-rs --config tgws-server.json
//!   tgws-rs --demo-links --secrets <hex32>[,<hex32>...]

use std::path::PathBuf;
use std::sync::Arc;

use tgws_rs::config::Config;
use tgws_rs::obfuscation;
use tgws_rs::server;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut config_path: Option<PathBuf> = None;
    let mut demo_links = false;
    let mut demo_secrets: Vec<String> = vec![];

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next().map(PathBuf::from),
            "--demo-links" => demo_links = true,
            "--secrets" => {
                demo_secrets = args
                    .next()
                    .unwrap_or_default()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect()
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!("usage: tgws-rs --config tgws-server.json | --demo-links --secrets <hex32>[,...]");
                std::process::exit(2);
            }
        }
    }

    if demo_links {
        for (i, s) in demo_secrets.iter().enumerate() {
            println!("secret #{i}: tg://proxy?server=<VPS_IP>&port=1443&secret=dd{s}");
        }
        return;
    }

    let path = config_path.unwrap_or_else(|| PathBuf::from("tgws-server.json"));
    let cfg = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    let cfg = Arc::new(cfg);

    println!("tgws-rs prototype (Rust) — mirror of the Python core");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let mut tasks = vec![tokio::spawn({
            let cfg = cfg.clone();
            async move {
                if let Err(e) = server::run_mtproto_listener(cfg).await {
                    eprintln!("mtproto listener failed: {e}");
                    std::process::exit(1);
                }
            }
        })];
        if cfg.socks5.as_ref().map(|s| s.enabled).unwrap_or(false) {
            tasks.push(tokio::spawn({
                let cfg = cfg.clone();
                async move {
                    if let Err(e) = server::run_socks5_listener(cfg).await {
                        eprintln!("socks5 listener failed: {e}");
                        std::process::exit(1);
                    }
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    });

    // silence unused warnings for the re-exported module docs
    let _ = obfuscation::HANDSHAKE_LEN;
}
