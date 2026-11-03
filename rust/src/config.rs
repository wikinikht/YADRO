//! JSON configuration (mirror of tgws-server.yaml, JSON for the
//! prototype to stay dependency-light).

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Socks5Config {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_socks5_host")]
    pub host: String,
    #[serde(default = "default_socks5_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub secrets: Vec<String>,
    #[serde(default)]
    pub dc_ips: BTreeMap<u16, String>,
    #[serde(default)]
    pub socks5: Option<Socks5Config>,
}

fn default_true() -> bool { true }
fn default_host() -> String { "0.0.0.0".into() }
fn default_port() -> u16 { 1443 }
fn default_socks5_host() -> String { "127.0.0.1".into() }
fn default_socks5_port() -> u16 { 1080 }

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            enabled: true,
            host: default_socks5_host(),
            port: default_socks5_port(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let cfg: Config = serde_json::from_str(&text)
            .map_err(|e| format!("invalid config: {e}"))?;
        if cfg.secrets.is_empty() {
            return Err("config: at least one secret required".into());
        }
        for s in &cfg.secrets {
            if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("config: bad secret '{s}' (32 hex chars required)"));
            }
        }
        Ok(cfg)
    }

    pub fn dc_ip(&self, dc: u16) -> String {
        self.dc_ips
            .get(&dc)
            .cloned()
            .unwrap_or_else(|| "149.154.167.220".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal() {
        let cfg: Config = serde_json::from_str(
            r#"{"secrets": ["aabbccddeeff00112233445566778899"]}"#,
        )
        .unwrap();
        assert_eq!(cfg.port, 1443);
        assert_eq!(cfg.dc_ip(2), "149.154.167.220");
        assert!(cfg.socks5.is_none());
    }

    #[test]
    fn rejects_bad_secret() {
        let cfg = Config::load(Path::new("/nonexistent"));
        assert!(cfg.is_err());
    }
}
