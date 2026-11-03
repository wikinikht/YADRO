//! SOCKS5 handshake parsing (mirror of server/socks5.py).
//!
//! Supports the no-auth method and CONNECT only; the actual tunneling
//! lives in `server.rs`.

use crate::bridge::ClientTransport;
use crate::obfuscation::{
    HANDSHAKE_LEN, PROTO_TAG_ABRIDGED,
};

pub const SOCKS_VER: u8 = 5;
pub const NO_AUTH: u8 = 0x00;
pub const NO_ACCEPTABLE: u8 = 0xFF;

pub const REP_OK: u8 = 0x00;
pub const REP_GENERAL_FAIL: u8 = 0x01;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug)]
pub struct SocksError(pub u8);

/// Greeting: VER NMETHODS METHODS... -> reply method selection.
pub fn read_greeting(buf: &[u8]) -> Result<Option<u8>, SocksError> {
    // returns Ok(Some(method_reply_byte)) or Ok(None) if incomplete
    if buf.len() < 2 {
        return Ok(None);
    }
    if buf[0] != SOCKS_VER {
        return Err(SocksError(REP_GENERAL_FAIL));
    }
    let n = buf[1] as usize;
    if buf.len() < 2 + n {
        return Ok(None);
    }
    let methods = &buf[2..2 + n];
    if methods.contains(&NO_AUTH) {
        Ok(Some(NO_AUTH))
    } else {
        Err(SocksError(NO_ACCEPTABLE))
    }
}

/// CONNECT request -> (target, port, consumed).
pub fn read_connect(buf: &[u8]) -> Result<Option<(String, u16, usize)>, SocksError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let (ver, cmd, _rsv, atyp) = (buf[0], buf[1], buf[2], buf[3]);
    if ver != SOCKS_VER {
        return Err(SocksError(REP_GENERAL_FAIL));
    }
    if cmd != 1 {
        return Err(SocksError(REP_CMD_NOT_SUPPORTED));
    }
    match atyp {
        1 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let ip = format!("{}.{}.{}.{}",
                buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok(Some((ip, port, 10)))
        }
        3 => {
            if buf.len() < 5 {
                return Ok(None);
            }
            let dlen = buf[4] as usize;
            if buf.len() < 5 + dlen + 2 {
                return Ok(None);
            }
            let host = String::from_utf8_lossy(&buf[5..5 + dlen]).into_owned();
            let port = u16::from_be_bytes([buf[5 + dlen], buf[6 + dlen]]);
            Ok(Some((host, port, 5 + dlen + 2)))
        }
        4 => {
            if buf.len() < 22 {
                return Ok(None);
            }
            let hex: Vec<String> = buf[4..20].iter().map(|b| format!("{:02x}", b)).collect();
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok(Some((hex.join(":"), port, 22)))
        }
        _ => Err(SocksError(REP_ATYP_NOT_SUPPORTED)),
    }
}

pub fn success_reply() -> [u8; 10] {
    [SOCKS_VER, REP_OK, 0, 1, 0, 0, 0, 0, 0, 0]
}

pub fn error_reply(rep: u8) -> [u8; 10] {
    [SOCKS_VER, rep, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// Classify the first bytes of the client MTProto stream.
pub fn classify_stream_head(first: u8) -> Option<ClientTransport> {
    match first {
        0xEF => Some(ClientTransport::PlainAbridged),
        0xEE => Some(ClientTransport::PlainIntermediate),
        _ => Some(ClientTransport::Obfuscated), // must be a 64-byte init
    }
}

pub const PLAIN_INTERMEDIATE_TAG: [u8; 4] = [0xEE, 0xEE, 0xEE, 0xEE];

pub fn tag_for_transport(t: ClientTransport, init_tag: [u8; 4]) -> [u8; 4] {
    match t {
        ClientTransport::PlainAbridged => PROTO_TAG_ABRIDGED,
        ClientTransport::PlainIntermediate => PLAIN_INTERMEDIATE_TAG,
        ClientTransport::Obfuscated => init_tag,
    }
}

pub fn handshake_len_for(t: ClientTransport) -> usize {
    match t {
        ClientTransport::Obfuscated => HANDSHAKE_LEN,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_roundtrip() {
        let buf = [0x05, 0x01, 0x00];
        assert_eq!(read_greeting(&buf).unwrap(), Some(NO_AUTH));
        let buf = [0x05, 0x01, 0x02];
        assert!(read_greeting(&buf).is_err());
        let buf = [0x05];
        assert_eq!(read_greeting(&buf).unwrap(), None);
    }

    #[test]
    fn connect_ipv4() {
        let mut buf = vec![0x05, 0x01, 0x00, 0x01, 149, 154, 167, 51];
        buf.extend_from_slice(&443u16.to_be_bytes());
        let (ip, port, used) = read_connect(&buf).unwrap().unwrap();
        assert_eq!(ip, "149.154.167.51");
        assert_eq!(port, 443);
        assert_eq!(used, 10);
    }

    #[test]
    fn connect_domain() {
        let mut buf = vec![0x05, 0x01, 0x00, 0x03, 5];
        buf.extend_from_slice(b"dc2.c");
        buf.extend_from_slice(&443u16.to_be_bytes());
        let (host, port, used) = read_connect(&buf).unwrap().unwrap();
        assert_eq!(host, "dc2.c");
        assert_eq!(port, 443);
        assert_eq!(used, 12);
    }

    #[test]
    fn classify() {
        assert_eq!(
            classify_stream_head(0xEF),
            Some(ClientTransport::PlainAbridged)
        );
        assert_eq!(
            classify_stream_head(0xEE),
            Some(ClientTransport::PlainIntermediate)
        );
        assert_eq!(
            classify_stream_head(0x42),
            Some(ClientTransport::Obfuscated)
        );
    }
}
