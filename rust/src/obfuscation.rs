//! MTProto obfuscated-transport primitives (mirror of proxy/utils.py +
//! proxy/tg_ws_proxy.py handshake code from the upstream project).

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use sha2::{Digest, Sha256};

pub const HANDSHAKE_LEN: usize = 64;
pub const SKIP_LEN: usize = 8;
pub const PREKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const PROTO_TAG_POS: usize = 56;
pub const DC_IDX_POS: usize = 60;

pub const PROTO_TAG_ABRIDGED: [u8; 4] = [0xEF, 0xEF, 0xEF, 0xEF];
pub const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xEE, 0xEE, 0xEE, 0xEE];
pub const PROTO_TAG_PADDED: [u8; 4] = [0xDD, 0xDD, 0xDD, 0xDD];

pub const PROTO_ABRIDGED: u32 = 0xEFEF_EFEF;
pub const PROTO_INTERMEDIATE: u32 = 0xEEEE_EEEE;
pub const PROTO_PADDED: u32 = 0xDDDD_DDDD;

const RESERVED_FIRST_BYTE: u8 = 0xEF;
const RESERVED_STARTS: [[u8; 4]; 7] = [
    *b"HEAD", *b"POST", *b"GET ", [0xEE, 0xEE, 0xEE, 0xEE],
    [0xDD, 0xDD, 0xDD, 0xDD], [0x16, 0x03, 0x01, 0x02], *b"OPTI",
];

pub fn proto_tag_to_int(tag: &[u8; 4]) -> Option<u32> {
    match *tag {
        PROTO_TAG_ABRIDGED => Some(PROTO_ABRIDGED),
        PROTO_TAG_INTERMEDIATE => Some(PROTO_INTERMEDIATE),
        PROTO_TAG_PADDED => Some(PROTO_PADDED),
        _ => None,
    }
}

pub fn proto_int_to_tag(int: u32) -> [u8; 4] {
    match int {
        PROTO_ABRIDGED => PROTO_TAG_ABRIDGED,
        PROTO_INTERMEDIATE => PROTO_TAG_INTERMEDIATE,
        _ => PROTO_TAG_PADDED,
    }
}

pub type Aes256Ctr = Ctr128BE<Aes256>;

/// AES-256-CTR keystream (big-endian counter), like Python's `modes.CTR`.
pub fn ctr_cipher(key: &[u8; 32], iv: &[u8; 16]) -> Aes256Ctr {
    Ctr128BE::new(key.into(), iv.into())
}

/// AES-CTR of a 64-byte zero buffer — the keystream itself.
pub fn keystream64(key: &[u8; 32], iv: &[u8; 16]) -> [u8; 64] {
    let mut cipher = ctr_cipher(key, iv);
    let mut zeros = [0u8; 64];
    cipher.apply_keystream(&mut zeros);
    zeros
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHandshake {
    pub dc: i32,
    pub is_media: bool,
    pub proto_int: u32,
    /// init[SKIP_LEN .. SKIP_LEN+PREKEY_LEN+IV_LEN] (needed for the ctx)
    pub dec_prekey_iv: [u8; PREKEY_LEN + IV_LEN],
}

/// Mirror of upstream `_try_handshake`: decrypt the init with
/// SHA256(prekey + secret) and validate the transport tag.
pub fn try_handshake(handshake: &[u8; HANDSHAKE_LEN], secret: &[u8; 16]) -> Option<ClientHandshake> {
    let mut prekey_iv = [0u8; PREKEY_LEN + IV_LEN];
    prekey_iv.copy_from_slice(&handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);

    let mut key_material = Vec::with_capacity(PREKEY_LEN + 16);
    key_material.extend_from_slice(&prekey_iv[..PREKEY_LEN]);
    key_material.extend_from_slice(secret);
    let key = sha256(&key_material);
    let iv: [u8; 16] = prekey_iv[PREKEY_LEN..].try_into().unwrap();

    let ks = keystream64(&key, &iv);
    let mut tail = [0u8; 8];
    for i in 0..8 {
        tail[i] = handshake[PROTO_TAG_POS + i] ^ ks[PROTO_TAG_POS + i];
    }

    let proto_int = proto_tag_to_int(tail[0..4].try_into().unwrap())?;
    let dc_idx = i16::from_le_bytes([tail[4], tail[5]]);
    let dc = (dc_idx as i32).abs();
    Some(ClientHandshake {
        dc,
        is_media: dc_idx < 0,
        proto_int,
        dec_prekey_iv: prekey_iv,
    })
}

/// Mirror of upstream `_generate_relay_init`: a fresh self-obfuscated
/// init towards the DC carrying proto tag + dc id.
pub fn generate_relay_init(proto_int: u32, dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
    let mut rnd = [0u8; HANDSHAKE_LEN];
    loop {
        getrandom_fill(&mut rnd);
        if rnd[0] == RESERVED_FIRST_BYTE {
            continue;
        }
        if RESERVED_STARTS.iter().any(|s| *s == rnd[0..4]) {
            continue;
        }
        if rnd[4..8] == [0, 0, 0, 0] {
            continue;
        }
        break;
    }

    let enc_key: [u8; 32] = rnd[SKIP_LEN..SKIP_LEN + KEY_LEN].try_into().unwrap();
    let enc_iv: [u8; 16] = rnd[SKIP_LEN + KEY_LEN..SKIP_LEN + KEY_LEN + IV_LEN]
        .try_into()
        .unwrap();
    let ks = keystream64(&enc_key, &enc_iv);

    let mut tail = [0u8; 8];
    tail[0..4].copy_from_slice(&proto_int_to_tag(proto_int));
    tail[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    getrandom_fill(&mut tail[6..8]);

    let mut out = rnd;
    for i in 0..8 {
        out[PROTO_TAG_POS + i] = tail[i] ^ ks[PROTO_TAG_POS + i];
    }
    out
}

/// Mirror of `parse_self_obfuscated_init` from server/socks5.py: a
/// plain (no proxy secret) self-obfuscated init; the key material is
/// the init itself.
pub fn parse_self_init(init: &[u8; HANDSHAKE_LEN]) -> Option<(u32, i16)> {
    let key: [u8; 32] = init[SKIP_LEN..SKIP_LEN + KEY_LEN].try_into().unwrap();
    let iv: [u8; 16] = init[SKIP_LEN + KEY_LEN..SKIP_LEN + KEY_LEN + IV_LEN]
        .try_into()
        .unwrap();
    let ks = keystream64(&key, &iv);
    let mut tail = [0u8; 8];
    for i in 0..8 {
        tail[i] = init[PROTO_TAG_POS + i] ^ ks[PROTO_TAG_POS + i];
    }
    let proto_int = proto_tag_to_int(tail[0..4].try_into().unwrap())?;
    let dc_idx = i16::from_le_bytes([tail[4], tail[5]]);
    Some((proto_int, dc_idx))
}

pub(crate) fn getrandom_fill(buf: &mut [u8]) {
    use std::io::Read;
    // /dev/urandom: no external crates needed for the prototype
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .expect("cannot read /dev/urandom");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_init_for_secret(secret: &[u8; 16], dc: i16, tag: [u8; 4]) -> [u8; HANDSHAKE_LEN] {
        let mut rnd = [0u8; HANDSHAKE_LEN];
        getrandom_fill(&mut rnd);
        rnd[0] = 0x12; // avoid reserved first byte
        let prekey: [u8; 32] = rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN].try_into().unwrap();
        let iv: [u8; 16] = rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
            .try_into()
            .unwrap();
        let mut material = Vec::new();
        material.extend_from_slice(&prekey);
        material.extend_from_slice(secret);
        let key = sha256(&material);
        let ks = keystream64(&key, &iv);
        let mut tail = [0u8; 8];
        tail[0..4].copy_from_slice(&tag);
        tail[4..6].copy_from_slice(&dc.to_le_bytes());
        let mut init = rnd;
        for i in 0..8 {
            init[PROTO_TAG_POS + i] = tail[i] ^ ks[PROTO_TAG_POS + i];
        }
        init
    }

    #[test]
    fn handshake_matches_secret() {
        let s1 = [0xAA; 16];
        let s2 = [0xBB; 16];
        let init = client_init_for_secret(&s2, 2, PROTO_TAG_ABRIDGED);
        assert!(try_handshake(&init, &s1).is_none());
        let h = try_handshake(&init, &s2).expect("must match");
        assert_eq!(h.dc, 2);
        assert!(!h.is_media);
        assert_eq!(h.proto_int, PROTO_ABRIDGED);
    }

    #[test]
    fn handshake_media_dc_negative() {
        let s = [0x11; 16];
        let init = client_init_for_secret(&s, -4, PROTO_TAG_ABRIDGED);
        let h = try_handshake(&init, &s).unwrap();
        assert_eq!(h.dc, 4);
        assert!(h.is_media);
    }

    #[test]
    fn relay_init_roundtrip_via_self_parse() {
        let init = generate_relay_init(PROTO_PADDED, 3);
        let (proto, dc) = parse_self_init(&init).expect("relay init is self-parsable");
        assert_eq!(proto, PROTO_PADDED);
        assert_eq!(dc, 3);
    }

    #[test]
    fn garbage_rejected() {
        let mut junk = [0u8; HANDSHAKE_LEN];
        junk[0] = 0x12;
        assert!(try_handshake(&junk, &[0; 16]).is_none());
        assert!(parse_self_init(&junk).is_none());
    }
}
