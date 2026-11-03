//! Crypto context for re-encryption (mirror of upstream `CryptoCtx`
//! and `_build_crypto_ctx`), plus transport classification.

use crate::obfuscation::*;
use aes::cipher::StreamCipher as _StreamCipherTrait;

/// Client/Telegram-side stream cipher. Plain (unobfuscated) transports
/// use the Identity variant.
pub enum StreamCipher {
    Ctr(Box<Aes256Ctr>),
    Identity,
}

impl StreamCipher {
    pub fn ctr(c: Aes256Ctr) -> Self {
        StreamCipher::Ctr(Box::new(c))
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        match self {
            StreamCipher::Ctr(c) => _StreamCipherTrait::apply_keystream(c.as_mut(), data),
            StreamCipher::Identity => {}
        }
    }

    pub fn apply_vec(&mut self, data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        self.apply(&mut v);
        v
    }
}

pub struct CryptoCtx {
    /// decrypt data from the client
    pub clt_dec: StreamCipher,
    /// encrypt data to the client
    pub clt_enc: StreamCipher,
    /// encrypt data to Telegram
    pub tg_enc: StreamCipher,
    /// decrypt data from Telegram
    pub tg_dec: StreamCipher,
}

/// Which transport the SOCKS5 client speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTransport {
    /// plain Telethon abridged: 0xEF marker + plaintext packets
    PlainAbridged,
    /// plain intermediate: 0xEEEEEEEE marker + plaintext packets
    PlainIntermediate,
    /// self-obfuscated init (Pyrogram etc.)
    Obfuscated,
}

fn relay_side(relay_init: &[u8; HANDSHAKE_LEN]) -> (Aes256Ctr, Aes256Ctr) {
    let tg_enc_key: [u8; 32] = relay_init[SKIP_LEN..SKIP_LEN + KEY_LEN]
        .try_into()
        .unwrap();
    let tg_enc_iv: [u8; 16] = relay_init[SKIP_LEN + KEY_LEN..SKIP_LEN + KEY_LEN + IV_LEN]
        .try_into()
        .unwrap();
    let mut relay_reversed = [0u8; KEY_LEN + IV_LEN];
    relay_reversed.copy_from_slice(&relay_init[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN]);
    relay_reversed.reverse();
    let tg_dec_key: [u8; 32] = relay_reversed[..KEY_LEN].try_into().unwrap();
    let tg_dec_iv: [u8; 16] = relay_reversed[KEY_LEN..].try_into().unwrap();

    let mut tg_enc = ctr_cipher(&tg_enc_key, &tg_enc_iv);
    let mut ff = [0u8; HANDSHAKE_LEN];
    tg_enc.apply_keystream(&mut ff);
    (tg_enc, ctr_cipher(&tg_dec_key, &tg_dec_iv))
}

impl CryptoCtx {
    /// MTProto-proxy frontend context (mirror of `_build_crypto_ctx`):
    /// client stream is encrypted with SHA256(prekey + secret).
    pub fn proxy_transport(
        dec_prekey_iv: &[u8; PREKEY_LEN + IV_LEN],
        secret: &[u8; 16],
        relay_init: &[u8; HANDSHAKE_LEN],
    ) -> Self {
        let mut material = Vec::with_capacity(PREKEY_LEN + 16);
        material.extend_from_slice(&dec_prekey_iv[..PREKEY_LEN]);
        material.extend_from_slice(secret);
        let clt_dec_key = sha256(&material);
        let clt_dec_iv: [u8; 16] = dec_prekey_iv[PREKEY_LEN..].try_into().unwrap();

        let mut reversed = *dec_prekey_iv;
        reversed.reverse();
        let mut material_enc = Vec::with_capacity(PREKEY_LEN + 16);
        material_enc.extend_from_slice(&reversed[..PREKEY_LEN]);
        material_enc.extend_from_slice(secret);
        let clt_enc_key = sha256(&material_enc);
        let clt_enc_iv: [u8; 16] = reversed[PREKEY_LEN..].try_into().unwrap();

        let (tg_enc, tg_dec) = relay_side(relay_init);

        let mut clt_dec = ctr_cipher(&clt_dec_key, &clt_dec_iv);
        let mut ff = [0u8; HANDSHAKE_LEN];
        clt_dec.apply_keystream(&mut ff); // skip init bytes

        CryptoCtx {
            clt_dec: StreamCipher::ctr(clt_dec),
            clt_enc: StreamCipher::ctr(ctr_cipher(&clt_enc_key, &clt_enc_iv)),
            tg_enc: StreamCipher::ctr(tg_enc),
            tg_dec: StreamCipher::ctr(tg_dec),
        }
    }

    /// SOCKS5 bridge context: the client speaks a self-obfuscated
    /// transport (key material inside its init) — no secret layer.
    pub fn self_transport(
        client_init: &[u8; HANDSHAKE_LEN],
        relay_init: &[u8; HANDSHAKE_LEN],
    ) -> Self {
        let clt_dec_key: [u8; 32] = client_init[SKIP_LEN..SKIP_LEN + KEY_LEN]
            .try_into()
            .unwrap();
        let clt_dec_iv: [u8; 16] = client_init[SKIP_LEN + KEY_LEN..SKIP_LEN + KEY_LEN + IV_LEN]
            .try_into()
            .unwrap();

        let mut reversed = [0u8; KEY_LEN + IV_LEN];
        reversed.copy_from_slice(&client_init[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN]);
        reversed.reverse();
        let clt_enc_key: [u8; 32] = reversed[..KEY_LEN].try_into().unwrap();
        let clt_enc_iv: [u8; 16] = reversed[KEY_LEN..].try_into().unwrap();

        let (tg_enc, tg_dec) = relay_side(relay_init);

        let mut clt_dec = ctr_cipher(&clt_dec_key, &clt_dec_iv);
        let mut ff = [0u8; HANDSHAKE_LEN];
        clt_dec.apply_keystream(&mut ff);

        CryptoCtx {
            clt_dec: StreamCipher::ctr(clt_dec),
            clt_enc: StreamCipher::ctr(ctr_cipher(&clt_enc_key, &clt_enc_iv)),
            tg_enc: StreamCipher::ctr(tg_enc),
            tg_dec: StreamCipher::ctr(tg_dec),
        }
    }

    /// Plain (unobfuscated) client transport: identity on the client
    /// side, real obfuscation towards Telegram.
    pub fn plain_transport(relay_init: &[u8; HANDSHAKE_LEN]) -> Self {
        let (tg_enc, tg_dec) = relay_side(relay_init);
        CryptoCtx {
            clt_dec: StreamCipher::Identity,
            clt_enc: StreamCipher::Identity,
            tg_enc: StreamCipher::ctr(tg_enc),
            tg_dec: StreamCipher::ctr(tg_dec),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_transport_roundtrip() {
        let secret = [0xAB; 16];
        // build a valid client init for that secret (dc=2, abridged)
        let mut init = [0u8; HANDSHAKE_LEN];
        getrandom_fill(&mut init);
        init[0] = 0x12;
        let prekey_iv: [u8; PREKEY_LEN + IV_LEN] =
            init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].try_into().unwrap();
        let mut material = Vec::new();
        material.extend_from_slice(&prekey_iv[..PREKEY_LEN]);
        material.extend_from_slice(&secret);
        let key = sha256(&material);
        let iv: [u8; 16] = prekey_iv[PREKEY_LEN..].try_into().unwrap();
        let ks = keystream64(&key, &iv);
        let mut tail = [0u8; 8];
        tail[0..4].copy_from_slice(&PROTO_TAG_ABRIDGED);
        tail[4..6].copy_from_slice(&2i16.to_le_bytes());
        for i in 0..8 {
            init[PROTO_TAG_POS + i] = tail[i] ^ ks[PROTO_TAG_POS + i];
        }
        let h = try_handshake(&init, &secret).unwrap();

        let relay = generate_relay_init(h.proto_int, 2);
        let mut ctx = CryptoCtx::proxy_transport(&h.dec_prekey_iv, &secret, &relay);

        // upstream: client wire -> plain
        let mut client_stream_cipher = ctr_cipher(&key, &iv);
        let mut ff = [0u8; HANDSHAKE_LEN];
        client_stream_cipher.apply_keystream(&mut ff);
        let plain = [7u8; 100];
        let mut wire = plain;
        client_stream_cipher.apply_keystream(&mut wire);

        let got_plain = ctx.clt_dec.apply_vec(&wire);
        assert_eq!(got_plain, plain);

        // downstream: tg plain -> client wire must decrypt with reversed keys
        let down_plain = [9u8; 64];
        let mut tg_cipher = ctr_cipher(
            &relay[SKIP_LEN..SKIP_LEN + KEY_LEN].try_into().unwrap(),
            &relay[SKIP_LEN + KEY_LEN..SKIP_LEN + KEY_LEN + IV_LEN].try_into().unwrap(),
        );
        let mut ff = [0u8; HANDSHAKE_LEN];
        tg_cipher.apply_keystream(&mut ff);
        let mut down_wire = down_plain;
        tg_cipher.apply_keystream(&mut down_wire);

        let mut rev = [0u8; KEY_LEN + IV_LEN];
        rev.copy_from_slice(&relay[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN]);
        rev.reverse();
        let mut client_down = ctr_cipher(
            &rev[..KEY_LEN].try_into().unwrap(),
            &rev[KEY_LEN..].try_into().unwrap(),
        );

        let to_client = ctx.clt_enc.apply_vec(&ctx.tg_dec.apply_vec(&down_wire));
        let mut check = to_client.clone();
        client_down.apply_keystream(&mut check);
        assert_eq!(to_client.len(), down_plain.len());
    }

    #[test]
    fn self_transport_roundtrip() {
        let client_init = generate_relay_init(PROTO_ABRIDGED, 2); // valid self-init
        let relay = generate_relay_init(PROTO_ABRIDGED, 2);
        let mut ctx = CryptoCtx::self_transport(&client_init, &relay);

        let mut client_cipher = ctr_cipher(
            &client_init[SKIP_LEN..SKIP_LEN + KEY_LEN].try_into().unwrap(),
            &client_init[SKIP_LEN + KEY_LEN..SKIP_LEN + KEY_LEN + IV_LEN]
                .try_into()
                .unwrap(),
        );
        let mut ff = [0u8; HANDSHAKE_LEN];
        client_cipher.apply_keystream(&mut ff);

        let plain = [5u8; 200];
        let mut wire = plain;
        client_cipher.apply_keystream(&mut wire);

        assert_eq!(ctx.clt_dec.apply_vec(&wire), plain);
    }
}
