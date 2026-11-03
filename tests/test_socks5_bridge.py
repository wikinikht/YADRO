"""
[server fork] SOCKS5 bridge unit tests (offline, no network).

Covers:
  - parse_self_obfuscated_init roundtrip (abridged/intermediate, dc, media)
  - build_bridge_ctx crypto roundtrips
    (client-transport stream decrypts; downstream re-encrypts to the
     client's reversed keys; relay init is a valid self-obfuscated init)
"""

import os
import struct
import unittest

from proxy._aes import Cipher, algorithms, modes
from proxy.utils import (
    HANDSHAKE_LEN, KEY_LEN, IV_LEN, PROTO_TAG_POS, DC_IDX_POS,
    PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE,
    PROTO_ABRIDGED_INT, PROTO_INTERMEDIATE_INT, PROTO_PADDED_INTERMEDIATE_INT,
)

from server.socks5 import (
    parse_self_obfuscated_init,
    build_bridge_ctx,
    Socks5Error,
    _infer_dc,
)


def _self_init(proto_tag: bytes, dc: int) -> bytes:
    """Client-side self-obfuscated transport init (plain dc-transport)."""
    while True:
        rnd = bytearray(os.urandom(64))
        if rnd[0] == 0xEF:
            continue
        if bytes(rnd[:4]) in (b'\x48\x45\x41\x44', b'\x50\x4F\x53\x54',
                              b'\x47\x45\x54\x20', b'\xee\xee\xee\xee',
                              b'\xdd\xdd\xdd\xdd', b'\x16\x03\x01\x02',
                              b'\x4F\x50\x54\x49'):
            continue
        break
    key = bytes(rnd[8:8 + KEY_LEN])
    iv = bytes(rnd[8 + KEY_LEN:8 + KEY_LEN + IV_LEN])
    ks = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(
        b'\x00' * HANDSHAKE_LEN)
    tail = proto_tag + struct.pack('<h', dc) + os.urandom(2)
    init = bytes(rnd[:PROTO_TAG_POS]) + bytes(
        a ^ b for a, b in zip(tail, ks[PROTO_TAG_POS:]))
    return init


class ParseInitTest(unittest.TestCase):
    def test_abridged_dc2(self):
        init = _self_init(PROTO_TAG_ABRIDGED, 2)
        parsed = parse_self_obfuscated_init(init)
        self.assertIsNotNone(parsed)
        proto_int, dc_idx = parsed
        self.assertEqual(proto_int, PROTO_ABRIDGED_INT)
        self.assertEqual(dc_idx, 2)

    def test_intermediate_dc4_media(self):
        init = _self_init(PROTO_TAG_INTERMEDIATE, -4)
        proto_int, dc_idx = parse_self_obfuscated_init(init)
        self.assertEqual(proto_int, PROTO_INTERMEDIATE_INT)
        self.assertEqual(dc_idx, -4)

    def test_padded(self):
        init = _self_init(PROTO_TAG_SECURE, 5)
        proto_int, dc_idx = parse_self_obfuscated_init(init)
        self.assertEqual(proto_int, PROTO_PADDED_INTERMEDIATE_INT)
        self.assertEqual(dc_idx, 5)

    def test_garbage_rejected(self):
        self.assertIsNone(parse_self_obfuscated_init(os.urandom(64)))
        self.assertIsNone(parse_self_obfuscated_init(b'\x00' * 64))
        # HEAD / HTTP start -> not an MTProto transport
        junk = bytearray(os.urandom(64))
        junk[0:4] = b'HEAD'
        self.assertIsNone(parse_self_obfuscated_init(bytes(junk)))


class BridgeCtxTest(unittest.TestCase):
    def test_roundtrip_upstream(self):
        """client payload stream must decrypt with ctx.clt_dec."""
        init = _self_init(PROTO_TAG_ABRIDGED, 2)
        key = init[8:8 + KEY_LEN]
        iv = init[8 + KEY_LEN:8 + KEY_LEN + IV_LEN]
        payload_cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        payload_cipher.update(b'\x00' * HANDSHAKE_LEN)  # consume init bytes
        plain = os.urandom(300)
        wire = payload_cipher.update(plain)

        ctx, relay_init = build_bridge_ctx(init, PROTO_TAG_ABRIDGED, 2)
        self.assertEqual(len(relay_init), HANDSHAKE_LEN)
        self.assertEqual(ctx.clt_dec.update(wire), plain)

    def test_downstream_reaches_client(self):
        """WS->client data must decrypt with the client's reversed keys."""
        init = _self_init(PROTO_TAG_ABRIDGED, 2)
        ctx, _ = build_bridge_ctx(init, PROTO_TAG_ABRIDGED, 2)

        plain = os.urandom(256)
        downstream = ctx.clt_enc.update(plain)

        rev = init[8:8 + KEY_LEN + IV_LEN][::-1]
        client_down_cipher = Cipher(
            algorithms.AES(rev[:KEY_LEN]), modes.CTR(rev[KEY_LEN:])
        ).encryptor()
        self.assertEqual(client_down_cipher.update(downstream), plain)

    def test_relay_init_is_valid_self_init(self):
        """relay init must parse back like a client init to the same dc."""
        from server.socks5 import parse_self_obfuscated_init
        from proxy.utils import PROTO_TAG_SECURE
        init = _self_init(PROTO_TAG_SECURE, 3)
        ctx, relay_init = build_bridge_ctx(init, PROTO_TAG_SECURE, 3)
        proto_int, dc_idx = parse_self_obfuscated_init(relay_init)
        self.assertEqual(proto_int, PROTO_PADDED_INTERMEDIATE_INT)
        self.assertEqual(dc_idx, 3)


class InferDcTest(unittest.TestCase):
    def test_known_ip(self):
        self.assertEqual(_infer_dc('149.154.167.51'), 2)
        self.assertEqual(_infer_dc('149.154.175.50'), 1)

    def test_unknown_ip(self):
        self.assertEqual(_infer_dc('8.8.8.8'), 0)


if __name__ == '__main__':
    unittest.main()
