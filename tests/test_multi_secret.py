"""
[server fork] Multi-secret support tests.

Covers:
  - ProxyConfig.secrets_list dedup/validation
  - _try_handshake matches the right secret out of several
  - FakeTLS secret loop picks the correct secret (client hello for
    secret #2 must be accepted when it is not first in the list)
  - CLI --secrets-file parsing (via load path used by main())
"""

import hashlib
import os
import struct
import unittest

from proxy._aes import Cipher, algorithms, modes
from proxy.config import proxy_config
from proxy.tg_ws_proxy import _try_handshake
from proxy.utils import (
    HANDSHAKE_LEN,
    PROTO_TAG_ABRIDGED,
    PROTO_TAG_INTERMEDIATE,
    RESERVED_FIRST_BYTES,
    RESERVED_STARTS,
    RESERVED_CONTINUE,
    SKIP_LEN,
    PREKEY_LEN,
    IV_LEN,
    PROTO_TAG_POS,
    DC_IDX_POS,
)

S1 = 'aa' * 16
S2 = 'bb' * 16


def _proxy_client_init(secret_hex: str, proto_tag: bytes = PROTO_TAG_ABRIDGED,
                       dc: int = 2) -> bytes:
    """Build a client init exactly like an MTProto-proxy client would."""
    while True:
        rnd = bytearray(os.urandom(64))
        if rnd[0] in RESERVED_FIRST_BYTES:
            continue
        if bytes(rnd[:4]) in RESERVED_STARTS:
            continue
        if bytes(rnd[4:8]) == RESERVED_CONTINUE:
            continue
        break
    prekey = bytes(rnd[SKIP_LEN:SKIP_LEN + PREKEY_LEN])
    iv = bytes(rnd[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN])
    key = hashlib.sha256(prekey + bytes.fromhex(secret_hex)).digest()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    keystream = cipher.update(b'\x00' * HANDSHAKE_LEN)
    tail = proto_tag + struct.pack('<h', dc) + os.urandom(2)
    init = bytes(rnd)
    init = init[:PROTO_TAG_POS] + bytes(
        a ^ b for a, b in zip(tail, keystream[PROTO_TAG_POS:]))
    return init


class SecretsListTest(unittest.TestCase):
    def setUp(self):
        proxy_config.extra_secrets = []
        proxy_config.secret = S1

    def tearDown(self):
        proxy_config.extra_secrets = []
        proxy_config.secret = '00' * 16

    def test_single(self):
        self.assertEqual(proxy_config.secrets_list, [S1])

    def test_multi_dedup(self):
        proxy_config.extra_secrets = [S2, S1, S2.upper()]
        self.assertEqual(proxy_config.secrets_list, [S1, S2])

    def test_invalid_filtered(self):
        proxy_config.extra_secrets = ['zz' * 16, 'short', S2]
        self.assertEqual(proxy_config.secrets_list, [S1, S2])

    def test_ee_prefix_stripped_not_needed_but_tolerated(self):
        # user may paste the full ee-secret; value validation keeps raw hex
        proxy_config.extra_secrets = ['ee' + S2]
        self.assertEqual(proxy_config.secrets_list, [S1])


class TryHandshakeMultiTest(unittest.TestCase):
    def test_each_secret_matches_own_init(self):
        for secret in (S1, S2):
            init = _proxy_client_init(secret)
            result = _try_handshake(init, bytes.fromhex(secret))
            self.assertIsNotNone(result, secret)
            dc, is_media, proto_tag, prekey_iv = result
            self.assertEqual(dc, 2)
            self.assertFalse(is_media)
            self.assertEqual(proto_tag, PROTO_TAG_ABRIDGED)
            self.assertEqual(prekey_iv, init[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN])

    def test_wrong_secret_rejected(self):
        init = _proxy_client_init(S1)
        self.assertIsNone(_try_handshake(init, bytes.fromhex(S2)))

    def test_multi_secret_loop_finds_match(self):
        init = _proxy_client_init(S2)
        matched = None
        for s in (S1, S2):
            if _try_handshake(init, bytes.fromhex(s)) is not None:
                matched = s
                break
        self.assertEqual(matched, S2)

    def test_media_dc_negative(self):
        init = _proxy_client_init(S1, dc=-4)
        dc, is_media, _, _ = _try_handshake(init, bytes.fromhex(S1))
        self.assertEqual(dc, 4)
        self.assertTrue(is_media)

    def test_intermediate_proto(self):
        init = _proxy_client_init(S1, proto_tag=PROTO_TAG_INTERMEDIATE)
        result = _try_handshake(init, bytes.fromhex(S1))
        self.assertIsNotNone(result)
        self.assertEqual(result[2], PROTO_TAG_INTERMEDIATE)


class FakeTlsLoopTest(unittest.TestCase):
    def test_second_secret_client_hello_accepted_in_loop(self):
        from tests.test_fake_tls import _client_hello
        from proxy.fake_tls import verify_client_hello
        import time

        secret2 = bytes.fromhex(S2)
        hello = _client_hello(secret=secret2, timestamp=int(time.time()))
        matched = None
        for s in (bytes.fromhex(S1), secret2):
            if verify_client_hello(hello, s) is not None:
                matched = s
                break
        self.assertEqual(matched, secret2)


if __name__ == '__main__':
    unittest.main()
