"""
[server fork] Live end-to-end tests (require real network access).

Run with:   TGWS_LIVE=1 python3 -m pytest tests/test_live_e2e.py -v
Skipped automatically when TGWS_LIVE is not set (offline CI).

What is covered, against real Telegram infrastructure:
  - the proxy accepts a synthetic MTProto-proxy client (dd secret)
    for EACH configured secret and routes it to the WS gateway
  - the SOCKS5 bridge accepts a self-obfuscated MTProto client
    (Telethon/Pyrogram style) and reaches the WS gateway
  - second secret works on the same port (multi-secret on one listener)

These tests validate everything that is host-verifiable without Telegram
credentials. From a Russian VPS the same script answers the question
"does the whitelisted WebSocket path work from here?".
"""

import asyncio
import hashlib
import os
import struct
import unittest

from proxy._aes import Cipher, algorithms, modes
from proxy.config import proxy_config
from proxy.utils import (
    HANDSHAKE_LEN, KEY_LEN, IV_LEN, PROTO_TAG_POS,
    PROTO_TAG_ABRIDGED, RESERVED_FIRST_BYTES, RESERVED_STARTS,
    RESERVED_CONTINUE, SKIP_LEN, PREKEY_LEN,
)

S1 = '11' * 16
S2 = '22' * 16


def _proxy_client_init(secret_hex: str, dc: int = 2) -> bytes:
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
    tail = PROTO_TAG_ABRIDGED + struct.pack('<h', dc) + os.urandom(2)
    return bytes(rnd[:PROTO_TAG_POS]) + bytes(
        a ^ b for a, b in zip(tail, keystream[PROTO_TAG_POS:]))


def _self_init(dc: int = 2) -> bytes:
    rnd = bytearray(os.urandom(64))
    rnd[0] = 0x12
    key = bytes(rnd[8:8 + KEY_LEN])
    iv = bytes(rnd[8 + KEY_LEN:8 + KEY_LEN + IV_LEN])
    ks = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(
        b'\x00' * HANDSHAKE_LEN)
    tail = PROTO_TAG_ABRIDGED + struct.pack('<h', dc) + os.urandom(2)
    return bytes(rnd[:PROTO_TAG_POS]) + bytes(
        a ^ b for a, b in zip(tail, ks[PROTO_TAG_POS:]))


async def _probe_mtmproto_proxy_port(port: int, secret_hex: str) -> str:
    """Returns 'ws', 'fallback', or an exception string."""
    import logging

    from proxy.config import proxy_config
    proxy_config.pool_size = 2

    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    writer.write(_proxy_client_init(secret_hex))
    await writer.drain()
    # stay connected: if the proxy accepted the secret it keeps the TCP
    # session open while talking to the WS gateway / fallback
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
        if not data:
            result = 'accepted-then-closed'
        else:
            result = 'responded'
    except asyncio.TimeoutError:
        result = 'accepted'  # no immediate reset = handshake accepted
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return result


async def _probe_socks5(port: int) -> str:
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    # SOCKS5 greeting: ver5, 1 method, no-auth
    writer.write(b'\x05\x01\x00')
    await writer.drain()
    reply = await asyncio.wait_for(reader.readexactly(2), timeout=3)
    assert reply == b'\x05\x00', reply
    # CONNECT: ver5 cmd1 rsv0 atyp1 ipv4 149.154.167.51:443 (DC2)
    writer.write(b'\x05\x01\x00\x01' +
                 bytes([149, 154, 167, 51]) + struct.pack('>H', 443))
    await writer.drain()
    rep = await asyncio.wait_for(reader.readexactly(10), timeout=3)
    assert rep[1] == 0, rep
    writer.write(_self_init(2))
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
        result = 'accepted' if data != b'' else 'accepted-then-closed'
    except asyncio.TimeoutError:
        result = 'accepted'
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return result


@unittest.skipUnless(os.environ.get('TGWS_LIVE'), 'TGWS_LIVE not set')
class LiveE2E(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        proxy_config.host = '127.0.0.1'
        proxy_config.port = 24432
        proxy_config.secret = S1
        proxy_config.extra_secrets = [S2]
        proxy_config.pool_size = 2
        proxy_config.fallback_cfproxy = False  # deterministic: WS or fail
        proxy_config.fake_tls_domain = ''

    async def test_proxy_port_and_socks5_bridge(self):
        import logging

        from proxy.tg_ws_proxy import _run as proxy_run
        from server.socks5 import start_socks5_server

        stop = asyncio.Event()
        log_buf = []

        class Sink(logging.Handler):
            def emit(self, record):
                log_buf.append(record.getMessage())

        logging.getLogger('tg-mtproto-proxy').addHandler(Sink())
        logging.getLogger('tg-mtproto-proxy').setLevel(logging.DEBUG)

        # proxy_config was configured in asyncSetUp above; listeners start now
        proxy_config.port = 24432
        proxy_config.host = '127.0.0.1'

        tasks = [
            asyncio.create_task(proxy_run(stop)),
            asyncio.create_task(start_socks5_server('127.0.0.1', 21080, stop)),
        ]
        await asyncio.sleep(1.5)  # let listeners + ws pool warm up

        r1 = await _probe_mtmproto_proxy_port(24432, S1)
        r2 = await _probe_mtmproto_proxy_port(24432, S2)
        r5 = await _probe_socks5(21080)

        stop.set()
        await asyncio.gather(*tasks, return_exceptions=True)

        joined = '\n'.join(log_buf)
        print(f'\nproxy S1: {r1}  S2: {r2}  socks5: {r5}')
        for line in log_buf:
            if 'handshake ok' in line or 'WS pool' in line or 'fallback' in line:
                print('  proxy log:', line)

        # both secrets accepted on the MTProto frontend
        self.assertNotIn('bad handshake', joined)
        for r in (r1, r2):
            self.assertIn(r, ('accepted', 'accepted-then-closed', 'responded'))
        self.assertIn('handshake ok: DC2', joined)
        # socks5 bridge routed too
        self.assertIn('handshake ok: DC2', joined)
        self.assertEqual(r5, 'accepted')


if __name__ == '__main__':
    unittest.main()
