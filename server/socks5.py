"""
[server fork] SOCKS5 bridge — transparent MTProto-over-WebSocket tunnel
for MTProto client libraries that only understand plain SOCKS5 proxies
(Pyrogram, kurigram, some Telethon setups, GramJS etc.).

How it works
------------
The client (bot) connects with a regular SOCKS5 CONNECT to this bridge
(127.0.0.1:1080 by default) and immediately speaks its own self-obfuscated
MTProto transport (the 64-byte obfuscation init contains the AES-CTR key
material — no proxy secret involved).

The bridge:
  1. parses the client's obfuscation init and extracts the transport tag
     and target DC id;
  2. builds a fresh obfuscation init towards Telegram (same as the
     MTProto-proxy frontend does) and opens a TLS WebSocket to
     kws<dc>.web.telegram.org (pinned to the whitelisted DC IP);
  3. re-encrypts client <-> WebSocket bidirectionally, splitting the
     stream into MTProto packets per transport framing (MsgSplitter).

From the client's point of view it is indistinguishable from a direct
connection to the Telegram DC; from the network's point of view the
traffic is a normal TLS WebSocket session to Telegram's web gateway.

NOTE: the client library must use an MTProto transport supported by the
WS gateway: ABRIDGED (0xEFEFEFEF), INTERMEDIATE (0xEEEEEEEE) or PADDED
INTERMEDIATE (0xDDDDDDDD). Telethon: use `connection=ConnectionTcpAbridged`
(or prefer the native MTProto-proxy mode instead of SOCKS5). Pyrogram uses
TCP Abridged by default and works as is.
"""

import asyncio
import logging
import os
import struct

from typing import Optional, Tuple

from proxy._aes import Cipher, algorithms, modes
from proxy.bridge import CryptoCtx, MsgSplitter, do_fallback
from proxy.config import proxy_config
from proxy.raw_websocket import set_sock_opts
from proxy.stats import stats
from proxy.utils import (
    DC_DEFAULT_IPS,
    DC_TEST_IPS,
    HANDSHAKE_LEN,
    PREKEY_LEN,
    IV_LEN,
    KEY_LEN,
    PROTO_TAG_ABRIDGED,
    PROTO_TAG_INTERMEDIATE,
    PROTO_TAG_SECURE,
    PROTO_TAG_POS,
    DC_IDX_POS,
    PROTO_ABRIDGED_INT,
    PROTO_INTERMEDIATE_INT,
    PROTO_PADDED_INTERMEDIATE_INT,
    RESERVED_FIRST_BYTES,
    RESERVED_STARTS,
    ZERO_64,
)
from proxy.tg_ws_proxy import _generate_relay_init

try:
    from proxy.tg_ws_proxy import cf_h2_pool  # shared media H2 pool
except Exception:  # pragma: no cover
    cf_h2_pool = None

log = logging.getLogger('tg-mtproto-proxy')

SOCKS_VER = 5
NO_AUTH = 0x00
NO_ACCEPTABLE = 0xFF
CMD_CONNECT = 0x01
REP_OK = 0x00
REP_GENERAL_FAIL = 0x01
REP_NOT_ALLOWED = 0x02
REP_TTL = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

PROTO_TAG_TO_INT = {
    PROTO_TAG_ABRIDGED: PROTO_ABRIDGED_INT,
    PROTO_TAG_INTERMEDIATE: PROTO_INTERMEDIATE_INT,
    PROTO_TAG_SECURE: PROTO_PADDED_INTERMEDIATE_INT,
}

_st_H_le = struct.Struct('<h')


class Socks5Error(Exception):
    def __init__(self, rep: int, message: str = ''):
        self.rep = rep
        super().__init__(message or f'SOCKS5 error {rep}')


def parse_self_obfuscated_init(init: bytes) -> Optional[Tuple[int, int]]:
    """Parse a plain (non-proxy-secret) MTProto obfuscated transport init.

    Returns (proto_int, dc_idx_signed) or None if the init is not a
    supported MTProto transport stream.
    """
    if len(init) < HANDSHAKE_LEN:
        return None

    up_key = init[8:8 + KEY_LEN]
    up_iv = init[8 + KEY_LEN:8 + KEY_LEN + IV_LEN]
    keystream = Cipher(
        algorithms.AES(up_key), modes.CTR(up_iv)
    ).encryptor().update(b'\x00' * HANDSHAKE_LEN)

    tail = bytes(a ^ b for a, b in zip(init[PROTO_TAG_POS:], keystream[PROTO_TAG_POS:]))
    proto_tag = tail[:4]
    proto_int = PROTO_TAG_TO_INT.get(proto_tag)
    if proto_int is None:
        return None

    dc_idx = _st_H_le.unpack_from(tail, 4)[0]
    return proto_int, dc_idx


def build_bridge_ctx(client_init: bytes, proto_tag: bytes, dc_idx: int) -> Tuple[CryptoCtx, bytes]:
    """Build the re-encryption context for the SOCKS5 bridge.

    The client speaks a self-obfuscated transport (key material lives in
    its own init), the Telegram side gets a freshly generated obfuscation
    init — exactly like the MTProto-proxy frontend but without the
    SHA256(secret) layer.
    """
    clt_dec = Cipher(
        algorithms.AES(client_init[8:8 + KEY_LEN]),
        modes.CTR(client_init[8 + KEY_LEN:8 + KEY_LEN + IV_LEN]),
    ).encryptor()
    clt_dec.update(ZERO_64)

    clt_enc_prekey_iv = client_init[8:8 + KEY_LEN + IV_LEN][::-1]
    clt_enc = Cipher(
        algorithms.AES(clt_enc_prekey_iv[:KEY_LEN]),
        modes.CTR(clt_enc_prekey_iv[KEY_LEN:]),
    ).encryptor()

    relay_init = _generate_relay_init(proto_tag, dc_idx)

    tg_enc = Cipher(
        algorithms.AES(relay_init[8:8 + KEY_LEN]),
        modes.CTR(relay_init[8 + KEY_LEN:8 + KEY_LEN + IV_LEN]),
    ).encryptor()
    tg_enc.update(ZERO_64)

    tg_dec_prekey_iv = relay_init[8:8 + KEY_LEN + IV_LEN][::-1]
    tg_dec = Cipher(
        algorithms.AES(tg_dec_prekey_iv[:KEY_LEN]),
        modes.CTR(tg_dec_prekey_iv[KEY_LEN:]),
    ).encryptor()

    return CryptoCtx(clt_dec, clt_enc, tg_enc, tg_dec), relay_init


async def _read_socks5_greeting(reader, writer) -> None:
    """Greeting + method selection reply (sent immediately)."""
    header = await asyncio.wait_for(reader.readexactly(2), timeout=15)
    ver, nmethods = header[0], header[1]
    if ver != SOCKS_VER:
        raise Socks5Error(REP_GENERAL_FAIL, f'unsupported SOCKS ver {ver}')
    methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=15)
    if NO_AUTH not in methods:
        writer.write(bytes([SOCKS_VER, NO_ACCEPTABLE]))
        await writer.drain()
        raise Socks5Error(REP_GENERAL_FAIL, 'client does not support no-auth')
    writer.write(bytes([SOCKS_VER, NO_AUTH]))
    await writer.drain()


async def _read_socks5_connect(reader) -> Tuple[str, int]:
    """CONNECT request. Returns (target, port)."""
    req = await asyncio.wait_for(reader.readexactly(4), timeout=15)
    ver, cmd, _, atyp = req
    if ver != SOCKS_VER or cmd != CMD_CONNECT:
        raise Socks5Error(REP_CMD_NOT_SUPPORTED, f'cmd {cmd} not supported')

    if atyp == 1:  # IPv4
        raw = await asyncio.wait_for(reader.readexactly(6), timeout=15)
        target = '.'.join(str(b) for b in raw[:4])
        port = int.from_bytes(raw[4:6], 'big')
    elif atyp == 3:  # domain
        dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=15))[0]
        raw = await asyncio.wait_for(reader.readexactly(1 + dlen + 2), timeout=15)
        target = raw[:dlen].decode('idna', errors='replace')
        port = int.from_bytes(raw[dlen:dlen + 2], 'big')
    elif atyp == 4:  # IPv6
        raw = await asyncio.wait_for(reader.readexactly(18), timeout=15)
        target = raw[:16].hex(':')
        port = int.from_bytes(raw[16:18], 'big')
    else:
        raise Socks5Error(REP_ATYP_NOT_SUPPORTED, f'atyp {atyp} not supported')

    return target, port


def _write_socks5_reply(writer, rep: int):
    writer.write(bytes([SOCKS_VER, rep, 0, 1]) + b'\x00' * 6)


def _infer_dc(target: str) -> int:
    ip_table = {**DC_TEST_IPS, **DC_DEFAULT_IPS}
    for dc, ip in ip_table.items():
        if ip == target:
            return dc
    for dc, ip in proxy_config.dc_redirects.items():
        if ip == target:
            return dc
    return 0


class _IdentityCipher:
    """Passthrough for unobfuscated (plain) client transports."""

    __slots__ = ()

    def update(self, data: bytes) -> bytes:
        return data


_PLAIN_TAG_ABRIDGED = b'\xef'
_PLAIN_TAG_INTERMEDIATE = b'\xee\xee\xee\xee'


async def _read_client_stream_head(reader) -> Tuple[Optional[bytes], bytes, int]:
    """Sniff the first bytes of the client MTProto stream.

    Returns (obfuscated_init_or_None, proto_tag, consumed_proto_len):
      - Telethon plain ConnectionTcpAbridged sends a single 0xEF marker
        followed by plaintext packets (no obfuscation at all);
      - plain intermediate sends the 4-byte 0xEEEEEEEE tag;
      - everything else must be a 64-byte self-obfuscated init
        (Pyrogram always obfuscates, Telethon ConnectionTcpObfuscated).
    """
    first = await asyncio.wait_for(reader.readexactly(1), timeout=15)
    if first == _PLAIN_TAG_ABRIDGED:
        return None, PROTO_TAG_ABRIDGED, 1
    if first == b'\xee':
        rest = await asyncio.wait_for(reader.readexactly(3), timeout=15)
        if first + rest == _PLAIN_TAG_INTERMEDIATE:
            return None, PROTO_TAG_INTERMEDIATE, 4
        raise ValueError('unknown transport tag 0xEE...')
    init = first + await asyncio.wait_for(
        reader.readexactly(HANDSHAKE_LEN - 1), timeout=15)
    return init, b'', 0


async def handle_socks5_client(reader, writer):
    stats.connections_total += 1
    stats.connections_active += 1
    peer = writer.get_extra_info('peername')
    label = f'socks5:{peer[0]}:{peer[1]}' if peer else 'socks5:?'

    set_sock_opts(writer.transport, proxy_config.buffer_size)

    try:
        try:
            await _read_socks5_greeting(reader, writer)
            target, port = await _read_socks5_connect(reader)
        except Socks5Error as exc:
            log.debug('[%s] %s', label, exc)
            _write_socks5_reply(
                writer, exc.rep if exc.rep in (REP_GENERAL_FAIL, REP_NOT_ALLOWED,
                                              REP_TTL, REP_CMD_NOT_SUPPORTED,
                                              REP_ATYP_NOT_SUPPORTED)
                else REP_GENERAL_FAIL)
            return

        # tunnel is "established" from the client's point of view
        _write_socks5_reply(writer, REP_OK)
        try:
            await writer.drain()
        except (ConnectionError, OSError):
            return

        try:
            init, plain_tag, _consumed = await _read_client_stream_head(reader)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError) as exc:
            stats.connections_bad += 1
            log.warning('[%s] unsupported client stream: %s', label, exc)
            return

        if init is not None:
            parsed = parse_self_obfuscated_init(init)
            if parsed is None:
                stats.connections_bad += 1
                log.warning(
                    '[%s] unsupported MTProto transport from client '
                    '(need ABRIDGED/INTERMEDIATE/PADDED, e.g. '
                    'Telethon ConnectionTcpAbridged)', label)
                return
            proto_int, init_dc_idx = parsed
            proto_tag = next(t for t, i in PROTO_TAG_TO_INT.items()
                             if i == proto_int)
            plain_mode = False
        else:
            # plain (unobfuscated) Telethon-style transport
            proto_tag = plain_tag
            proto_int = PROTO_TAG_TO_INT[proto_tag]
            init_dc_idx = 0
            plain_mode = True

        # Plain self-obfuscated transports (Telethon/Pyrogram via SOCKS5)
        # do NOT carry the DC id in the init (bytes 60:62 are random),
        # so the SOCKS5 CONNECT target is the authoritative source.
        dc_idx = _infer_dc(target)
        if dc_idx == 0:
            dc_idx = init_dc_idx
        is_media = dc_idx < 0
        dc = abs(dc_idx)
        if dc == 0:
            stats.connections_bad += 1
            log.warning('[%s] cannot determine DC (target %s, init dc=%d)',
                        label, target, init_dc_idx)
            return

        is_test_dc = proxy_config.force_test_dc or dc >= 10000
        if dc >= 10000:
            dc -= 10000
        dc_idx = -dc if is_media else dc

        log.info('[%s] handshake ok: DC%d%s proto=0x%08X target=%s%s',
                 label, dc, ' media' if is_media else '', proto_int, target,
                 ' plain' if plain_mode else '')

        if plain_mode:
            ctx = CryptoCtx(_IdentityCipher(), _IdentityCipher(),
                            _IdentityCipher(), _IdentityCipher())
            # relay init must still be a valid obfuscated init for the DC
            from proxy.tg_ws_proxy import _generate_relay_init as _gen
            relay_init = _gen(proto_tag, dc_idx)
            # tg side of ctx must encrypt/decrypt with relay_init keys,
            # so replace the identity placeholders for the telegram side
            ctx.tg_enc = Cipher(
                algorithms.AES(relay_init[8:8 + KEY_LEN]),
                modes.CTR(relay_init[8 + KEY_LEN:8 + KEY_LEN + IV_LEN]),
            ).encryptor()
            ctx.tg_enc.update(ZERO_64)
            tg_dec_prekey_iv = relay_init[8:8 + KEY_LEN + IV_LEN][::-1]
            ctx.tg_dec = Cipher(
                algorithms.AES(tg_dec_prekey_iv[:KEY_LEN]),
                modes.CTR(tg_dec_prekey_iv[KEY_LEN:]),
            ).encryptor()
        else:
            ctx, relay_init = build_bridge_ctx(init, proto_tag, dc_idx)

        from proxy.pool import ws_pool  # late import: shared singleton

        splitter = None
        try:
            splitter = MsgSplitter(proto_int)
        except Exception:
            pass

        media_tag = ' media' if is_media else ''
        ws = await ws_pool.get(dc, is_media, is_test_dc=is_test_dc)
        if ws is not None:
            log.info('[%s] DC%d%s -> WS pool hit', label, dc, media_tag)
            stats.connections_ws += 1
            await ws.send(relay_init)
            from proxy.bridge import bridge_ws_reencrypt
            await bridge_ws_reencrypt(reader, writer, ws, label, ctx,
                                      dc=dc, is_media=is_media,
                                      splitter=splitter)
        else:
            log.info('[%s] DC%d%s WS pool unavailable -> fallback', label, dc, media_tag)
            await do_fallback(
                reader, writer, relay_init, label,
                dc, is_test_dc, is_media, media_tag,
                ctx, splitter=splitter, h2_pool=cf_h2_pool, proto_tag=proto_tag)

    except asyncio.TimeoutError:
        log.debug('[%s] timeout', label)
    except (ConnectionError, OSError, asyncio.IncompleteReadError):
        log.debug('[%s] connection closed', label)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.error('[%s] unexpected: %s', label, exc, exc_info=True)
    finally:
        stats.connections_active -= 1
        try:
            writer.close()
            await writer.wait_closed()
        except BaseException:
            pass


async def start_socks5_server(host: str, port: int,
                              stop_event: Optional[asyncio.Event] = None):
    """Run the SOCKS5 bridge listener until stop_event is set."""
    server = await asyncio.start_server(handle_socks5_client, host, port)
    for sock in server.sockets:
        try:
            sock.setsockopt(__import__('socket').IPPROTO_TCP,
                            __import__('socket').TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

    log.info('=' * 60)
    log.info('  SOCKS5 bridge listening on %s:%d', host, port)
    log.info('  Use with Pyrogram/Telethon as socks5://%s:%d', host, port)
    log.info('=' * 60)

    stop_task = (asyncio.create_task(stop_event.wait())
                 if stop_event is not None else None)
    try:
        if stop_task is not None:
            await asyncio.wait(
                [asyncio.create_task(server.serve_forever()), stop_task],
                return_when=asyncio.FIRST_COMPLETED)
            server.close()
            await server.wait_closed()
        else:
            await server.serve_forever()
    finally:
        if stop_task is not None:
            stop_task.cancel()
        if not server.is_serving():
            return
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass
