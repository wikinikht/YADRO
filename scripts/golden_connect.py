"""Golden e2e: real Telethon connect() through tg-ws-proxy-server.

Routes tested:
  1. native MTProto proxy frontend (dd secret) via
     ConnectionTcpMTProxyRandomizedIntermediate
  2. SOCKS5 bridge via ConnectionTcpAbridged (Pyrogram-style route)
connect() performs a full MTProto handshake (req_pq -> resPQ -> DH) —
if it succeeds, the tunnel carries real Telegram traffic.
"""
import asyncio, os, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)

from proxy.config import proxy_config
from server.config_loader import setup_logging

SECRET = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
PORT, S5PORT = 24433, 21085

async def main():
    from telethon import TelegramClient, connection
    from server.socks5 import start_socks5_server
    from proxy.tg_ws_proxy import _run as proxy_run

    proxy_config.host = '127.0.0.1'
    proxy_config.port = PORT
    proxy_config.secret = SECRET
    proxy_config.extra_secrets = []
    proxy_config.pool_size = 2
    proxy_config.fake_tls_domain = ''
    setup_logging({'verbose': False, 'log_file': '', 'log_max_mb': 5, 'log_backups': 1})
    stop = asyncio.Event()
    tasks = [asyncio.create_task(proxy_run(stop)),
             asyncio.create_task(start_socks5_server('127.0.0.1', S5PORT, stop))]
    await asyncio.sleep(1.5)

    results = {}

    t0 = time.monotonic()
    try:
        c = TelegramClient(
            'golden1', 1, 'x',
            proxy=('127.0.0.1', PORT, 'dd' + SECRET),
            connection=connection.ConnectionTcpMTProxyRandomizedIntermediate)
        await c.connect()
        results['mtproto-proxy frontend (dd)'] = \
            f'OK in {time.monotonic()-t0:.1f}s (authorized={await c.is_user_authorized()})'
        await c.disconnect()
    except Exception as e:
        results['mtproto-proxy frontend (dd)'] = f'FAIL: {type(e).__name__}: {e}'

    t0 = time.monotonic()
    try:
        c = TelegramClient(
            'golden2', 1, 'x',
            proxy=('socks5', '127.0.0.1', S5PORT),
            connection=connection.ConnectionTcpAbridged)
        await c.connect()
        results['socks5 bridge (abridged)'] = \
            f'OK in {time.monotonic()-t0:.1f}s'
        await c.disconnect()
    except Exception as e:
        results['socks5 bridge (abridged)'] = f'FAIL: {type(e).__name__}: {e}'


    t0 = time.monotonic()
    try:
        c = TelegramClient(
            'golden3', 1, 'x',
            proxy=('socks5', '127.0.0.1', S5PORT),
            connection=connection.ConnectionTcpObfuscated)  # Pyrogram-style: always obfuscated
        await c.connect()
        results['socks5 bridge (obfuscated, pyrogram-style)'] = \
            f'OK in {time.monotonic()-t0:.1f}s'
        await c.disconnect()
    except Exception as e:
        results['socks5 bridge (obfuscated, pyrogram-style)'] = f'FAIL: {type(e).__name__}: {e}'

    stop.set()
    await asyncio.gather(*tasks, return_exceptions=True)
    print('\n=== GOLDEN CONNECT RESULTS ===')
    for k, v in results.items():
        print(f'  {k}: {v}')
    return all('OK' in v for v in results.values())

if __name__ == '__main__':
    sys.exit(0 if asyncio.run(main()) else 1)
