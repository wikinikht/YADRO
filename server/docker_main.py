"""
[server fork] Docker entrypoint: MTProto proxy + SOCKS5 bridge in one loop.

Env vars (same names as upstream Dockerfile, plus new ones):
  TG_WS_PROXY_HOST       listen host (default 0.0.0.0)
  TG_WS_PROXY_PORT       proxy port (default 1443)
  TG_WS_PROXY_SECRET     primary secret (random if empty)
  TG_WS_PROXY_SECRETS    extra secrets, whitespace-separated ([fork])
  TG_WS_PROXY_DC_IPS     "DC:IP" pairs, whitespace-separated
  TG_WS_PROXY_CF_WORKER  CF worker domain (optional)
  TG_WS_PROXY_NO_SECURE  True/False
  TG_WS_PROXY_FTLS_DOMAIN FakeTLS masking domain for ee-secrets ([fork])
  TG_WS_PROXY_SOCKS5_ENABLED  True/False ([fork])
  TG_WS_PROXY_SOCKS5_HOST     default 0.0.0.0 ([fork])
  TG_WS_PROXY_SOCKS5_PORT     default 1080 ([fork])
"""

import asyncio
import logging
import os
import signal

from proxy.config import proxy_config, parse_dc_ip_list
from proxy.stats import stats
from server.config_loader import setup_logging

log = logging.getLogger('tg-mtproto-proxy')


def _env_bool(name: str, default: bool) -> bool:
    return str(os.environ.get(name, str(default))).strip().lower() in (
        '1', 'true', 'yes', 'on')


def apply_env() -> None:
    proxy_config.host = os.environ.get('TG_WS_PROXY_HOST', '0.0.0.0')
    proxy_config.port = int(os.environ.get('TG_WS_PROXY_PORT', '1443'))

    secrets = [s for s in os.environ.get('TG_WS_PROXY_SECRET', '').split()
               if s]
    secrets += [s for s in os.environ.get('TG_WS_PROXY_SECRETS', '').split()
                if s]
    if secrets:
        proxy_config.secret = secrets[0]
        proxy_config.extra_secrets = secrets[1:]
    # else: proxy_config defaults to a random secret

    dc_ips = os.environ.get('TG_WS_PROXY_DC_IPS', '').split()
    if dc_ips:
        proxy_config.dc_redirects = parse_dc_ip_list(dc_ips)

    worker = os.environ.get('TG_WS_PROXY_CF_WORKER', '').strip()
    if worker:
        proxy_config.cfproxy_worker_domains = [worker]

    proxy_config.disable_secure = _env_bool('TG_WS_PROXY_NO_SECURE', False)
    proxy_config.fake_tls_domain = os.environ.get(
        'TG_WS_PROXY_FTLS_DOMAIN', '').strip()


async def main() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    from proxy.utils import DomainCensorFilter
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s  %(levelname)-5s  %(message)s', datefmt='%H:%M:%S'))
    handler.addFilter(DomainCensorFilter())
    root.addHandler(handler)
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    apply_env()

    from proxy.tg_ws_proxy import _run as proxy_run
    from server.socks5 import start_socks5_server

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            pass

    tasks = [asyncio.create_task(proxy_run(stop_event))]
    if _env_bool('TG_WS_PROXY_SOCKS5_ENABLED', True):
        tasks.append(asyncio.create_task(start_socks5_server(
            os.environ.get('TG_WS_PROXY_SOCKS5_HOST', '0.0.0.0'),
            int(os.environ.get('TG_WS_PROXY_SOCKS5_PORT', '1080')),
            stop_event)))

    done, pending = await asyncio.wait(
        tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in done:
        if t.exception() is not None:
            log.error('Component failed: %r', t.exception())
    stop_event.set()
    await asyncio.gather(*tasks, return_exceptions=True)
    log.info('Final stats: %s', stats.summary())


if __name__ == '__main__':
    asyncio.run(main())
