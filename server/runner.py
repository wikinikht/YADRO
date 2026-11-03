"""
[server fork] Runner — applies a YAML config and runs the MTProto proxy
plus the optional SOCKS5 bridge in a single asyncio loop with clean
SIGINT/SIGTERM handling (systemd friendly).
"""

import asyncio
import logging
import signal

from typing import Optional

from proxy import tg_ws_proxy
from proxy.stats import stats

log = logging.getLogger('tg-mtproto-proxy')


async def _run_all(cfg: dict, stop_event: asyncio.Event) -> None:
    s5 = cfg.get('socks5') or {}
    tasks = [asyncio.create_task(tg_ws_proxy._run(stop_event))]
    if s5.get('enabled'):
        from server.socks5 import start_socks5_server
        tasks.append(asyncio.create_task(start_socks5_server(
            s5.get('host', '127.0.0.1'), int(s5.get('port', 1080)),
            stop_event)))

    stop_task = asyncio.create_task(stop_event.wait())
    done, pending = await asyncio.wait(
        [*tasks, stop_task], return_when=asyncio.FIRST_COMPLETED)

    if stop_task in done:
        log.info('Stop signal received, shutting down...')
    else:
        # a component crashed — report and stop everything
        stop_event.set()
        for t in tasks:
            if t in done and t.exception() is not None:
                log.error('Component failed: %r', t.exception())

    for t in tasks:
        if not t.done():
            t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    stop_task.cancel()
    try:
        await stop_task
    except (asyncio.CancelledError, Exception):
        pass
    log.info('Final stats: %s', stats.summary())


def run_from_config(config_path: str, verbose: Optional[bool] = None) -> int:
    from server.config_loader import (
        load_config, apply_config, setup_logging, ConfigError,
    )

    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        print(f'Config error: {exc}', file=__import__('sys').stderr)
        return 1

    if verbose is True:
        cfg['verbose'] = True
    setup_logging(cfg)
    apply_config(cfg)

    stop_event = asyncio.Event()

    def _handle_signal(signame):
        log.debug('Got %s', signame)
        stop_event.set()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig.name)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda *_: stop_event.set())

    try:
        loop.run_until_complete(_run_all(cfg, stop_event))
        return 0
    except KeyboardInterrupt:
        stop_event.set()
        return 0
    finally:
        loop.close()
        asyncio.set_event_loop(None)
