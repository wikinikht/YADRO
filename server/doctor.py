"""
[server fork] `tgws-server doctor` — diagnostics for a (Russian) VPS.

Checks, in order:
  1. config & secrets
  2. listening ports (proxy / socks5)
  3. DNS for kws2/kws4.web.telegram.org (poisoning detection)
  4. TLS+WebSocket handshake to the pinned Telegram IP with SNI kws2/kws4
     (THE test: 101 = whitelisted path works, timeout = TSPU blocks it,
      then CF fallbacks must carry the traffic)
  5. direct MTProto TCP to a real DC IP (expected blocked in RF —
     informational only)
  6. log file writability
"""

import asyncio
import logging
import ssl
import socket
import sys

from typing import Dict, List, Optional, Tuple

log = logging.getLogger('tgws-doctor')

OK, WARN, FAIL, SKIP = 'OK', 'WARN', 'FAIL', 'SKIP'


class Check:
    def __init__(self, name: str):
        self.name = name
        self.status: str = SKIP
        self.detail: str = ''


def _sync_check_port(host: str, port: int) -> Tuple[bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
        return True, f'something is listening on {host}:{port}'
    except OSError as exc:
        return False, f'{host}:{port} not reachable: {exc}'
    finally:
        s.close()


def check_dns(domains: List[str]) -> List[Check]:
    out = []
    for d in domains:
        c = Check(f'DNS {d}')
        try:
            infos = socket.getaddrinfo(d, 443, socket.AF_INET)
            ips = sorted({i[4][0] for i in infos})
            c.status = OK
            c.detail = f'resolves to {", ".join(ips)}'
            suspicious = [ip for ip in ips if not ip.startswith('149.154.')]
            if suspicious:
                c.status = WARN
                c.detail += (f'  <- unexpected IP(s) {", ".join(suspicious)}: '
                             'possible DNS poisoning; proxy pins IPs from '
                             'dc_ips, so this alone is not fatal')
        except OSError as exc:
            c.status = FAIL
            c.detail = f'{exc}'
        out.append(c)
    return out


async def check_ws_gateway(ip: str, domain: str, timeout: float = 8.0) -> Check:
    """THE whitelist test: TLS(SNI=domain) -> HTTP Upgrade -> expect 101."""
    from proxy.raw_websocket import RawWebSocket, WsHandshakeError
    c = Check(f'WS gateway {domain} via {ip}:443')
    try:
        ws = await RawWebSocket.connect(ip, domain, timeout=timeout)
    except WsHandshakeError as exc:
        if exc.is_redirect:
            c.status = WARN
            c.detail = (f'HTTP {exc.status_code} redirect to {exc.location} '
                        '(gateway up but this route redirects; '
                        'proxy handles this automatically)')
        else:
            c.status = FAIL
            c.detail = f'HTTP {exc.status_code}: {exc.status_line}'
        return c
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        c.status = FAIL
        c.detail = f'{type(exc).__name__}: {exc}'
        return c
    except Exception as exc:  # pragma: no cover
        c.status = FAIL
        c.detail = f'{type(exc).__name__}: {exc}'
        return c
    await ws.close()
    c.status = OK
    c.detail = ('TLS+Upgrade OK (101). Whitelisted WebSocket path works '
                'from this host')
    return c


async def check_direct_dc(ip: str, port: int = 443, timeout: float = 6.0) -> Check:
    """Direct MTProto TCP to a real DC IP (expected blocked in RF)."""
    c = Check(f'Direct MTProto TCP {ip}:{port}')
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        c.status = OK
        c.detail = 'connectable (not blocked here)'
    except (OSError, asyncio.TimeoutError) as exc:
        c.status = WARN
        c.detail = (f'blocked/unreachable ({type(exc).__name__}) — '
                    'expected inside RF; the WebSocket tunnel is what matters')
    return c


def run_doctor(cfg: Optional[Dict], config_path: Optional[str]) -> int:
    from server.config_loader import load_config, DEFAULT_CONFIG_PATH
    from server.generator import generate_secret

    results: List[Check] = []
    path = config_path or DEFAULT_CONFIG_PATH

    print(f'tgws-server doctor — {path}')
    print('=' * 62)

    try:
        cfg = load_config(path)
    except Exception as exc:
        print(f'  [FAIL] config: {exc}')
        print('\nCreate a config first:  tgws-server gen')
        return 1

    print(f'  [ OK ] config loaded: {len(cfg["secrets"])} secret(s), '
          f'proxy :{cfg["port"]}, ftls={"yes" if cfg["fake_tls_domain"] else "no"}')

    # ports (not listening is expected before deployment — warn only)
    s5 = cfg.get('socks5') or {}
    if s5.get('enabled'):
        listening, detail = _sync_check_port(s5.get('host', '127.0.0.1'),
                                             s5.get('port', 1080))
        results.append(_mk('SOCKS5 bridge port', listening,
                           'listening' if listening else
                           f'not running yet ({detail.split(": ", 1)[-1]})',
                           warn_only=True))
    listening, detail = _sync_check_port('127.0.0.1', int(cfg['port']))
    results.append(_mk(
        'Proxy port (loopback check)', True,
        'listening' if listening else 'not running right now '
        '(that is fine if you only wanted a dry run)'))

    # DNS
    results.extend(check_dns(['kws2.web.telegram.org',
                              'kws4.web.telegram.org']))

    # WS gateway via pinned IP
    dc_map = {}
    for item in cfg['dc_ips']:
        dc, ip = str(item).split(':', 1)
        dc_map[int(dc)] = ip
    pinned = dc_map.get(2, '149.154.167.220')

    loop = asyncio.new_event_loop()
    try:
        for domain in ('kws2.web.telegram.org', 'kws4.web.telegram.org'):
            results.append(loop.run_until_complete(
                check_ws_gateway(pinned, domain)))
        results.append(loop.run_until_complete(
            check_direct_dc('149.154.167.51')))
    finally:
        loop.close()

    # log file
    lf = cfg.get('log_file')
    if lf:
        try:
            import os as _os
            _os.makedirs(_os.path.dirname(_os.path.abspath(lf)),
                         exist_ok=True)
            with open(lf, 'a', encoding='utf-8'):
                pass
            results.append(_mk('Log file', True, lf))
        except OSError as exc:
            results.append(_mk('Log file', False, f'{lf}: {exc}'))

    print()
    fails = warns = 0
    for r in results:
        mark = {'OK': ' OK ', 'WARN': 'WARN', 'FAIL': 'FAIL', 'SKIP': 'SKIP'}[r.status]
        if r.status == FAIL:
            fails += 1
        elif r.status == WARN:
            warns += 1
        print(f'  [{mark}] {r.name}: {r.detail}')

    print()
    if fails == 0 and warns == 0:
        print('All checks passed. Run:  tgws-server run')
        return 0
    if fails == 0:
        print('Usable with warnings. Review WARN lines above.')
        return 2
    print(f'{fails} critical failure(s). See docs/TESTING.md '
          '(section "Что делать, если doctor красный").')
    return 1


def _mk(name: str, ok: bool, detail: str, warn_only: bool = False) -> Check:
    c = Check(name)
    if ok:
        c.status = OK
    else:
        c.status = WARN if warn_only else FAIL
    c.detail = detail
    return c
