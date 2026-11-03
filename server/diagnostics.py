"""
[server fork] `tgws-server diagnose` — full diagnostic sweep.

Unlike `doctor` (quick smoke test), `diagnose` runs a LARGE structured
set of checks and finishes with a "likely causes" section, so that when
something does not work you know WHERE it broke:

  ENV       python version, platform, privileges, disk, ulimit, locale
  DEPS      pyyaml / cryptography / core imports
  CONFIG    file, secrets, dc pinning, socks5 exposure, permissions, log
  CRYPTO    offline self-test of the whole obfuscation pipeline
            (AES-CTR engine, self-init parse, bridge re-encrypt ctx,
             MsgSplitter framing) — no network involved
  NETWORK   DNS (+poisoning), TCP to the pinned IP, TLS+WS handshake
            (THE whitelist test) via pinned IP AND via domain name,
            direct MTProto TCP (informational), Bot API endpoint
  SOCKS5    bridge port, and with --full a real end-to-end probe:
            a synthetic MTProto client walks the running bridge /
            frontend (or an in-process boot of the stack)
  RUNTIME   systemd unit state, container detection, server log scan
            (Traceback / handshake errors / WS pool exhaustion)

Exit codes: 0 = clean, 1 = at least one FAIL, 2 = only warnings.
Output: human text, --json PATH (machine report), --report PATH (md).

Network checks are skipped with --offline; --group NAME runs one group.
"""

import asyncio
import json
import os
import platform as _pyplatform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import hashlib
import resource

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

from server import __version__

OK, WARN, FAIL, SKIP, INFO = 'OK', 'WARN', 'FAIL', 'SKIP', 'INFO'

GROUPS = ('ENV', 'DEPS', 'CONFIG', 'CRYPTO', 'NETWORK', 'SOCKS5', 'RUNTIME')

PINNED_IP = '149.154.167.220'   # DC2/DC4 WebSocket gateway (TSPU whitelist)
DIRECT_DC_IP = '149.154.167.51'  # real DC2 MTProto IP (blocked in RF)
GATEWAY_DOMAINS = ('kws2.web.telegram.org', 'kws4.web.telegram.org')


@dataclass
class CheckResult:
    group: str
    name: str
    status: str = SKIP
    detail: str = ''
    fix: str = ''
    ms: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DiagnoseReport:
    """Accumulates checks and renders text / JSON / Markdown."""

    def __init__(self, config_path: str, offline: bool, full: bool):
        self.config_path = config_path
        self.offline = offline
        self.full = full
        self.started = time.time()
        self.checks: List[CheckResult] = []
        self.meta: Dict[str, Any] = {
            'tool': 'tgws-server diagnose',
            'version': __version__,
            'hostname': socket.gethostname(),
            'platform': f'{_pyplatform.system()} {_pyplatform.release()} '
                        f'({_pyplatform.machine()})',
            'python': sys.version.split()[0],
            'config': config_path,
            'offline': offline,
            'full': full,
        }

    # -- accumulation ---------------------------------------------------
    def add(self, group: str, name: str, status: str, detail: str = '',
            fix: str = '', ms: int = 0) -> CheckResult:
        r = CheckResult(group, name, status, detail, fix, ms)
        self.checks.append(r)
        return r

    def extend(self, results: List[CheckResult]) -> None:
        self.checks.extend(results)

    # -- summary --------------------------------------------------------
    def counts(self) -> Dict[str, int]:
        c = {s: 0 for s in (OK, WARN, FAIL, SKIP, INFO)}
        for r in self.checks:
            c[r.status] = c.get(r.status, 0) + 1
        return c

    def exit_code(self) -> int:
        c = self.counts()
        if c[FAIL]:
            return 1
        if c[WARN]:
            return 2
        return 0

    def failed(self, name_substring: str) -> bool:
        return any(r.status == FAIL and name_substring.lower() in r.name.lower()
                   for r in self.checks)

    # -- likely-cause engine ---------------------------------------------
    def likely_causes(self) -> List[Dict[str, str]]:
        """Map failure signatures to probable causes and remedies."""
        out: List[Dict[str, str]] = []
        c = self.counts()

        if c[FAIL] == 0 and c[WARN] == 0:
            return out

        def has(group: str, substr: str, *statuses: str) -> bool:
            return any(r.group == group and r.name.lower().find(substr.lower()) >= 0
                       and r.status in statuses for r in self.checks)

        # 1. config missing / broken
        if has('CONFIG', 'load config', FAIL):
            out.append({
                'cause': 'конфиг отсутствует или повреждён — сервису нечего запускать',
                'evidence': 'CONFIG: load config → FAIL',
                'remedy': 'tgws-server gen   (или исправить YAML вручную)',
            })
        # 2. deps broken
        if has('DEPS', 'import', FAIL) or has('CRYPTO', 'AES-CTR engine', FAIL):
            out.append({
                'cause': 'сломано окружение (не хватает библиотек или '
                         'криптобэкенд не работает) — любой запуск упадёт',
                'evidence': 'DEPS/CRYPTO: import или AES-CTR → FAIL',
                'remedy': 'pip install -e . --force-reinstall && '
                          'pip install --force-reinstall cryptography pyyaml',
            })
        # 3. DNS poisoned / broken
        if has('NETWORK', 'DNS kws', FAIL):
            out.append({
                'cause': 'DNS-резолвер не работает — имена Telegram не '
                         'резолвятся (наследуются и для пулов WS)',
                'evidence': 'NETWORK: DNS kws* → FAIL',
                'remedy': 'проверьте /etc/resolv.conf; используйте '
                          '1.1.1.1/8.8.8.8. Некритично: прокси пинит IP из dc_ips',
            })
        elif has('NETWORK', 'DNS kws', WARN):
            out.append({
                'cause': 'DNS отвечает «чужими» адресами (подмена/санкционный '
                         'резолвер). Не фатально: IP пиннится из dc_ips',
                'evidence': 'NETWORK: DNS kws* → WARN (unexpected IP)',
                'remedy': 'оставьте dc_ips как есть (149.154.167.220); '
                          'при желании переходите на DoH',
            })
        # 4. TCP blocked
        if has('NETWORK', 'TCP', FAIL) and has('NETWORK', 'WS gateway', FAIL):
            out.append({
                'cause': 'исходящий TCP:443 до пинового IP заблокирован '
                         'целиком (файрвол VPS или блок на уровне хостера) — '
                         'WS-туннель не поднимется вообще',
                'evidence': 'NETWORK: TCP + WS gateway → FAIL',
                'remedy': 'проверьте исходящий firewall (ufw/iptables/панель '
                          'хостера) на 443/tcp; смените IP/хостера, если '
                          'блокирует провайдер',
            })
        # 5. WS blocked while TCP fine → whitelist/SNI story
        tcp_ok = any(r.group == 'NETWORK' and r.name.startswith('TCP')
                     and r.status == OK for r in self.checks)
        ws_fail = has('NETWORK', 'WS gateway', FAIL)
        if tcp_ok and ws_fail:
            first_fail = next((r for r in self.checks
                               if r.group == 'NETWORK' and r.name.startswith('WS gateway')
                               and r.status == FAIL), None)
            dd = (first_fail.detail if first_fail else '').lower()
            if '404' in dd or '403' in dd or 'http 4' in dd:
                out.append({
                    'cause': 'TCP открыт, но WS-рукопожатие получает 4xx — '
                             'TSPU режет SNI/путь или путь белого списка '
                             'изменился',
                    'evidence': f'NETWORK: {first_fail.name if first_fail else "WS"} '
                                f'→ FAIL ({first_fail.detail if first_fail else ""})',
                    'remedy': 'обновите форк (git pull — путь/заголовки могли '
                              'измениться); включите CF-фолбэк (cfproxy_domains); '
                              'проверьте issues upstream-репозитория',
                })
            elif 'timeout' in dd or 'timed out' in dd or 'ssl' in dd:
                out.append({
                    'cause': 'TCP-коннект проходит, но TLS/WS до пинового IP '
                             'обрывается по таймауту — типичное поведение TSPU: '
                             'этот IP/маршрут для вашего хоста деградировал',
                    'evidence': f'NETWORK: {first_fail.name if first_fail else "WS"} '
                                f'→ FAIL (timeout/SSL)',
                    'remedy': 'попробуйте другой IP из подсети 149.154.167.x в '
                              'dc_ips; используйте cfproxy_domains (фолбэк через '
                              'Cloudflare); смените IP у хостера',
                })
        # 6. direct DC open but WS dead (inverse, rare)
        if (any(r.group == 'NETWORK' and r.name.startswith('Direct MTProto')
                and r.status == OK for r in self.checks) and ws_fail):
            out.append({
                'cause': 'странная комбинация: прямой MTProto открыт, а '
                         'белый WS-путь закрыт — вероятно, путь белого списка '
                         'изменился для этого IP',
                'evidence': 'NETWORK: Direct MTProto OK vs WS gateway FAIL',
                'remedy': 'обновите форк; сверяйте SNI/заголовки с upstream',
            })
        # 7. socks5 down / crashed
        if has('SOCKS5', 'bridge port', FAIL) or has('SOCKS5', 'bridge port', WARN):
            proxy_up = any(r.group == 'RUNTIME' and r.name.startswith('Proxy port')
                           and r.status == OK for r in self.checks)
            out.append({
                'cause': 'SOCKS5-мост не слушает порт — боты-клиенты (Pyrogram/'
                         'Telethon) не смогут подключиться',
                'evidence': 'SOCKS5: bridge port не отвечает',
                'remedy': ('запустите: tgws-server run -c ' + self.config_path) if not proxy_up
                else 'мост упал при живом прокси: смотрите log_file и '
                     'tgws-server diagnose --group SOCKS5; проверьте '
                     'socks5.enabled и свободность порта',
            })
        # 8. e2e failures
        if has('SOCKS5', 'e2e', FAIL):
            out.append({
                'cause': 'сквозной тест через мост не дошёл до WS-шлюза — '
                         'локальный конвейер (crypto/обфускация) или сетевой '
                         'путь сломан',
                'evidence': 'SOCKS5: e2e probe → FAIL',
                'remedy': 'если CRYPTO зелёный — сетевая часть: смотрите '
                          'группу NETWORK; если красный — переустановите '
                          'криптозависимости',
            })
        # 9. log scan errors
        if has('RUNTIME', 'server log', FAIL):
            out.append({
                'cause': 'в журнале сервера найдены Traceback/CRITICAL — '
                         'последняя ошибка указана в проверке «server log»',
                'evidence': 'RUNTIME: server log scan → FAIL',
                'remedy': 'исправьте по тексту ошибки; частые случаи: порт '
                          'занят, secrets битые, нет доступа к log-файлу',
            })
        elif has('RUNTIME', 'server log', WARN):
            out.append({
                'cause': 'в журнале есть ERROR/handshake-сбои — часть клиентов '
                         'отваливается (обычно неверный secret или не-MTProto '
                         'трафик на порт)',
                'evidence': 'RUNTIME: server log scan → WARN',
                'remedy': 'сверьте secret в клиенте (tgws-server links); '
                          'уберите лишние сервисы с порта',
            })
        # 10. dc pinning drifted
        if has('CONFIG', 'dc_ips pinning', WARN):
            out.append({
                'cause': 'dc_ips больше не пиннят IP белого списка — туннель '
                         'пойдёт мимо разрешённого пути и будет резаться',
                'evidence': 'CONFIG: dc_ips pinning → WARN',
                'remedy': 'верните "2:149.154.167.220" и "4:149.154.167.220"',
            })
        # 11. exposed socks5
        if has('CONFIG', 'socks5 binding', WARN):
            out.append({
                'cause': 'SOCKS5-мост слушает не на loopback — без аутентификации '
                         'им может пользоваться кто угодно (риск бана/абьюза)',
                'evidence': 'CONFIG: socks5 binding → WARN',
                'remedy': 'верните socks5.host: 127.0.0.1 или закройте порт '
                          'файрволом',
            })
        return out

    # -- rendering --------------------------------------------------------
    def render_text(self) -> str:
        lines: List[str] = []
        m = self.meta
        lines.append(f'tgws-server diagnose v{__version__} — {m["hostname"]}')
        lines.append(f'{m["platform"]}, python {m["python"]}, '
                     f'config: {m["config"]}'
                     f'{" [offline]" if self.offline else ""}'
                     f'{" [full]" if self.full else ""}')
        lines.append('=' * 70)
        cur_group = None
        for r in self.checks:
            if r.group != cur_group:
                cur_group = r.group
                lines.append('')
                lines.append(f'[{cur_group}]')
            mark = {'OK': ' OK ', 'WARN': 'WARN', 'FAIL': 'FAIL',
                    'SKIP': 'SKIP', 'INFO': 'INFO'}[r.status]
            line = f'  [{mark}] {r.name}'
            if r.detail:
                line += f': {r.detail}'
            lines.append(line)
            if r.fix and r.status in (FAIL, WARN):
                lines.append(f'         ↳ fix: {r.fix}')
        c = self.counts()
        lines.append('')
        lines.append('=' * 70)
        lines.append(f"summary: OK={c[OK]}  WARN={c[WARN]}  FAIL={c[FAIL]}  "
                     f"SKIP={c[SKIP]}  INFO={c[INFO]}"
                     f"   ({time.time() - self.started:.1f}s)")
        causes = self.likely_causes()
        if causes:
            lines.append('')
            lines.append('ВЕРОЯТНЫЕ ПРИЧИНЫ (по убыванию уверенности):')
            for i, cause in enumerate(causes, 1):
                lines.append(f'  {i}. {cause["cause"]}')
                lines.append(f'     доказательство: {cause["evidence"]}')
                lines.append(f'     что делать:     {cause["remedy"]}')
        elif c[FAIL] == 0:
            lines.append('Всё зелёное — можно запускать: tgws-server run')
        return '\n'.join(lines)

    def to_json(self) -> str:
        payload = {
            **self.meta,
            'finished': time.time(),
            'duration_s': round(time.time() - self.started, 2),
            'summary': self.counts(),
            'exit_code': self.exit_code(),
            'likely_causes': self.likely_causes(),
            'checks': [r.as_dict() for r in self.checks],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    def to_markdown(self) -> str:
        c = self.counts()
        m = self.meta
        md: List[str] = []
        md.append('# tgws-server diagnose — отчёт')
        md.append('')
        md.append(f'* host: **{m["hostname"]}** ({m["platform"]})')
        md.append(f'* python: {m["python"]}, tgws-server: {__version__}')
        md.append(f'* config: `{m["config"]}`'
                  + (', режим **offline**' if self.offline else '')
                  + (', режим **full**' if self.full else ''))
        md.append(f'* итог: '
                  f'{c[FAIL]} FAIL / {c[WARN]} WARN / {c[OK]} OK / '
                  f'{c[SKIP]} SKIP / {c[INFO]} INFO')
        md.append('')
        cur = None
        for r in self.checks:
            if r.group != cur:
                cur = r.group
                md.append(f'## {cur}')
                md.append('')
                md.append('| Статус | Проверка | Детали |')
                md.append('|---|---|---|')
            icon = {'OK': '✅', 'WARN': '⚠️', 'FAIL': '❌',
                    'SKIP': '⏭️', 'INFO': 'ℹ️'}[r.status]
            detail = r.detail.replace('|', '\\|')
            fix = f' <br>_fix: {r.fix}_' if (r.fix and r.status in (FAIL, WARN)) else ''
            md.append(f'| {icon} {r.status} | {r.name} | {detail}{fix} |')
        causes = self.likely_causes()
        if causes:
            md.append('')
            md.append('## Вероятные причины')
            md.append('')
            for i, cause in enumerate(causes, 1):
                md.append(f'{i}. **{cause["cause"]}**')
                md.append(f'   - доказательство: `{cause["evidence"]}`')
                md.append(f'   - что делать: {cause["remedy"]}')
        return '\n'.join(md) + '\n'


# ------------------------------------------------------------------
# low-level helpers
# ------------------------------------------------------------------

def _sync_tcp(host: str, port: int, timeout: float = 4.0) -> Tuple[bool, str, int]:
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True, f'{host}:{port} reachable', int((time.time() - t0) * 1000)
    except OSError as exc:
        return False, f'{host}:{port}: {exc}', int((time.time() - t0) * 1000)
    finally:
        s.close()


def _resolve_ips(host: str) -> List[str]:
    infos = socket.getaddrinfo(host, 443, socket.AF_INET)
    return sorted({i[4][0] for i in infos})


def _is_loopback(host: str) -> bool:
    try:
        return __import__('ipaddress').ip_address(host).is_loopback
    except ValueError:
        return host.lower() in ('localhost',)


def _proxy_client_init(secret_hex: str, dc: int = 2) -> bytes:
    """Obfuscated MTProto-proxy client init (dd-secret path)."""
    from proxy.utils import (
        HANDSHAKE_LEN, KEY_LEN, IV_LEN, PROTO_TAG_POS, PROTO_TAG_ABRIDGED,
        RESERVED_FIRST_BYTES, RESERVED_STARTS, RESERVED_CONTINUE,
        SKIP_LEN, PREKEY_LEN,
    )
    from proxy._aes import Cipher, algorithms, modes
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


def _self_init(dc: int = 2, proto_tag: bytes = None) -> bytes:
    """Self-obfuscated transport init (SOCKS5 bridge clients)."""
    from proxy.utils import (
        HANDSHAKE_LEN, KEY_LEN, IV_LEN, PROTO_TAG_POS, PROTO_TAG_ABRIDGED,
    )
    from proxy._aes import Cipher, algorithms, modes
    if proto_tag is None:
        proto_tag = PROTO_TAG_ABRIDGED
    rnd = bytearray(os.urandom(64))
    rnd[0] = 0x12
    key = bytes(rnd[8:8 + KEY_LEN])
    iv = bytes(rnd[8 + KEY_LEN:8 + KEY_LEN + IV_LEN])
    ks = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(
        b'\x00' * HANDSHAKE_LEN)
    tail = proto_tag + struct.pack('<h', dc) + os.urandom(2)
    return bytes(rnd[:PROTO_TAG_POS]) + bytes(
        a ^ b for a, b in zip(tail, ks[PROTO_TAG_POS:]))


def _snapshot_proxy_config() -> Dict[str, Any]:
    from proxy.config import proxy_config
    return dict(vars(proxy_config))


def _restore_proxy_config(snap: Dict[str, Any]) -> None:
    from proxy.config import proxy_config
    for k in list(vars(proxy_config)):
        if k in snap:
            setattr(proxy_config, k, snap[k])


# ------------------------------------------------------------------
# ENV group
# ------------------------------------------------------------------

def check_env(rep: DiagnoseReport) -> None:
    py = sys.version_info
    if py < (3, 8):
        rep.add('ENV', 'python >= 3.8', FAIL,
                f'{py.major}.{py.minor}.{py.micro} — слишком старый',
                fix='установите python3.8+ (apt install python3.10 / deadsnakes)')
    else:
        rep.add('ENV', 'python >= 3.8', OK,
                f'{py.major}.{py.minor}.{py.micro} '
                f'({sys.version.split()[0]})')

    system = _pyplatform.system()
    rep.add('ENV', 'platform', INFO,
            f'{system} {_pyplatform.release()} ({_pyplatform.machine()})'
            + ('' if system == 'Linux' else
               ' — серверный сценарий рассчитан на Linux'))

    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        rep.add('ENV', 'not running as root', WARN,
                'запуск от root: лишние права у сетевой службы',
                fix='запускайте под обычным пользователем (systemd User=)')
    else:
        rep.add('ENV', 'not running as root', OK,
                f'uid={getattr(os, "geteuid", lambda: 0)()}')

    usage = shutil.disk_usage(os.getcwd())
    free_mb = usage.free // (1024 * 1024)
    if free_mb < 200:
        rep.add('ENV', 'disk space', WARN, f'свободно {free_mb} МБ',
                fix='освободите место — журнал и ротация быстро упрутся')
    else:
        rep.add('ENV', 'disk space', OK, f'свободно {free_mb} МБ')

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 4096:
            rep.add('ENV', 'nofile limit', WARN, f'soft={soft}',
                    fix='systemd: LimitNOFILE=65536 (уже в юните tgws-server systemd)')
        else:
            rep.add('ENV', 'nofile limit', OK, f'soft={soft}')
    except (AttributeError, OSError):
        rep.add('ENV', 'nofile limit', SKIP, 'getrlimit недоступен')

    enc = (sys.stdout.encoding or '').lower()
    if enc and 'utf' not in enc:
        rep.add('ENV', 'utf-8 stdout', WARN, f'encoding={enc}',
                fix='export PYTHONIOENCODING=utf-8 или locale-gen ru_RU.UTF-8')
    else:
        rep.add('ENV', 'utf-8 stdout', OK, f'encoding={enc or "utf-8"}')


# ------------------------------------------------------------------
# DEPS group
# ------------------------------------------------------------------

def check_deps(rep: DiagnoseReport) -> None:
    try:
        import yaml  # noqa: F401
        rep.add('DEPS', 'pyyaml', OK, 'import ok')
    except ImportError as exc:
        rep.add('DEPS', 'pyyaml', FAIL, f'{exc}',
                fix='pip install pyyaml (или apt install python3-yaml)')

    try:
        from proxy._aes import Cipher, algorithms, modes  # noqa: F401
        rep.add('DEPS', 'cryptography backend', OK, 'proxy._aes import ok')
    except Exception as exc:
        rep.add('DEPS', 'cryptography backend', FAIL, f'{type(exc).__name__}: {exc}',
                fix='pip install --force-reinstall cryptography')

    for mod in ('proxy.config', 'proxy.tg_ws_proxy', 'proxy.raw_websocket',
                'proxy.bridge', 'server.socks5', 'server.config_loader'):
        try:
            __import__(mod)
            rep.add('DEPS', f'import {mod}', OK, 'ok')
        except Exception as exc:
            rep.add('DEPS', f'import {mod}', FAIL,
                    f'{type(exc).__name__}: {exc}',
                    fix='pip install -e . (в корне распакованного архива)')

    for lib, why in (('telethon', 'golden-тесты и боты на Telethon'),
                     ('pyrogram', 'боты на Pyrogram')):
        try:
            __import__(lib)
            rep.add('DEPS', f'optional {lib}', INFO, f'установлен ({why})')
        except ImportError:
            rep.add('DEPS', f'optional {lib}', INFO,
                    f'не установлен — нужен только для {why}')


# ------------------------------------------------------------------
# CONFIG group
# ------------------------------------------------------------------

def check_config(rep: DiagnoseReport, config_path: str) -> Optional[Dict]:
    from server.config_loader import load_config, ConfigError

    path = config_path or 'tgws-server.yaml'
    if not os.path.exists(path):
        rep.add('CONFIG', 'load config', FAIL, f'{path}: файл не найден',
                fix='tgws-server gen   (создаст конфиг с секретами)')
        return None
    try:
        cfg = load_config(path)
    except ConfigError as exc:
        rep.add('CONFIG', 'load config', FAIL, f'{exc}',
                fix='исправьте YAML или пересоздайте: tgws-server gen --force')
        return None
    except Exception as exc:
        rep.add('CONFIG', 'load config', FAIL,
                f'{type(exc).__name__}: {exc}',
                fix='проверьте YAML-синтаксис (yaml lint)')
        return None

    rep.add('CONFIG', 'load config', OK,
            f"{len(cfg['secrets'])} secret(s), port={cfg['port']}, "
            f"ftls={'yes' if cfg['fake_tls_domain'] else 'no (dd)'}")

    # per-secret sanity
    vals = [s['value'] for s in cfg['secrets']]
    for s in cfg['secrets']:
        weak = (set(s['value']) <= {'0', 'f'} or len(set(s['value'])) < 4)
        rep.add('CONFIG', f"secret '{s['name']}'",
                WARN if weak else OK,
                f"{s['value'][:8]}…{s['value'][-4:]}"
                + (' — выглядит слабым (мало энтропии)' if weak else ''),
                fix='tgws-server secret add <имя> и раздайте заново' if weak else '')
    if len(set(vals)) != len(vals):
        rep.add('CONFIG', 'secrets uniqueness', WARN, 'есть дубликаты',
                fix='удалите повторяющиеся: tgws-server secret remove <имя>')
    else:
        rep.add('CONFIG', 'secrets uniqueness', OK, f'{len(vals)} уникальных')

    # dc pinning
    dc_map = {}
    for item in cfg['dc_ips']:
        dc, ip = str(item).split(':', 1)
        dc_map[int(dc)] = ip
    bad = {dc: ip for dc, ip in dc_map.items() if ip != PINNED_IP}
    if bad or set(dc_map) - {2, 4}:
        rep.add('CONFIG', 'dc_ips pinning', WARN,
                f'неожиданно: {bad or set(dc_map) - {2, 4}}',
                fix=f'белый список действует для {PINNED_IP}; верните '
                    f'"2:{PINNED_IP}" и "4:{PINNED_IP}"')
    else:
        rep.add('CONFIG', 'dc_ips pinning', OK,
                f'DC2/DC4 → {PINNED_IP}')

    # socks5 exposure
    s5 = cfg.get('socks5') or {}
    if s5.get('enabled'):
        host = str(s5.get('host', '127.0.0.1'))
        if not _is_loopback(host):
            rep.add('CONFIG', 'socks5 binding', WARN,
                    f'мост слушает {host} (не loopback) и БЕЗ аутентификации',
                    fix='верните socks5.host: 127.0.0.1, либо закройте порт '
                        'файрволом (ufw deny <порт>)')
        else:
            rep.add('CONFIG', 'socks5 binding', OK, f'{host} (loopback)')

    # proxy host exposure — informational
    ph = str(cfg['host'])
    rep.add('CONFIG', 'proxy binding', INFO,
            f'{ph}:{cfg["port"]}'
            + ('' if _is_loopback(ph) else
               ' — внешний интерфейс: держите порт закрытым от сканеров '
               '(это MTProto-фронтенд, секрет обязателен)'))

    # fake tls domain sanity
    ftls = str(cfg.get('fake_tls_domain') or '')
    if ftls:
        ok_name = re.fullmatch(r'[a-z0-9.-]{3,253}', ftls.lower())
        suspicious = ('telegram' in ftls or ftls.endswith('t.me'))
        if not ok_name or suspicious:
            rep.add('CONFIG', 'fake_tls_domain', WARN, f'"{ftls}"',
                    fix='домен-маска должен быть обычным незаблокированным '
                        'сайтом (например, cloudflare.com); без слов telegram')
        else:
            rep.add('CONFIG', 'fake_tls_domain', OK, f'"{ftls}" (ee-маска)')

    # permissions (posix only)
    if os.name == 'posix':
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            rep.add('CONFIG', 'config permissions', WARN,
                    f'{oct(mode)} — секреты читают другие пользователи',
                    fix=f'chmod 600 {path}')
        else:
            rep.add('CONFIG', 'config permissions', OK, oct(mode))

    # log file writable
    lf = cfg.get('log_file')
    if lf:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(lf)), exist_ok=True)
            with open(lf, 'a', encoding='utf-8'):
                pass
            rep.add('CONFIG', 'log file writable', OK, lf)
        except OSError as exc:
            rep.add('CONFIG', 'log file writable', FAIL, f'{lf}: {exc}',
                    fix=f'исправьте путь/права: {exc}')
    return cfg


# ------------------------------------------------------------------
# CRYPTO group (offline self-test)
# ------------------------------------------------------------------

def check_crypto(rep: DiagnoseReport) -> None:
    # 1. AES-CTR engine roundtrip
    t0 = time.time()
    try:
        from proxy._aes import Cipher, algorithms, modes
        key = os.urandom(32)
        iv = os.urandom(16)
        data = os.urandom(1024)
        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        rt = dec.update(enc.update(data))
        assert rt == data
        rep.add('CRYPTO', 'AES-CTR engine', OK, 'roundtrip ok',
                ms=int((time.time() - t0) * 1000))
    except Exception as exc:
        rep.add('CRYPTO', 'AES-CTR engine', FAIL,
                f'{type(exc).__name__}: {exc}',
                fix='pip install --force-reinstall cryptography')

    # 2. self-init parse roundtrip (both transports)
    try:
        from server.socks5 import parse_self_obfuscated_init
        from proxy.utils import (
            PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE,
            PROTO_ABRIDGED_INT, PROTO_INTERMEDIATE_INT,
        )
        for tag, want, dc in ((PROTO_TAG_ABRIDGED, PROTO_ABRIDGED_INT, 2),
                              (PROTO_TAG_INTERMEDIATE, PROTO_INTERMEDIATE_INT, 4)):
            init = _self_init(dc, proto_tag=tag)
            got = parse_self_obfuscated_init(init)
            assert got is not None, 'parse returned None'
            assert got == (want, dc), f'{got} != {(want, dc)}'
        rep.add('CRYPTO', 'self-init parse roundtrip', OK,
                'abridged/dc2 + intermediate/dc4')
    except Exception as exc:
        rep.add('CRYPTO', 'self-init parse roundtrip', FAIL,
                f'{type(exc).__name__}: {exc}',
                fix='код форка повреждён — git status / переустановка')

    # 3. bridge re-encryption full roundtrip (client -> bridge -> tg -> bridge -> client)
    #    Mirrors the production cipher consumption patterns exactly:
    #      client send : forward key/iv, keystream advanced by 64 bytes
    #      client recv : REVERSED key/iv, keystream from 0
    #      bridge->tg  : forward relay key/iv, advanced by 64
    #      tg->bridge  : REVERSED relay key/iv, keystream from 0
    try:
        from server.socks5 import parse_self_obfuscated_init, build_bridge_ctx
        from proxy.utils import (
            HANDSHAKE_LEN, KEY_LEN, IV_LEN, PROTO_TAG_ABRIDGED,
        )
        from proxy._aes import Cipher, algorithms, modes
        init = _self_init(2)
        proto_int, dc_idx = parse_self_obfuscated_init(init)
        ctx, relay_init = build_bridge_ctx(init, PROTO_TAG_ABRIDGED, dc_idx)

        def _cipher(key_iv: bytes, advance: bool):
            c = Cipher(algorithms.AES(key_iv[:KEY_LEN]),
                       modes.CTR(key_iv[KEY_LEN:])).encryptor()
            if advance:
                c.update(b'\x00' * HANDSHAKE_LEN)
            return c

        fwd_key_iv = init[8:8 + KEY_LEN + IV_LEN]
        rev_key_iv = fwd_key_iv[::-1]
        tg_fwd_key_iv = relay_init[8:8 + KEY_LEN + IV_LEN]
        tg_rev_key_iv = tg_fwd_key_iv[::-1]

        # client -> bridge (bridge decrypts with clt_dec)
        payload = os.urandom(300)
        wire = init + _cipher(fwd_key_iv, advance=True).update(payload)
        assert ctx.clt_dec.update(wire[HANDSHAKE_LEN:]) == payload, \
            'bridge cannot decrypt client stream'

        # bridge -> gateway (gateway decrypts with forward relay, advanced 64)
        to_tg = ctx.tg_enc.update(payload)
        assert _cipher(tg_fwd_key_iv, advance=True).update(to_tg) == payload, \
            'gateway side decrypt mismatch'

        # gateway -> bridge (bridge decrypts with tg_dec: reversed, from 0)
        back = os.urandom(200)
        wire_back = _cipher(tg_rev_key_iv, advance=False).update(back)
        assert ctx.tg_dec.update(wire_back) == back, \
            'bridge cannot decrypt gateway stream'

        # bridge -> client (client decrypts with reversed init key/iv, from 0)
        to_client = ctx.clt_enc.update(back)
        assert _cipher(rev_key_iv, advance=False).update(to_client) == back, \
            'client side decrypt mismatch'
        rep.add('CRYPTO', 'bridge re-encrypt roundtrip', OK,
                'client→bridge→TG→bridge→client, все 4 потока сходятся')
    except Exception as exc:
        rep.add('CRYPTO', 'bridge re-encrypt roundtrip', FAIL,
                f'{type(exc).__name__}: {exc}',
                fix='переустановите форк из архива (повреждён socks5.py)')

    # 4. MsgSplitter framing (abridged): frames come out WITH their length
    #    prefixes, split across arbitrary TCP chunk boundaries
    try:
        from proxy.bridge import MsgSplitter
        from proxy.utils import PROTO_ABRIDGED_INT
        p1, p2 = os.urandom(40), os.urandom(120)  # 10 и 30 слов
        f1 = bytes([len(p1) // 4]) + p1
        f2 = bytes([len(p2) // 4]) + p2
        stream = f1 + f2
        sp = MsgSplitter(PROTO_ABRIDGED_INT)
        cut = 47  # рвём поток посреди второго пакета
        parts = sp.split(stream[:cut], stream[:cut]) + \
            sp.split(stream[cut:], stream[cut:]) + sp.flush()
        assert parts == [f1, f2], \
            f'framing broken: {[len(p) for p in parts]!r}'
        rep.add('CRYPTO', 'MsgSplitter framing', OK,
                '2 пакета из 2 рваных чанков восстановлены точно')
    except Exception as exc:
        rep.add('CRYPTO', 'MsgSplitter framing', FAIL,
                f'{type(exc).__name__}: {exc}',
                fix='переустановите форк (повреждён proxy/bridge.py)')


# ------------------------------------------------------------------
# NETWORK group (live)
# ------------------------------------------------------------------

def check_network(rep: DiagnoseReport, cfg: Optional[Dict],
                  timeout: float) -> None:
    from server.doctor import check_dns, check_ws_gateway, check_direct_dc

    if cfg is None:
        for name in ('DNS kws2/kws4', 'TCP pinned IP', 'WS gateway pinned',
                     'WS gateway domain', 'Direct MTProto'):
            rep.add('NETWORK', name, SKIP, 'нет конфига')
        return

    pinned = PINNED_IP
    dc_map = {}
    for item in cfg['dc_ips']:
        dc, ip = str(item).split(':', 1)
        dc_map[int(dc)] = ip
    pinned = dc_map.get(2, PINNED_IP)

    # DNS
    for d in GATEWAY_DOMAINS:
        t0 = time.time()
        c = check_dns([d])[0]
        rep.add('NETWORK', f'DNS {d}', c.status, c.detail,
                fix='IP-пиннинг в dc_ips делает это некритичным' if c.status == WARN
                else ('проверьте /etc/resolv.conf' if c.status == FAIL else ''),
                ms=int((time.time() - t0) * 1000))
    try:
        ips = _resolve_ips('api.telegram.org')
        rep.add('NETWORK', 'DNS api.telegram.org', INFO,
                ', '.join(ips[:4]) + ' — нужен только Bot API клиентам (aiogram)')
    except OSError as exc:
        rep.add('NETWORK', 'DNS api.telegram.org', INFO,
                f'не резолвится ({exc}) — Bot API (aiogram) отсюда работать не будет')

    # TCP to pinned IP
    t0 = time.time()
    ok, detail, _ = _sync_tcp(pinned, 443, timeout=timeout)
    rep.add('NETWORK', f'TCP {pinned}:443', OK if ok else FAIL, detail,
            fix='исходящий 443 закрыт файрволом/хостером — откройте egress '
                'или смените хостинг' if not ok else '',
            ms=int((time.time() - t0) * 1000))

    # WS gateway via pinned IP — THE whitelist test
    loop = asyncio.new_event_loop()
    try:
        for d in GATEWAY_DOMAINS:
            t0 = time.time()
            c = loop.run_until_complete(
                check_ws_gateway(pinned, d, timeout=timeout))
            fix = ''
            if c.status == FAIL:
                dd = c.detail.lower()
                if 'timeout' in dd or 'timed out' in dd:
                    fix = ('TSPU глушит этот маршрут: попробуйте другой IP '
                           '149.154.167.x, cfproxy_domains (CF-фолбэк) или '
                           'смените IP у хостера')
                elif '404' in dd or '403' in dd or 'http 4' in dd or 'http 5' in dd:
                    fix = ('путь/SNI режется или изменился: обновите форк '
                           '(git pull), проверьте issues upstream; включите '
                           'cfproxy_domains')
                else:
                    fix = 'смотрите docs/TESTING.md, раздел про doctor'
            rep.add('NETWORK', f'WS gateway {d} via {pinned}', c.status,
                    c.detail, fix=fix, ms=int((time.time() - t0) * 1000))

        # comparison: same domain via DNS (no pinning) — does plain SNI work?
        t0 = time.time()
        c = loop.run_until_complete(
            check_ws_gateway(GATEWAY_DOMAINS[0], GATEWAY_DOMAINS[0],
                             timeout=timeout))
        rep.add('NETWORK', f'WS gateway {GATEWAY_DOMAINS[0]} via DNS',
                c.status if c.status != FAIL else WARN,
                ('без пиннинга: ' + c.detail) if c.status != SKIP else c.detail,
                fix='', ms=int((time.time() - t0) * 1000))

        # direct MTProto — informational, expected blocked in RF
        t0 = time.time()
        c = loop.run_until_complete(
            check_direct_dc(DIRECT_DC_IP, timeout=timeout))
        rep.add('NETWORK', f'Direct MTProto TCP {DIRECT_DC_IP}:443', INFO,
                c.detail, ms=int((time.time() - t0) * 1000))
    finally:
        loop.close()


# ------------------------------------------------------------------
# SOCKS5 group
# ------------------------------------------------------------------

async def _probe_socks5_bridge(port: int, with_connect: bool = True) -> Tuple[str, str]:
    """Synthetic client against the bridge. Returns (result, detail)."""
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    try:
        writer.write(b'\x05\x01\x00')
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(2), timeout=5)
        if reply != b'\x05\x00':
            return 'fail', f'greeting reply {reply!r} != 05 00'
        if not with_connect:
            return 'ok', 'greeting/method ok (05 00)'
        writer.write(b'\x05\x01\x00\x01' +
                     bytes([149, 154, 167, 51]) + struct.pack('>H', 443))
        await writer.drain()
        rep = await asyncio.wait_for(reader.readexactly(10), timeout=10)
        if rep[1] != 0:
            return 'fail', f'CONNECT reply code {rep[1]} (ожидался 0x00)'
        writer.write(_self_init(2))
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=6)
            if data:
                return 'ok', 'CONNECT ok, шлюз держит сессию (данные идут)'
            return 'warn', ('CONNECT ok, но соединение сразу закрыто — '
                            'WS-шлюз недоступен (смотрите группу NETWORK)')
        except asyncio.TimeoutError:
            return 'ok', 'CONNECT ok, шлюз держит сессию (нет RST/Fin)'
    except asyncio.TimeoutError:
        return 'fail', 'таймаут на этапе SOCKS5-рукопожатия'
    except (OSError, asyncio.IncompleteReadError) as exc:
        return 'fail', f'{type(exc).__name__}: {exc}'
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _probe_frontend(port: int, secret_hex: str) -> Tuple[str, str]:
    """Synthetic MTProto-proxy client against the frontend."""
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    try:
        writer.write(_proxy_client_init(secret_hex))
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=6)
            if not data:
                return 'warn', ('инициализация принята, но соединение закрыто — '
                                'WS-шлюз недоступен (смотрите NETWORK)')
            return 'ok', 'обфусцированный handshake принят, данные идут'
        except asyncio.TimeoutError:
            return 'ok', 'handshake принят (сессия открыта, без RST)'
    except (OSError, asyncio.IncompleteReadError) as exc:
        return 'fail', f'{type(exc).__name__}: {exc}'
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def check_socks5(rep: DiagnoseReport, cfg: Optional[Dict],
                 full: bool, timeout: float, path: str = '') -> None:
    if cfg is None:
        rep.add('SOCKS5', 'bridge port', SKIP, 'нет конфига')
        return

    s5 = cfg.get('socks5') or {}
    s5_port = int(s5.get('port', 1080))
    proxy_port = int(cfg['port'])

    # port checks (not running is expected before deployment)
    listening, detail, _ = _sync_tcp('127.0.0.1', proxy_port, timeout=2)
    rep.add('SOCKS5', 'MTProto frontend port',
            OK if listening else SKIP,
            'слушает' if listening else
            'не запущен (нормально до деплоя; для e2e — tgws-server run или --full)')

    if s5.get('enabled'):
        listening, detail, _ = _sync_tcp('127.0.0.1', s5_port, timeout=2)
        rep.add('SOCKS5', 'SOCKS5 bridge port',
                OK if listening else WARN,
                'слушает' if listening else
                f'не запущен: {detail.split(":", 1)[-1]}',
                fix='' if listening else
                f'tgws-server run -c {path or "tgws-server.yaml"} '
                f'(или systemd-юнит)')

    if not full:
        if s5.get('enabled'):
            rep.add('SOCKS5', 'e2e probe (bridge→WS gateway)',
                    SKIP, 'доступно с --full')
        rep.add('SOCKS5', 'e2e probe (frontend→WS gateway)',
                SKIP, 'доступно с --full')
        return

    # ---- full mode: real end-to-end (needs network) ----
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    snap = _snapshot_proxy_config()
    booted = False
    tasks: List[asyncio.Task] = []
    stop = asyncio.Event()
    try:
        frontend_listening = _sync_tcp('127.0.0.1', proxy_port, timeout=2)[0]
        bridge_listening = (s5.get('enabled')
                            and _sync_tcp('127.0.0.1', s5_port, timeout=2)[0])

        if not frontend_listening:
            # boot the stack in-process on ephemeral ports (real code path)
            from proxy import tg_ws_proxy
            from proxy.config import proxy_config
            from server.config_loader import apply_config
            apply_config(cfg)
            proxy_config.host = '127.0.0.1'
            proxy_config.port = 0          # ephemeral
            proxy_config.pool_size = 2
            proxy_config.fallback_cfproxy = False  # deterministic: WS or fail
            proxy_config.fake_tls_domain = ''
            stale_instance = tg_ws_proxy._server_instance
            tasks.append(loop.create_task(tg_ws_proxy._run(stop)))
            if s5.get('enabled'):
                tasks.append(loop.create_task(_serve_bridge_ephemeral(stop)))
            # wait for listeners
            deadline = time.time() + 8
            while time.time() < deadline:
                inst = tg_ws_proxy._server_instance
                if inst is not None and inst is not stale_instance:
                    proxy_port = inst.sockets[0].getsockname()[1]
                    if not s5.get('enabled') or _EPHEMERAL_S5_PORT:
                        break
                loop.run_until_complete(asyncio.sleep(0.2))
            booted = True
            if proxy_port == 0:
                rep.add('SOCKS5', 'e2e probe (frontend→WS gateway)', SKIP,
                        'не удалось поднять стек в этом процессе '
                        '(порт/файрвол?) — запустите tgws-server run и '
                        'повторите diagnose --full')
        elif not bridge_listening and s5.get('enabled'):
            tasks.append(loop.create_task(_serve_bridge_ephemeral(stop)))
            deadline = time.time() + 5
            while time.time() < deadline and not _EPHEMERAL_S5_PORT:
                loop.run_until_complete(asyncio.sleep(0.1))

        # frontend probe with primary secret
        if proxy_port:
            secret0 = cfg['secrets'][0]['value']
            try:
                t0 = time.time()
                res, det = loop.run_until_complete(
                    _probe_frontend(proxy_port, secret0))
                rep.add('SOCKS5', 'e2e probe (frontend→WS gateway)',
                        {'ok': OK, 'warn': WARN, 'fail': FAIL}[res], det,
                        fix='локальный путь ок, сетевой нет — группа NETWORK'
                        if res == 'warn' else '',
                        ms=int((time.time() - t0) * 1000))
            except (OSError, asyncio.TimeoutError) as exc:
                rep.add('SOCKS5', 'e2e probe (frontend→WS gateway)', FAIL,
                        f'{type(exc).__name__}: {exc}',
                        fix='фронтенд не принимает синтетический клиент — '
                            'смотрите группу CRYPTO/NETWORK')

        # socks5 probe
        if s5.get('enabled'):
            target_port = (s5_port if (bridge_listening and not booted)
                           else _EPHEMERAL_S5_PORT)
            if target_port:
                try:
                    t0 = time.time()
                    res, det = loop.run_until_complete(
                        _probe_socks5_bridge(target_port, with_connect=True))
                    rep.add('SOCKS5', 'e2e probe (bridge→WS gateway)',
                            {'ok': OK, 'warn': WARN, 'fail': FAIL}[res], det,
                            fix='локальный путь ок, сетевой нет — группа NETWORK'
                            if res == 'warn' else '' if res == 'ok' else
                            'мост отвечает не по SOCKS5 или падает: '
                            'tgws-server diagnose --group CRYPTO',
                            ms=int((time.time() - t0) * 1000))
                except (OSError, asyncio.TimeoutError) as exc:
                    rep.add('SOCKS5', 'e2e probe (bridge→WS gateway)', FAIL,
                            f'{type(exc).__name__}: {exc}',
                            fix='мост недоступен: проверьте, что сервис запущен')
            else:
                rep.add('SOCKS5', 'e2e probe (bridge→WS gateway)', SKIP,
                        'мост не поднялся при тесте')
    finally:
        stop.set()
        if tasks:
            loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        loop.close()
        asyncio.set_event_loop(None)
        _restore_proxy_config(snap)


_EPHEMERAL_S5_PORT = 0


async def _serve_bridge_ephemeral(stop: asyncio.Event):
    """Run the production SOCKS5 handler on an ephemeral loopback port."""
    global _EPHEMERAL_S5_PORT
    from server.socks5 import handle_socks5_client
    server = await asyncio.start_server(handle_socks5_client, '127.0.0.1', 0)
    _EPHEMERAL_S5_PORT = server.sockets[0].getsockname()[1]
    stop_task = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait([asyncio.create_task(server.serve_forever()),
                            stop_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        stop_task.cancel()
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass
        _EPHEMERAL_S5_PORT = 0


# ------------------------------------------------------------------
# RUNTIME group
# ------------------------------------------------------------------

def check_runtime(rep: DiagnoseReport, cfg: Optional[Dict]) -> None:
    # systemd unit
    unit_path = '/etc/systemd/system/tgws-server.service'
    if os.path.exists(unit_path):
        systemctl = shutil.which('systemctl')
        active = '?'
        if systemctl:
            try:
                out = subprocess.run(
                    [systemctl, 'is-active', 'tgws-server'],
                    capture_output=True, text=True, timeout=5)
                active = (out.stdout or '').strip() or out.returncode
            except (OSError, subprocess.TimeoutExpired):
                active = 'unknown'
        rep.add('RUNTIME', 'systemd unit', INFO,
                f'юнит установлен, состояние: {active}',
                fix='' if active == 'active' else
                'sudo systemctl enable --now tgws-server')
    else:
        rep.add('RUNTIME', 'systemd unit', INFO,
                'не установлен (нормально для ручного запуска)',
                fix='tgws-server systemd > tgws-server.service && '
                    'sudo cp tgws-server.service /etc/systemd/system/')

    # container detection
    if os.path.exists('/.dockerenv') or os.environ.get('container'):
        rep.add('RUNTIME', 'container', INFO,
                'запущено в контейнере (docker/podman)')

    # proxy port (loopback) — informational duplicate of SOCKS5 group entry
    if cfg:
        listening, detail, _ = _sync_tcp('127.0.0.1', int(cfg['port']), timeout=2)
        rep.add('RUNTIME', 'Proxy port (loopback)',
                OK if listening else INFO,
                'слушает' if listening else
                'не запущен сейчас (нормально до tgws-server run)')

    # server log scan — the "know what broke" check
    lf = (cfg or {}).get('log_file') or ''
    if lf and os.path.exists(lf):
        try:
            size = os.path.getsize(lf)
            with open(lf, 'rb') as fh:
                if size > 262144:
                    fh.seek(-262144, os.SEEK_END)
                tail = fh.read().decode('utf-8', errors='replace')
            crit = []
            for pat, sev in ((r'^Traceback', 'traceback'),
                             (r'CRITICAL', 'critical'),
                             (r'bad handshake', 'handshake reject'),
                             (r'ERROR', 'error'),
                             (r'WS pool (empty|exhausted|.*fail)', 'ws pool')):
                found = [l for l in tail.splitlines() if re.search(pat, l)]
                if found:
                    crit.append((sev, found[-1][:160]))
            has_tb = any(sev in ('traceback', 'critical') for sev, _ in crit)
            has_err = bool(crit)
            last = crit[-1][1] if crit else ''
            if has_tb:
                rep.add('RUNTIME', 'server log scan', FAIL,
                        f'{len(crit)} проблем(ы), последняя: {last}',
                        fix='исправьте по тексту ошибки; часто: порт занят, '
                            'битый secret, нет прав на лог-файл')
            elif has_err:
                rep.add('RUNTIME', 'server log scan', WARN,
                        f'{len(crit)} проблем(ы), последняя: {last}',
                        fix='сверьте secret у клиентов (tgws-server links); '
                            'чужой трафик на порт')
            else:
                rep.add('RUNTIME', 'server log scan', OK,
                        f'{lf}: ошибок в хвосте ({size // 1024} КБ) нет')
        except OSError as exc:
            rep.add('RUNTIME', 'server log scan', SKIP, f'{lf}: {exc}')
    else:
        rep.add('RUNTIME', 'server log scan', SKIP,
                'log_file не задан в конфиге — включите его, чтобы видеть '
                'ошибки: log_file: "/var/log/tgws-server.log"')


# ------------------------------------------------------------------
# entry point
# ------------------------------------------------------------------

def run_diagnostics(config_path: Optional[str] = None,
                    offline: bool = False,
                    full: bool = False,
                    timeout: float = 8.0,
                    group: Optional[str] = None) -> DiagnoseReport:
    from server.config_loader import load_config, ConfigError

    path = config_path or 'tgws-server.yaml'
    full = full and not offline   # e2e boot needs the real network
    rep = DiagnoseReport(path, offline=offline, full=full)

    cfg = None
    if group in (None, 'ENV'):
        check_env(rep)
    if group in (None, 'DEPS'):
        check_deps(rep)
    if group in (None, 'CONFIG', 'NETWORK', 'SOCKS5', 'RUNTIME', 'CRYPTO'):
        # config is needed by most groups; only report errors once
        if group in (None, 'CONFIG'):
            cfg = check_config(rep, path)
        else:
            try:
                cfg = load_config(path)
            except Exception:
                cfg = None
                if group == 'NETWORK':
                    rep.add('NETWORK', 'config', SKIP, 'нет валидного конфига')
    if not offline and group in (None, 'NETWORK'):
        check_network(rep, cfg, timeout)
    elif group == 'NETWORK' and offline:
        rep.add('NETWORK', 'all live checks', SKIP, '--offline')
    if group in (None, 'CRYPTO'):
        check_crypto(rep)
    if group in (None, 'SOCKS5'):
        check_socks5(rep, cfg, full=full, timeout=timeout, path=path)
    if group in (None, 'RUNTIME'):
        check_runtime(rep, cfg)
    return rep


def run_diagnose_cli(config_path: Optional[str], offline: bool = False,
                     full: bool = False, timeout: float = 8.0,
                     group: Optional[str] = None,
                     json_out: Optional[str] = None,
                     md_out: Optional[str] = None) -> int:
    rep = run_diagnostics(config_path, offline=offline, full=full,
                          timeout=timeout, group=group)
    print(rep.render_text())

    if json_out:
        with open(json_out, 'w', encoding='utf-8') as fh:
            fh.write(rep.to_json())
        print(f'\nJSON-отчёт: {json_out}')
    if md_out:
        with open(md_out, 'w', encoding='utf-8') as fh:
            fh.write(rep.to_markdown())
        print(f'Markdown-отчёт: {md_out}')

    code = rep.exit_code()
    if code == 0:
        print('\nИтог: 0 критических проблем.')
    elif code == 1:
        print('\nИтог: есть FAIL — смотрите «ВЕРОЯТНЫЕ ПРИЧИНЫ» выше, '
              'затем docs/TESTING.md.')
    else:
        print('\nИтог: критических проблем нет, но есть предупреждения.')
    return code
