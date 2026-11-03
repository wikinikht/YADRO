"""
[server fork] YAML configuration loader.

Maps tgws-server.yaml onto the upstream `proxy_config` singleton so the
patched core (multi-secret) runs exactly as the upstream CLI would.
"""

import logging
import os

from typing import Any, Dict, List, Optional

from proxy.config import proxy_config
from proxy.utils import DomainCensorFilter

try:
    import yaml
except ImportError as _exc:  # pragma: no cover
    yaml = None
    _yaml_error = _exc

log = logging.getLogger('tg-mtproto-proxy')

DEFAULT_CONFIG_PATH = 'tgws-server.yaml'

DEFAULTS: Dict[str, Any] = {
    'host': '0.0.0.0',
    'port': 1443,
    'fake_tls_domain': '',
    'secrets': [],
    'dc_ips': ['2:149.154.167.220', '4:149.154.167.220'],
    'socks5': {'enabled': True, 'host': '127.0.0.1', 'port': 1080},
    'cfproxy_domains': [],
    'cf_worker_domains': [],
    'no_cfproxy': False,
    'no_secure': False,
    'no_h2': False,
    'buffer_kb': 256,
    'pool_size': 4,
    'proxy_protocol': False,
    'force_test_dc': False,
    'log_file': '',
    'log_max_mb': 5,
    'log_backups': 2,
    'verbose': False,
}


class ConfigError(Exception):
    pass


def _load_yaml(path: str) -> Dict[str, Any]:
    if yaml is None:
        raise ConfigError(
            f"PyYAML is required to read {path}: pip install pyyaml "
            f"(or apt install python3-yaml) [{_yaml_error}]")
    with open(path, 'r', encoding='utf-8') as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ConfigError(f'{path}: top-level mapping expected')
    return data


def normalize_secrets(raw: Any) -> List[Dict[str, str]]:
    """Accepts both list of dicts ({name, value}) and list of strings."""
    result: List[Dict[str, str]] = []
    if not raw:
        return result
    if isinstance(raw, str):
        raw = [raw]
    for i, item in enumerate(raw):
        if isinstance(item, str):
            result.append({'name': f'secret-{i + 1}', 'value': item.strip()})
        elif isinstance(item, dict):
            value = str(item.get('value', '') or '').strip()
            name = str(item.get('name') or f'secret-{i + 1}')
            result.append({'name': name, 'value': value})
    return result


def load_config(path: str) -> Dict[str, Any]:
    """Load and validate config file, returns merged dict."""
    if not os.path.exists(path):
        raise ConfigError(
            f'Config not found: {path}. Create one with: tgws-server gen')
    data = _load_yaml(path)
    cfg = {**DEFAULTS}
    for key, value in data.items():
        if value is None:
            continue
        if key in cfg and key == 'socks5' and isinstance(value, dict):
            merged = dict(cfg['socks5'])
            merged.update(value)
            cfg[key] = merged
        else:
            cfg[key] = value

    cfg['secrets'] = normalize_secrets(cfg.get('secrets'))
    if not cfg['secrets']:
        raise ConfigError(
            f"{path}: no secrets defined. Add at least one secret "
            "(tgws-server gen creates them automatically).")

    for i, s in enumerate(cfg['secrets']):
        v = s['value'].strip().lower()
        # tolerate a full client-style 'dd<32hex>' / 'ee<32hex>' paste
        if len(v) == 34 and v.startswith(('dd', 'ee')):
            v = v[2:]
        if len(v) != 32 or any(c not in '0123456789abcdef' for c in v):
            raise ConfigError(
                f"{path}: secrets[{i}] ('{s['name']}') must be 32 hex chars "
                f"(optionally 'dd'/'ee' prefixed), got {len(v)} chars")
        s['value'] = v

    s5 = cfg.get('socks5') or {}
    if s5.get('enabled'):
        p = s5.get('port', 1080)
        if not isinstance(p, int) or not (0 < p < 65536):
            raise ConfigError(f'{path}: socks5.port invalid: {p!r}')

    return cfg


def apply_config(cfg: Dict[str, Any]) -> None:
    """Write the config into the upstream proxy_config singleton."""
    from proxy.config import parse_dc_ip_list

    proxy_config.host = str(cfg['host'])
    proxy_config.port = int(cfg['port'])
    proxy_config.secret = cfg['secrets'][0]['value'].lower()
    proxy_config.extra_secrets = [
        s['value'].lower() for s in cfg['secrets'][1:]]
    proxy_config.dc_redirects = parse_dc_ip_list(
        [str(x) for x in cfg['dc_ips']])
    proxy_config.buffer_size = max(4, int(cfg['buffer_kb'])) * 1024
    proxy_config.pool_size = max(0, int(cfg['pool_size']))
    proxy_config.fallback_cfproxy = not bool(cfg['no_cfproxy'])
    proxy_config.cfproxy_user_domains = list(cfg['cfproxy_domains'])
    proxy_config.cfproxy_worker_domains = list(cfg['cf_worker_domains'])
    proxy_config.cfproxy_h2_media = not bool(cfg['no_h2'])
    proxy_config.disable_secure = bool(cfg['no_secure'])
    proxy_config.fake_tls_domain = str(cfg['fake_tls_domain']).strip()
    proxy_config.proxy_protocol = bool(cfg['proxy_protocol'])
    proxy_config.force_test_dc = bool(cfg['force_test_dc'])


def setup_logging(cfg: Dict[str, Any]) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if cfg.get('verbose') else logging.INFO)
    fmt = logging.Formatter('%(asctime)s  %(levelname)-5s  %(message)s',
                            datefmt='%H:%M:%S')
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console.addFilter(DomainCensorFilter())
    root.addHandler(console)

    log_file = cfg.get('log_file')
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        from utils.logging_setup import build_log_handler
        fh = build_log_handler(
            log_file,
            log_max_mb=float(cfg.get('log_max_mb', 5)),
            backups=int(cfg.get('log_backups', 2)),
        )
        fh.addFilter(DomainCensorFilter())
        root.addHandler(fh)

    for noisy in ('asyncio', 'httpx', 'httpcore'):
        logging.getLogger(noisy).setLevel(logging.WARNING)
