"""
[server fork] Config generator and link builder.

`tgws-server gen`  — create a ready-to-run config with N secrets
`tgws-server links`— print tg://proxy links and bot code snippets
"""

import os
import secrets as _secrets
import sys

from typing import Any, Dict, List, Optional

from server.config_loader import DEFAULT_CONFIG_PATH

TEMPLATE = """\
# tg-ws-proxy-server configuration
# Docs: https://github.com/wikinikht/YADRO
# Upstream protocol: https://github.com/Flowseal/tg-ws-proxy
host: {host}                 # 0.0.0.0 = accept external (firewall it!)
port: {port}
fake_tls_domain: "{ftls}"  # ee-secret masking domain; empty -> dd-secrets

# One secret per consumer: each gets its own tg://proxy link.
# Rotate = add new secret, hand it out, then remove the old one.
secrets:
{secrets_block}

# Only DC2/DC4 are served over the whitelisted WebSocket IP.
# Keep both entries unless you know what you are doing.
dc_ips:
  - "2:149.154.167.220"
  - "4:149.154.167.220"

socks5:                     # bridge for Pyrogram/Telethon bots
  enabled: {socks5}
  host: 127.0.0.1           # keep loopback unless you must expose it
  port: {socks5_port}

cfproxy_domains: []         # optional: own CF-proxied domains
cf_worker_domains: []       # optional: own CF Worker domains (docs/CfWorker)
no_cfproxy: false
no_secure: false
no_h2: false
buffer_kb: 256
pool_size: 4
proxy_protocol: false       # true if behind nginx/haproxy
force_test_dc: false

log_file: "{log_file}"
log_max_mb: 5
log_backups: 2
verbose: false
"""


def generate_secret() -> str:
    return _secrets.token_hex(16)


def build_config_dict(
    n_secrets: int = 2,
    port: int = 1443,
    host: str = '0.0.0.0',
    fake_tls_domain: str = '',
    socks5: bool = True,
    socks5_port: int = 1080,
    log_file: str = '',
    first_secret: Optional[str] = None,
    extra_secrets: Optional[List[str]] = None,
) -> Dict[str, Any]:
    values = []
    if first_secret:
        values.append(first_secret)
    values.extend(extra_secrets or [])
    while len(values) < max(1, n_secrets):
        values.append(generate_secret())
    names = ['main'] + [f'user-{i}' for i in range(2, len(values) + 1)]
    return {
        'host': host,
        'port': port,
        'fake_tls_domain': fake_tls_domain,
        'secrets': [{'name': n, 'value': v} for n, v in zip(names, values)],
        'socks5': {'enabled': socks5, 'host': '127.0.0.1', 'port': socks5_port},
        'log_file': log_file,
    }


def render_config(cfg: Dict[str, Any]) -> str:
    lines = []
    for i, s in enumerate(cfg['secrets']):
        comment = '   # primary' if i == 0 else ''
        lines.append(f'  - name: {s["name"]}')
        lines.append(f'    value: {s["value"]}{comment}')
    socks5 = cfg.get('socks5', {})
    return TEMPLATE.format(
        host=cfg['host'],
        port=cfg['port'],
        ftls=cfg.get('fake_tls_domain', ''),
        secrets_block='\n'.join(lines),
        socks5='true' if socks5.get('enabled', True) else 'false',
        socks5_port=socks5.get('port', 1080),
        log_file=cfg.get('log_file', ''),
    )


def write_config(path: str, cfg: Dict[str, Any], force: bool = False) -> None:
    if os.path.exists(path) and not force:
        raise FileExistsError(
            f'{path} already exists; use --force to overwrite '
            '(existing secrets will be lost)')
    os.makedirs(os.path.dirname(os.path.abspath(path)) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(render_config(cfg))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def add_secret(path: str, name: str) -> Dict[str, str]:
    """Append a new secret to an existing config, returns it."""
    try:
        import yaml
    except ImportError:  # pragma: no cover
        raise SystemExit('PyYAML required: pip install pyyaml')
    with open(path, 'r', encoding='utf-8') as fh:
        data = yaml.safe_load(fh) or {}
    from server.config_loader import normalize_secrets
    items = normalize_secrets(data.get('secrets'))
    for it in items:
        if it['name'] == name:
            raise SystemExit(f"secret '{name}' already exists")
    new = {'name': name, 'value': generate_secret()}
    items.append(new)
    data['secrets'] = items
    with open(path, 'w', encoding='utf-8') as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return new


def remove_secret(path: str, name: str) -> None:
    try:
        import yaml
    except ImportError:  # pragma: no cover
        raise SystemExit('PyYAML required: pip install pyyaml')
    with open(path, 'r', encoding='utf-8') as fh:
        data = yaml.safe_load(fh) or {}
    from server.config_loader import normalize_secrets
    items = normalize_secrets(data.get('secrets'))
    left = [it for it in items if it['name'] != name]
    if len(left) == len(items):
        raise SystemExit(f"secret '{name}' not found")
    if not left:
        raise SystemExit('cannot remove the last remaining secret')
    data['secrets'] = left
    with open(path, 'w', encoding='utf-8') as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)


def secret_links(cfg: Dict[str, Any], server: Optional[str] = None,
                 port: Optional[int] = None) -> List[Dict[str, str]]:
    """Build tg://proxy links (and bot snippets) for every secret."""
    server = server or cfg['host']
    if server in ('0.0.0.0', '::', ''):
        server = '<VPS_IP>'
    port = port or int(cfg['port'])
    ftls = str(cfg.get('fake_tls_domain') or '').strip()
    domain_hex = ftls.encode('ascii').hex() if ftls else ''
    out = []
    for s in cfg['secrets']:
        secret = s['value'].lower()
        full = f'ee{secret}{domain_hex}' if ftls else f'dd{secret}'
        link = f'tg://proxy?server={server}&port={port}&secret={full}'
        out.append({
            'name': s['name'],
            'secret': secret,
            'link': link,
            'type': 'ee (FakeTLS)' if ftls else 'dd (plain obfuscated)',
        })
    return out


def bot_snippets(link_host: str, port: int, secret: str,
                 ftls: str = '') -> Dict[str, str]:
    full = (f'ee{secret}{ftls.encode("ascii").hex()}' if ftls
            else f'dd{secret}')
    return {
        'telethon (native MTProto proxy)': (
            "from telethon import TelegramClient\n"
            "proxy = ('mtproto', '127.0.0.1', %d, '%s')\n"
            "client = TelegramClient('bot', API_ID, API_HASH, proxy=proxy)"
            % (port, full)),
        'pyrogram / kurigram (SOCKS5 bridge)': (
            "app = Client(\n"
            "    'bot', api_id=API_ID, api_hash=API_HASH,\n"
            "    proxies={'scheme': 'socks5',\n"
            "             'hostname': '127.0.0.1', 'port': 1080},\n"
            ")"),
        'systemd/socket check': (
            'ss -tlnp | grep -E "%d|%d"' % (port, 1080)),
    }


def print_links(cfg: Dict[str, Any]) -> None:
    links = secret_links(cfg)
    ftls = str(cfg.get('fake_tls_domain') or '').strip()
    port = int(cfg['port'])
    print()
    print('=== tg://proxy links (for Telegram clients / people) ===')
    for it in links:
        print(f'[{it["name"]}] ({it["type"]})')
        print(f'  {it["link"]}')
    print()
    print('=== bot snippets (primary secret) ===')
    snippets = bot_snippets(links[0]['secret'] and '<VPS_IP>', port,
                            links[0]['secret'], ftls)
    for title, code in snippets.items():
        print(f'--- {title} ---')
        print(code)
    s5 = cfg.get('socks5', {})
    if s5.get('enabled'):
        print(f'--- SOCKS5 bridge ---')
        print(f'  socks5://{s5.get("host", "127.0.0.1")}:{s5.get("port", 1080)}')
    print()


def main():  # pragma: no cover - thin CLI wrapper
    from server.cli import main as cli_main
    sys.exit(cli_main())


if __name__ == '__main__':
    main()
