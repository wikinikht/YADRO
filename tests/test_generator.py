"""
[server fork] Config generator / loader tests.
"""

import os
import tempfile
import unittest

from server.config_loader import (
    load_config, apply_config, normalize_secrets, ConfigError,
)
from server.generator import (
    build_config_dict, render_config, write_config, add_secret,
    remove_secret, secret_links,
)
from proxy.config import proxy_config


class GeneratorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'tgws-server.yaml')

    def test_build_and_render(self):
        cfg = build_config_dict(n_secrets=3, port=2443,
                                fake_tls_domain='example.org')
        self.assertEqual(len(cfg['secrets']), 3)
        names = [s['name'] for s in cfg['secrets']]
        self.assertEqual(names[0], 'main')
        self.assertEqual(len(set(names)), 3)
        text = render_config(cfg)
        self.assertIn('port: 2443', text)
        self.assertIn('example.org', text)
        for s in cfg['secrets']:
            self.assertIn(s['value'], text)

    def test_write_load_roundtrip(self):
        cfg = build_config_dict(n_secrets=2, port=1443)
        write_config(self.path, cfg)
        self.assertTrue(os.path.exists(self.path))
        loaded = load_config(self.path)
        self.assertEqual(loaded['port'], 1443)
        self.assertEqual(len(loaded['secrets']), 2)
        self.assertEqual(loaded['secrets'][0]['value'],
                         cfg['secrets'][0]['value'])
        # config file must be 0600
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_load_rejects_bad_secret(self):
        cfg = build_config_dict(n_secrets=1)
        cfg['secrets'][0]['value'] = 'zz'
        write_config(self.path, cfg, force=True)
        with self.assertRaises(ConfigError):
            load_config(self.path)

    def test_normalize_string_list(self):
        items = normalize_secrets(['aa' * 16, {'name': 'x', 'value': 'bb' * 16}])
        self.assertEqual(items[0]['name'], 'secret-1')
        self.assertEqual(items[1]['name'], 'x')

    def test_add_remove_secret(self):
        cfg = build_config_dict(n_secrets=1)
        write_config(self.path, cfg)
        created = add_secret(self.path, 'tester')
        loaded = load_config(self.path)
        self.assertEqual(len(loaded['secrets']), 2)
        self.assertIn('tester', [s['name'] for s in loaded['secrets']])
        remove_secret(self.path, 'tester')
        loaded = load_config(self.path)
        self.assertEqual(len(loaded['secrets']), 1)

    def test_links_dd_and_ee(self):
        cfg = build_config_dict(n_secrets=1, fake_tls_domain='')
        links = secret_links(cfg, server='1.2.3.4')
        self.assertTrue(links[0]['link'].startswith(
            f"tg://proxy?server=1.2.3.4&port={cfg['port']}&secret=dd"))
        cfg = build_config_dict(n_secrets=1, fake_tls_domain='example.org')
        links = secret_links(cfg, server='1.2.3.4')
        secret = cfg['secrets'][0]['value']
        self.assertEqual(links[0]['link'],
                         f'tg://proxy?server=1.2.3.4&port={cfg["port"]}'
                         f'&secret=ee{secret}example.org'.replace(
                             'example.org', 'example.org'.encode().hex()))
        self.assertIn('example.org'.encode().hex(), links[0]['link'])

    def test_links_mask_wildcard_host(self):
        cfg = build_config_dict(n_secrets=1)
        cfg['host'] = '0.0.0.0'
        links = secret_links(cfg)
        self.assertIn('<VPS_IP>', links[0]['link'])


class ApplyConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'tgws-server.yaml')
        # snapshot the full upstream singleton so tests don't leak state
        import dataclasses
        self._orig = {f.name: getattr(proxy_config, f.name)
                      for f in dataclasses.fields(proxy_config)}

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(proxy_config, k, v)

    def test_apply_multi_secret(self):
        cfg = build_config_dict(n_secrets=3, port=9443,
                                fake_tls_domain='test.example')
        write_config(self.path, cfg, force=True)
        loaded = load_config(self.path)
        apply_config(loaded)
        self.assertEqual(proxy_config.port, 9443)
        self.assertEqual(proxy_config.fake_tls_domain, 'test.example')
        self.assertEqual(len(proxy_config.secrets_list), 3)
        self.assertEqual(proxy_config.secrets_list[0],
                         cfg['secrets'][0]['value'])


if __name__ == '__main__':
    unittest.main()
