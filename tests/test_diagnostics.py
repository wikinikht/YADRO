"""
[server fork] Tests for tgws-server diagnose (server/diagnostics.py).

Offline-first: every test runs with offline=True so CI never touches the
network. Live e2e (in-process stack boot + synthetic client) is guarded
by TGWS_LIVE like tests/test_live_e2e.py.

Also covers the likely-cause engine: given a synthetic set of failed
checks it must name the right probable cause (config missing, firewall
egress, TSPU SNI filtering, DNS poisoning, bridge down, log errors...).
"""

import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.diagnostics import (  # noqa: E402
    DiagnoseReport, CheckResult,
    run_diagnostics, run_diagnose_cli,
    OK, WARN, FAIL, SKIP, INFO, GROUPS,
)
from server.config_loader import load_config  # noqa: E402


def _write_config(tmpdir: str, body: str) -> str:
    path = os.path.join(tmpdir, 'tgws-server.yaml')
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(body)
    os.chmod(path, 0o600)
    return path


VALID_CFG = """\
host: 127.0.0.1
port: 1443
fake_tls_domain: ""
secrets:
  - name: main
    value: "11" * 16
""".replace('"11" * 16', '11111111111111111111111111111111')


class EnvDepsCryptoTest(unittest.TestCase):
    def test_env_group_clean(self):
        rep = run_diagnostics(offline=True, group='ENV')
        names = [c.name for c in rep.checks]
        for expected in ('python >= 3.8', 'platform', 'disk space',
                         'utf-8 stdout'):
            self.assertIn(expected, names)
        self.assertEqual([c.status for c in rep.checks if c.name == 'python >= 3.8'],
                         [OK])

    def test_deps_group_clean(self):
        rep = run_diagnostics(offline=True, group='DEPS')
        fails = [c for c in rep.checks if c.status == FAIL]
        self.assertEqual(fails, [], f'deps must be importable: {fails}')

    def test_crypto_selftest_all_ok(self):
        rep = run_diagnostics(offline=True, group='CRYPTO')
        self.assertEqual(len(rep.checks), 4)
        for c in rep.checks:
            self.assertEqual(c.status, OK, f'{c.name}: {c.detail}')

    def test_group_filter_exclusive(self):
        rep = run_diagnostics(offline=True, group='CRYPTO')
        self.assertTrue(rep.checks)
        self.assertTrue(all(c.group == 'CRYPTO' for c in rep.checks))


class ConfigChecksTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='tgws-diag-')

    def _diag(self, body: str):
        path = _write_config(self.tmp, body)
        return run_diagnostics(path, offline=True, group='CONFIG')

    def _one(self, rep, name):
        found = [c for c in rep.checks if c.name == name]
        self.assertTrue(found, f'check {name!r} missing in '
                               f'{[c.name for c in rep.checks]}')
        return found[0]

    def test_missing_config(self):
        rep = run_diagnostics('/nonexistent/tgws.yaml', offline=True,
                              group='CONFIG')
        c = self._one(rep, 'load config')
        self.assertEqual(c.status, FAIL)
        self.assertIn('tgws-server gen', c.fix)
        # and the cause engine explains it
        causes = rep.likely_causes()
        self.assertTrue(any('конфиг' in x['cause'] for x in causes))

    def test_valid_config_ok(self):
        rep = self._diag(VALID_CFG)
        c = self._one(rep, 'load config')
        self.assertEqual(c.status, OK, c.detail)
        self.assertEqual(rep.exit_code() in (0, 2), True)

    def test_broken_yaml(self):
        rep = self._diag('secrets: [ {name: x, value: 1\n  broken')
        self.assertEqual(self._one(rep, 'load config').status, FAIL)

    def test_bad_secret_length(self):
        rep = self._diag(
            'secrets:\n  - name: main\n    value: "aabb"\n')
        c = self._one(rep, 'load config')
        self.assertEqual(c.status, FAIL)
        self.assertIn('32 hex', c.detail)

    def test_weak_secret_warns(self):
        rep = self._diag(
            'secrets:\n  - name: weak\n    value: "'
            + 'a' * 32 + '"\n')
        c = self._one(rep, "secret 'weak'")
        self.assertEqual(c.status, WARN)

    def test_duplicate_secrets_warn(self):
        v = 'ab' * 16
        rep = self._diag(
            f'secrets:\n  - name: a\n    value: "{v}"\n'
            f'  - name: b\n    value: "{v}"\n')
        self.assertEqual(self._one(rep, 'secrets uniqueness').status, WARN)

    def test_dd_ee_prefix_tolerated(self):
        rep = self._diag(
            'secrets:\n  - name: p\n    value: "dd'
            + 'ab' * 16 + '"\n')
        self.assertEqual(self._one(rep, 'load config').status, OK)

    def test_dc_pinning_drift_warns(self):
        body = VALID_CFG + (
            '\ndc_ips:\n  - "2:1.2.3.4"\n  - "4:1.2.3.4"\n')
        rep = self._diag(body)
        c = self._one(rep, 'dc_ips pinning')
        self.assertEqual(c.status, WARN)
        causes = rep.likely_causes()
        self.assertTrue(any('dc_ips' in x['cause'] and '149.154.167.220'
                            in x['remedy'] for x in causes))

    def test_socks5_exposure_warns(self):
        body = VALID_CFG + (
            '\nsocks5:\n  enabled: true\n  host: 0.0.0.0\n  port: 1080\n')
        rep = self._diag(body)
        c = self._one(rep, 'socks5 binding')
        self.assertEqual(c.status, WARN)
        self.assertIn('файрвол', c.fix)

    def test_socks5_loopback_ok(self):
        body = VALID_CFG + (
            '\nsocks5:\n  enabled: true\n  host: 127.0.0.1\n  port: 1080\n')
        rep = self._diag(body)
        self.assertEqual(self._one(rep, 'socks5 binding').status, OK)

    def test_bad_fake_tls_domain_warns(self):
        body = VALID_CFG + '\nfake_tls_domain: "telegram.org"\n'
        rep = self._diag(body)
        self.assertEqual(self._one(rep, 'fake_tls_domain').status, WARN)

    def test_wide_permissions_warn(self):
        path = _write_config(self.tmp, VALID_CFG)
        os.chmod(path, 0o644)
        rep = run_diagnostics(path, offline=True, group='CONFIG')
        c = self._one(rep, 'config permissions')
        self.assertEqual(c.status, WARN)
        self.assertIn('chmod 600', c.fix)


class OfflineSweepTest(unittest.TestCase):
    """The full offline sweep: deterministic, no network, exit codes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='tgws-diag-')
        self.cfg = _write_config(self.tmp, VALID_CFG)

    def test_offline_sweep_no_failures(self):
        rep = run_diagnostics(self.cfg, offline=True)
        fails = [c for c in rep.checks if c.status == FAIL]
        self.assertEqual(fails, [], f'offline sweep must be clean: {fails}')

    def test_offline_skips_live_network(self):
        rep = run_diagnostics(self.cfg, offline=True, group='NETWORK')
        self.assertEqual([c.status for c in rep.checks], [SKIP])

    def test_full_downgraded_offline(self):
        rep = run_diagnostics(self.cfg, offline=True, full=True)
        self.assertFalse(rep.full)
        self.assertTrue(all(c.status == SKIP for c in rep.checks
                            if c.name.startswith('e2e')))

    def test_nonfull_marks_e2e_skip(self):
        rep = run_diagnostics(self.cfg, offline=True)
        e2e = [c for c in rep.checks if c.name.startswith('e2e')]
        self.assertTrue(e2e)
        self.assertTrue(all(c.status == SKIP for c in e2e))

    def test_log_scan_clean_and_error(self):
        log = os.path.join(self.tmp, 'tgws.log')
        body = VALID_CFG + f'\nlog_file: "{log}"\n'
        with open(log, 'w', encoding='utf-8') as fh:
            fh.write('12:00:00  INFO   WS pool warm\n')
        rep = run_diagnostics(_write_config(self.tmp, body), offline=True)
        clean = [c for c in rep.checks if c.name == 'server log scan']
        self.assertEqual(clean[0].status, OK)

        with open(log, 'a', encoding='utf-8') as fh:
            fh.write('12:01:00  ERROR  bad handshake from 1.2.3.4\n')
        rep = run_diagnostics(_write_config(self.tmp, body), offline=True)
        warn = [c for c in rep.checks if c.name == 'server log scan']
        self.assertEqual(warn[0].status, WARN)
        self.assertIn('bad handshake', warn[0].detail)

        with open(log, 'a', encoding='utf-8') as fh:
            fh.write('12:02:00 CRITICAL boom\nTraceback (most recent):\n')
        rep = run_diagnostics(_write_config(self.tmp, body), offline=True)
        bad = [c for c in rep.checks if c.name == 'server log scan']
        self.assertEqual(bad[0].status, FAIL)

    def test_exit_codes(self):
        self.assertEqual(run_diagnostics(self.cfg, offline=True).exit_code(), 2)
        rep = run_diagnostics('/nonexistent/x.yaml', offline=True)
        self.assertEqual(rep.exit_code(), 1)


class ReportsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='tgws-diag-')
        self.cfg = _write_config(self.tmp, VALID_CFG)

    def test_json_parseable(self):
        rep = run_diagnostics(self.cfg, offline=True)
        data = json.loads(rep.to_json())
        self.assertEqual(data['summary'], rep.counts())
        self.assertEqual(data['exit_code'], rep.exit_code())
        self.assertEqual(len(data['checks']), len(rep.checks))
        for c in data['checks']:
            self.assertIn(c['status'], (OK, WARN, FAIL, SKIP, INFO))
            self.assertIn(c['group'], GROUPS)

    def test_markdown_report_written(self):
        j = os.path.join(self.tmp, 'r.json')
        m = os.path.join(self.tmp, 'r.md')
        code = run_diagnose_cli(self.cfg, offline=True, json_out=j, md_out=m)
        self.assertEqual(code, 2)
        data = json.load(open(j, encoding='utf-8'))
        self.assertGreater(len(data['checks']), 20)
        md = open(m, encoding='utf-8').read()
        for section in ('## ENV', '## DEPS', '## CONFIG', '## CRYPTO',
                        '## SOCKS5', '## RUNTIME'):
            self.assertIn(section, md)
        self.assertNotIn('None', md.replace('None.', ''))

    def test_render_text_sections(self):
        rep = run_diagnostics(self.cfg, offline=True)
        text = rep.render_text()
        for section in ('[ENV]', '[DEPS]', '[CONFIG]', '[CRYPTO]',
                        '[SOCKS5]', '[RUNTIME]', 'summary:',
                        'ВЕРОЯТНЫЕ ПРИЧИНЫ'):
            self.assertIn(section, text)


class LikelyCauseEngineTest(unittest.TestCase):
    """Feed synthetic failure sets, expect the right diagnosis."""

    @staticmethod
    def _rep_with(checks):
        rep = DiagnoseReport('x.yaml', offline=False, full=False)
        for group, name, status, detail in checks:
            rep.add(group, name, status, detail)
        return rep

    def test_no_causes_when_clean(self):
        rep = self._rep_with([('CONFIG', 'load config', OK, 'fine')])
        self.assertEqual(rep.likely_causes(), [])

    def test_config_missing(self):
        rep = self._rep_with([('CONFIG', 'load config', FAIL, 'not found')])
        causes = rep.likely_causes()
        self.assertTrue(any('tgws-server gen' in c['remedy'] for c in causes))

    def test_egress_firewall(self):
        rep = self._rep_with([
            ('NETWORK', 'TCP 149.154.167.220:443', FAIL, 'timeout'),
            ('NETWORK', 'WS gateway kws2 via 149.154.167.220', FAIL,
             'TimeoutError'),
        ])
        causes = rep.likely_causes()
        self.assertTrue(any('файрвол' in c['cause'] or 'хостер' in c['cause']
                            for c in causes))

    def test_tspu_sni_filtering(self):
        rep = self._rep_with([
            ('NETWORK', 'TCP 149.154.167.220:443', OK, 'reachable'),
            ('NETWORK', 'WS gateway kws2 via 149.154.167.220', FAIL,
             'HTTP 404'),
        ])
        causes = rep.likely_causes()
        self.assertTrue(any('4xx' in c['cause'] or 'SNI' in c['cause']
                            for c in causes))
        self.assertTrue(any('cfproxy_domains' in c['remedy'] for c in causes))

    def test_tspu_timeout_after_tcp_ok(self):
        rep = self._rep_with([
            ('NETWORK', 'TCP 149.154.167.220:443', OK, 'reachable'),
            ('NETWORK', 'WS gateway kws2 via 149.154.167.220', FAIL,
             'asyncio.TimeoutError: timed out'),
        ])
        causes = rep.likely_causes()
        self.assertTrue(any('TSPU' in c['cause'] for c in causes))
        self.assertTrue(any('149.154.167' in c['remedy'] for c in causes))

    def test_dns_poisoning_nonfatal(self):
        rep = self._rep_with([
            ('NETWORK', 'DNS kws2.web.telegram.org', WARN,
             'unexpected IP 8.8.8.8'),
        ])
        causes = rep.likely_causes()
        self.assertTrue(any('подмен' in c['cause'] for c in causes))
        self.assertTrue(all('dc_ips' in c['remedy'] or 'DoH' in c['remedy']
                            for c in causes))

    def test_bridge_down(self):
        rep = self._rep_with([
            ('SOCKS5', 'SOCKS5 bridge port', WARN, 'not running'),
        ])
        causes = rep.likely_causes()
        self.assertTrue(any('мост' in c['cause'] for c in causes))

    def test_log_traceback(self):
        rep = self._rep_with([
            ('RUNTIME', 'server log scan', FAIL,
             'Traceback (most recent call last)'),
        ])
        causes = rep.likely_causes()
        self.assertTrue(any('Traceback' in c['cause'] or
                            'журнал' in c['cause'] for c in causes))


@unittest.skipUnless(os.environ.get('TGWS_LIVE'), 'TGWS_LIVE not set')
class LiveFullE2ETest(unittest.TestCase):
    """--full in live conditions: boots the stack in-process, probes both
    entry points with synthetic MTProto clients, restores proxy_config."""

    def test_full_e2e_and_state_restore(self):
        from proxy.config import proxy_config

        tmp = tempfile.mkdtemp(prefix='tgws-diag-live-')
        path = _write_config(tmp, VALID_CFG)
        snap = dict(vars(proxy_config))
        try:
            rep = run_diagnostics(path, full=True, timeout=6)
            e2e = [c for c in rep.checks
                   if c.name.startswith('e2e') and c.status != SKIP]
            self.assertTrue(e2e, 'full mode must run e2e probes')
            for c in e2e:
                self.assertIn(c.status, (OK, WARN),
                              f'{c.name}: {c.detail}')
            ws = [c for c in rep.checks
                  if c.name.startswith('WS gateway') and c.status == FAIL]
            self.assertEqual(ws, [], f'WS gateway must be reachable: {ws}')
        finally:
            for k, v in snap.items():
                setattr(proxy_config, k, v)
            self.assertEqual(vars(proxy_config), snap,
                             'diagnose --full must leave proxy_config intact')


if __name__ == '__main__':
    unittest.main()
