#!/usr/bin/env python3
"""Offline mounted-route provisioning and broker contracts. No live effects."""
from contextlib import nullcontext
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mounted_provision_fixtures', Path(__file__).with_name('coinstall-provision-test.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
p = fixtures.p
sys.path.insert(0, str(Path(__file__).parent))
import broker_test as broker_fixtures


def public(**extra):
    return {'host': 'relay.example.org', 'site_host': 'relay.example.org', 'public_ip': '8.8.8.8',
            'base_url': 'https://relay.example.org/GitRePosted', 'site_url': 'https://relay.example.org/GitRePosted',
            'path_prefix': '/GitRePosted', 'routing_schema': 1,
            'tls_ready': True, 'installed': False, 'shared_host': True, **extra}


class MountedProvisionTests(unittest.TestCase):
    def test_prefix_is_fixed_and_new_installs_preserve_legacy_peer_and_resume_contracts(self):
        for peer, expected in [(None, '/GitRePosted'), ({'path_prefix': '/GitPosted'}, '/GitRePosted'),
                               ({'path_prefix': ''}, '')]:
            with patch.object(p, 'peer_installation', return_value=peer):
                self.assertEqual(expected, p.installation_prefix('8.8.8.8'))
        for marker, expected in [({}, ''), ({'path_prefix': ''}, ''),
                                 ({'path_prefix': '/GitRePosted', 'routing_schema': 1}, '/GitRePosted')]:
            with patch.object(p, 'read_json', return_value=marker), patch.object(p, 'peer_installation') as peer:
                self.assertEqual(expected, p.installation_prefix('8.8.8.8', True))
                peer.assert_not_called()
        for marker in [{'path_prefix': '/GitPosted', 'routing_schema': 1}, {'path_prefix': '/GitRePosted'},
                       {'path_prefix': '/GitRePosted', 'routing_schema': 2},
                       {'path_prefix': '/GitRePosted', 'routing_schema': True}]:
            with self.assertRaises(p.Failure): p.path_prefix(marker)

    def test_no_host_inherits_only_mounted_peer_canonical_host(self):
        args = types.SimpleNamespace(resume=False, public_ip='8.8.8.8', host=None)
        with patch.object(p, 'peer_installation', return_value={'path_prefix': '/GitPosted', 'host': '8.8.8.8', 'site_host': 'shared.example.org'}):
            self.assertEqual(('8.8.8.8', 'shared.example.org'), p.install_target(args))
        with patch.object(p, 'peer_installation', return_value={'path_prefix': '', 'site_host': 'old.example.org'}):
            self.assertEqual(('8.8.8.8', '8.8.8.8'), p.install_target(args))
        args.resume = True
        with patch.object(p, 'read_json', return_value={'public_ip': '8.8.8.8', 'host': 'saved.example.org'}), patch.object(p, 'peer_installation') as peer:
            self.assertEqual(('8.8.8.8', 'saved.example.org'), p.install_target(args))
            peer.assert_not_called()

    def test_preflight_accepts_shared_mounted_ip_and_checks_both_private_ports(self):
        base = fixtures.CoInstallProvisionTests()
        with base.preflight_fixture({'project': 'gitposted', 'path_prefix': '/GitPosted'}) as (_, bound), patch.object(p, 'verify_passive_apache_stub'):
            self.assertTrue(p.preflight(host='8.8.8.8', ip='8.8.8.8', explicit_host=False))
        self.assertEqual([('0.0.0.0', 3010), ('::', 3010), ('0.0.0.0', 8182), ('::', 8182)], bound)
        with base.preflight_fixture({'project': 'gitposted', 'path_prefix': ''}), self.assertRaises(p.Failure) as raised:
            p.preflight(host='8.8.8.8', ip='8.8.8.8', explicit_host=False)
        self.assertEqual('SECOND_HOST_REQUIRED', raised.exception.code)

    def test_claim_validation_passes_prefix_and_keeps_pending_history(self):
        state = public(acme_hosts=['old.example.org'], pending_host='new.example.org')
        with patch.object(p.coinstall, 'validate_hosts') as validate:
            p.ensure_hosts_available(state)
        self.assertEqual(('gitreposted', ['relay.example.org', 'relay.example.org', 'old.example.org', 'new.example.org'], '8.8.8.8'), validate.call_args.args)
        self.assertEqual({'path_prefix': '/GitRePosted'}, validate.call_args.kwargs)

    def test_backend_is_private_stripped_and_keeps_external_php_uri_and_redirects(self):
        text = p.nginx_content(public())
        checked = p.gateway._backend('gitreposted', text)
        self.assertIn('listen 127.0.0.1:8182;', checked)
        self.assertNotIn('listen 80', checked)
        self.assertNotIn('listen 443', checked)
        self.assertIn('absolute_redirect off;', checked)
        self.assertIn('port_in_redirect off;', checked)
        self.assertIn('set_real_ip_from 127.0.0.1;', checked)
        self.assertEqual(2, checked.count('fastcgi_param REQUEST_URI $http_x_original_uri;'))
        self.assertIn('return 302 /GitRePosted/install/;', checked)
        self.assertIn('location = /webhooks/telegram', checked)
        self.assertIn('proxy_pass http://127.0.0.1:3010;', checked)
        installed = p.nginx_content(public(installed=True))
        self.assertNotIn('return 302 /GitRePosted/install/;', installed)
        self.assertNotIn('SCRIPT_FILENAME ' + str(p.INSTALL) + '/web/index.php', installed)

    def test_gateway_result_is_applied_without_losing_installer_checkpoint(self):
        state = public(version='fixture', job={'status': 'idle'}, tls_ready=False)
        with patch.object(p, 'shared_lock', return_value=nullcontext()), patch.object(p, 'ensure_hosts_available'), \
             patch.object(p.gateway, 'configure', return_value={'tls_ready': True, 'install_url': state['base_url'] + '/install/'}) as configure:
            p.configure_nginx(state)
        self.assertTrue(state['tls_ready'])
        self.assertEqual('fixture', state['version'])
        self.assertEqual({'status': 'idle'}, state['job'])
        self.assertEqual('gitreposted', configure.call_args.args[0])

    def test_broker_sandbox_allows_own_http01_webroot_and_suite_registry(self):
        captured = {}
        with patch.object(p, 'atomic', side_effect=lambda target, value, *args: captured.setdefault(str(target), value)), patch.object(p, 'run'):
            p.units()
        unit = captured['/etc/systemd/system/gitreposted-installer.service']
        line = next(line for line in unit.splitlines() if line.startswith('ReadWritePaths='))
        self.assertIn(str(p.ACME), line.split())
        self.assertIn('-/var/lib/gitposted-suite', line.split())
        self.assertIn('ProtectSystem=full', unit)

    def test_certificate_reuses_ready_owner_and_never_issues_for_unready_sibling(self):
        for ready in (True, False):
            with patch.object(p, 'shared_lock', return_value=nullcontext()), patch.object(p, 'read_json', return_value=public()), \
                 patch.object(p, 'ensure_hosts_available'), patch.object(p, 'configure_nginx') as configure, \
                 patch.object(p.gateway, 'get_authority', return_value={'owner': 'gitposted', 'tls_ready': ready}), \
                 patch.object(p, '_obtain_certificate') as issue, patch.object(p.gateway, 'mark_tls_ready') as mark:
                if ready: p.obtain_certificate('relay.example.org', '8.8.8.8')
                else:
                    with self.assertRaises(p.Failure) as raised: p.obtain_certificate('relay.example.org', '8.8.8.8')
                    self.assertEqual('TLS_OWNER_NOT_READY', raised.exception.code)
                configure.assert_called_once(); issue.assert_not_called(); mark.assert_not_called()
        events = []
        with patch.object(p, 'shared_lock', return_value=nullcontext()), patch.object(p, 'read_json', return_value=public()), \
             patch.object(p, 'ensure_hosts_available'), patch.object(p, 'configure_nginx', side_effect=lambda _: events.append('route')), \
             patch.object(p.gateway, 'get_authority', return_value={'owner': 'gitreposted', 'tls_ready': False}), \
             patch.object(p, '_obtain_certificate', side_effect=lambda *args: events.append('issue')), \
             patch.object(p.gateway, 'mark_tls_ready', side_effect=lambda *args: events.append('publish')):
            p.obtain_certificate('relay.example.org', '8.8.8.8')
        self.assertEqual(['route', 'issue', 'publish'], events)

    def test_renewal_processes_all_ready_owned_authorities_and_never_sibling(self):
        authorities = {'relay.example.org': {'owner': 'gitposted', 'tls_ready': True},
                       'retired.example.org': {'owner': 'gitreposted', 'tls_ready': True},
                       'pending.example.org': {'owner': 'gitreposted', 'tls_ready': False}}
        registry = {'projects': {'gitreposted': public()}, 'authorities': authorities}
        with patch.object(p.os, 'geteuid', return_value=0, create=True), patch.object(p, 'shared_lock', return_value=nullcontext()), \
             patch.object(p, 'read_json', return_value=public()), \
             patch.object(p, 'ensure_hosts_available', side_effect=AssertionError('Renewal must not inspect a pending peer')), \
             patch.object(p, 'peer_installation', side_effect=AssertionError('Renewal must not inspect a pending peer')), \
             patch.object(p.gateway, 'read_registry', return_value=registry), \
             patch.object(p, 'renewal_config_exists', return_value=True) as exists, patch.object(p, 'run') as run:
            p.renew_certificates()
        exists.assert_called_once_with('retired.example.org')
        self.assertIn(p.cert_name('retired.example.org'), run.call_args.args[0])
        with patch.object(p.os, 'geteuid', return_value=0, create=True), patch.object(p, 'shared_lock', return_value=nullcontext()), \
             patch.object(p, 'read_json', return_value=public()), patch.object(p, 'ensure_hosts_available'), \
             patch.object(p.gateway, 'read_registry', return_value=registry), \
             patch.object(p, 'renewal_config_exists', return_value=False), patch.object(p, 'run') as run, self.assertRaises(p.Failure) as raised:
            p.renew_certificates()
        self.assertEqual('TLS_STATE', raised.exception.code)
        run.assert_not_called()

    def test_mounted_renewal_requires_own_immutable_registry_descriptor(self):
        for own in [None, {**public(), 'host': 'other.example.org'}, {**public(), 'public_ip': '1.1.1.1'},
                    {**public(), 'path_prefix': '/GitPosted'}]:
            with self.subTest(own=own), patch.object(p.os, 'geteuid', return_value=0, create=True), \
                 patch.object(p, 'shared_lock', return_value=nullcontext()), patch.object(p, 'read_json', return_value=public()), \
                 patch.object(p, 'ensure_hosts_available', side_effect=AssertionError('Peer inspection forbidden')), \
                 patch.object(p.gateway, 'read_registry', return_value={'projects': {} if own is None else {'gitreposted': own}, 'authorities': {}}), \
                 patch.object(p, 'renewal_config_exists') as exists, patch.object(p, 'run') as run, self.assertRaises(p.Failure) as raised:
                p.renew_certificates()
            self.assertEqual('TLS_STATE', raised.exception.code)
            exists.assert_not_called(); run.assert_not_called()

    def test_mounted_renewal_skips_foreign_owned_and_unissued_certificates(self):
        registry = {'projects': {'gitreposted': public()}, 'authorities': {
            'relay.example.org': {'owner': 'gitposted', 'tls_ready': True},
            'pending.example.org': {'owner': 'gitreposted', 'tls_ready': False}}}
        with patch.object(p.os, 'geteuid', return_value=0, create=True), patch.object(p, 'shared_lock', return_value=nullcontext()), \
             patch.object(p, 'read_json', return_value=public()), \
             patch.object(p, 'ensure_hosts_available', side_effect=AssertionError('Peer inspection forbidden')), \
             patch.object(p.gateway, 'read_registry', return_value=registry), \
             patch.object(p, 'renewal_config_exists') as exists, patch.object(p, 'run') as run:
            p.renew_certificates()
        exists.assert_not_called(); run.assert_not_called()

    def test_terminal_reconciliation_retains_prefix_and_cleans_duplicate_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            metadata = public(installed=False)
            marker = {'installed_at': 123, 'version': 'fixture', 'admin_url': 'https://relay.example.org/GitRePosted/control/',
                      'path_prefix': '/GitRePosted', 'routing_schema': 1}
            for name, value in [('installed.json', marker), ('public.json', metadata), ('private.json', {'config': {'secret': 'fixture'}, 'settings': {}})]:
                (state / name).write_text(json.dumps(value), encoding='utf8')
            with patch.object(p, 'STATE', state), patch.object(p, 'save_json', side_effect=lambda path, value, public=False: path.write_text(json.dumps(value), encoding='utf8')):
                self.assertTrue(p.reconcile_installed())
            saved = json.loads((state / 'public.json').read_text())
            self.assertEqual('/GitRePosted', saved['path_prefix'])
            self.assertEqual('https://relay.example.org/GitRePosted', saved['site_url'])
            self.assertEqual({}, json.loads((state / 'private.json').read_text()))


class MountedBrokerTests(unittest.TestCase):
    setUp = broker_fixtures.BrokerTests.setUp
    tearDown = broker_fixtures.BrokerTests.tearDown
    save_json = broker_fixtures.BrokerTests.save_json
    persist = broker_fixtures.BrokerTests.persist
    make = broker_fixtures.BrokerTests.make

    def test_domain_and_terminal_marker_keep_mount_through_resume_reconciliation(self):
        q = broker_fixtures.p
        self.public = public()
        self.private = {'host_settings': {'host': 'canonical.example.org', 'email': ''}}
        app = self.make()
        with patch.object(q, 'configure_nginx') as configure:
            app.host_step('nginx')
        self.assertEqual('https://canonical.example.org/GitRePosted', app.public['site_url'])
        self.assertEqual('/GitRePosted', configure.call_args.args[0]['path_prefix'])
        app.private['settings'] = broker_fixtures.broker.settings(broker_fixtures.valid_settings())
        app.private['config'] = {'base_url': app.public['site_url']}
        with patch.object(q, 'configure_nginx'):
            app.install_step('finish')
        marker = json.loads((self.state / 'installed.json').read_text())
        self.assertEqual('/GitRePosted', marker['path_prefix'])
        self.assertEqual(1, marker['routing_schema'])
        app.save()
        self.assertTrue(q.reconcile_installed())
        saved = json.loads((self.state / 'public.json').read_text())
        self.assertEqual('https://canonical.example.org/GitRePosted', saved['site_url'])
        self.assertEqual('https://canonical.example.org/GitRePosted/control/', saved['admin_url'])

    def test_generated_node_environment_uses_external_prefixed_site_url(self):
        q = broker_fixtures.p
        self.public = public()
        self.private = {'settings': broker_fixtures.broker.settings(broker_fixtures.valid_settings())}
        app = self.make()
        with patch.object(q, 'run', return_value=b'0'):
            app.install_step('database')
        self.assertEqual(self.public['site_url'], app.private['config']['base_url'])
        with patch.object(q, 'atomic') as output:
            app.write_config(app.private['config'])
        config = json.loads(output.call_args.args[1])
        self.assertEqual(self.public['site_url'], config['PUBLIC_BASE_URL'])
        self.assertEqual('127.0.0.1', config['HOST'])
        self.assertEqual('3010', config['PORT'])


if __name__ == '__main__': unittest.main()
