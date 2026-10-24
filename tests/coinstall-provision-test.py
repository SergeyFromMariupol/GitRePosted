#!/usr/bin/env python3
"""Offline co-install contract checks; no real services, databases or providers."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name != 'posix':
    sys.modules.setdefault('pwd', types.SimpleNamespace())
    sys.modules.setdefault('grp', types.SimpleNamespace())
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *_: None))

spec = importlib.util.spec_from_file_location('coinstall_reposted_provision', Path(__file__).resolve().parents[1] / 'lib/provision.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class CoInstallProvisionTests(unittest.TestCase):
    def public(self, shared=True):
        return {'host': 'relay.example.org', 'site_host': 'relay.example.org', 'public_ip': '8.8.8.8',
                'tls_ready': True, 'installed': True, 'shared_host': shared}

    @contextlib.contextmanager
    def preflight_fixture(self, peer):
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            for name in ('INSTALL', 'APP', 'STATE', 'DATA', 'CONFIG', 'LOG', 'SITE', 'ENABLED_SITE', 'NODE_ROOT'):
                stack.enter_context(patch.object(p, name, Path(temporary) / name / ('config.json' if name == 'CONFIG' else 'target')))
            original = Path.read_text
            def read_text(path, *args, **kwargs):
                if str(path).replace('\\', '/') == '/etc/os-release':
                    return 'ID=ubuntu\nVERSION_ID="24.04"\n'
                if str(path).replace('\\', '/') == '/proc/meminfo':
                    return 'MemTotal: 2000000 kB\n'
                return original(path, *args, **kwargs)
            stack.enter_context(patch.object(Path, 'read_text', read_text))
            stack.enter_context(patch.object(p.os, 'geteuid', return_value=0, create=True))
            stack.enter_context(patch.object(p.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=8 * 1024**3)))
            stack.enter_context(patch.object(p, 'node_archive'))
            stack.enter_context(patch.object(p, 'read_json', return_value=None))
            stack.enter_context(patch.object(p.pwd, 'getpwnam', side_effect=KeyError, create=True))
            stack.enter_context(patch.object(p, 'peer_installation', return_value=peer))
            stack.enter_context(patch.object(p, 'ensure_hosts_available', return_value=peer))
            stack.enter_context(patch.object(p.shutil, 'which', return_value=None))
            bound = []
            class Socket:
                def __enter__(self): return self
                def __exit__(self, *_): return None
                def setsockopt(self, *_): pass
                def bind(self, address): bound.append(address)
            stack.enter_context(patch.object(p.socket, 'socket', return_value=Socket()))
            yield stack, bound

    def test_second_named_vhost_reuses_ports_and_omits_all_default_flags(self):
        public = self.public()
        public.update({'site_host': 'new-relay.example.org', 'pending_host': 'pending.example.org',
                       'acme_hosts': ['historic.example.org']})
        text = p.nginx_content(public)
        http, tls = text.split('listen 443 ssl', 1)
        self.assertNotIn('default_server', text)
        self.assertIn('server_name relay.example.org new-relay.example.org historic.example.org pending.example.org;', http)
        self.assertNotIn('pending.example.org', tls)
        self.assertNotIn('historic.example.org', tls)
        self.assertIn('proxy_pass http://127.0.0.1:3010;', text)
        self.assertIn('location ^~ /.well-known/acme-challenge/', http)

    def test_first_remains_single_default_owner_with_named_acme_routes(self):
        text = p.nginx_content({**self.public(False), 'site_host': 'second.example.org'})
        self.assertEqual(2, text.count('default_server'))
        self.assertIn('server_name relay.example.org second.example.org;', text)
        self.assertIn('listen 80 default_server;', text)

    def test_invalid_alias_or_shared_flag_is_not_rendered(self):
        for extra in ({'shared_host': 'false'}, {'acme_hosts': 'evil.example.org'},
                      {'acme_hosts': ['evil; include /etc/passwd']},
                      {'acme_hosts': ['a.example.org'] * 33}):
            with self.subTest(extra=extra), self.assertRaises(p.Failure):
                p.nginx_content({**self.public(), **extra})

    def test_shared_preflight_only_requires_its_private_node_port(self):
        with self.preflight_fixture({'project': 'gitposted'}) as (_, bound), patch.object(p, 'verify_passive_apache_stub') as verify:
            self.assertTrue(p.preflight(host='relay.example.org', ip='8.8.8.8'))
            verify.assert_called_once()
        self.assertEqual([('0.0.0.0', 3010), ('::', 3010)], bound)

    def test_shared_passive_php_apache_fragment_requires_exact_package_ownership(self):
        for owner in (b'php8.3-fpm: /etc/apache2/conf-available/php8.3-fpm.conf\n',
                      b'php8.3-fpm:amd64: /etc/apache2/conf-available/php8.3-fpm.conf\n'):
            with self.subTest(owner=owner), patch.object(p.shutil, 'which', return_value=None), \
                 patch.object(p.coinstall, 'passive_apache_stub', return_value=True), patch.object(p, 'run', return_value=owner):
                p.verify_passive_apache_stub()
        with patch.object(p.shutil, 'which', return_value=None), patch.object(p.coinstall, 'passive_apache_stub', return_value=True), \
             patch.object(p, 'run', return_value=b'foreign-package: /etc/apache2/conf-available/php8.3-fpm.conf\n'), \
             self.assertRaises(p.Failure) as raised:
            p.verify_passive_apache_stub()
        self.assertEqual('UNMANAGED_WEB_SERVER', raised.exception.code)

    def test_shared_real_apache_binary_is_refused_before_stub_probe(self):
        with patch.object(p.shutil, 'which', return_value='/usr/sbin/apache2'), \
             patch.object(p.coinstall, 'passive_apache_stub') as inspect, self.assertRaises(p.Failure) as raised:
            p.verify_passive_apache_stub()
        inspect.assert_not_called()
        self.assertEqual('EXISTING_SERVICE', raised.exception.code)

    @unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0, 'POSIX package-owned Apache stub fixture')
    def test_shared_preflight_accepts_real_passive_stub_in_disposable_root(self):
        with tempfile.TemporaryDirectory() as temporary, self.preflight_fixture({'project': 'gitposted'}) as (_, bound), \
             patch.object(p.coinstall, 'ROOT', Path(temporary)), \
             patch.object(p, 'run', return_value=b'php8.3-fpm: /etc/apache2/conf-available/php8.3-fpm.conf\n') as run:
            base = Path(temporary) / 'etc/apache2/conf-available'
            base.mkdir(parents=True, mode=0o755)
            stub = base / 'php8.3-fpm.conf'; stub.write_bytes(b'# package PHP-FPM integration\n'); stub.chmod(0o644)
            self.assertTrue(p.preflight(host='relay.example.org', ip='8.8.8.8'))
            self.assertEqual(['dpkg-query', '--search', '/etc/apache2/conf-available/php8.3-fpm.conf'], run.call_args.args[0])
            self.assertEqual([('0.0.0.0', 3010), ('::', 3010)], bound)

    def test_unknown_web_stack_remains_rejected(self):
        with self.preflight_fixture(None), patch.object(p.shutil, 'which', side_effect=lambda name: '/usr/sbin/nginx' if name == 'nginx' else None):
            with self.assertRaises(p.Failure) as raised:
                p.preflight(host='relay.example.org', ip='8.8.8.8')
        self.assertEqual('EXISTING_SERVICE', raised.exception.code)

    def test_host_collision_stops_before_private_port_or_installation_write(self):
        with self.preflight_fixture({'project': 'gitposted'}) as (_, bound), \
             patch.object(p, 'ensure_hosts_available', side_effect=p.Failure('HOST_IN_USE', 'Fixture collision')), \
             patch.object(p, 'directory') as directory:
            with self.assertRaises(p.Failure) as raised:
                p.preflight(host='occupied.example.org', ip='8.8.8.8')
            directory.assert_not_called()
        self.assertEqual('HOST_IN_USE', raised.exception.code)
        self.assertEqual([], bound)

    def test_resume_requires_same_completed_peer_and_preserves_shared_mode(self):
        marker = {'installer': 'gitreposted-clean-v1', 'shared_host': True}
        with self.preflight_fixture({'project': 'gitposted'}), patch.object(p, 'read_json', return_value=marker):
            self.assertTrue(p.preflight(True, host='relay.example.org', ip='8.8.8.8'))
            with patch.object(p, 'peer_installation', return_value=None), self.assertRaises(p.Failure) as raised:
                p.preflight(True, host='relay.example.org', ip='8.8.8.8')
        self.assertEqual('PEER_MISSING', raised.exception.code)

    def test_second_requires_an_explicit_dns_host_even_if_ip_is_not_peer_base(self):
        for host, explicit in [('relay.example.org', False), ('8.8.8.8', True), (None, False)]:
            with self.subTest(host=host, explicit=explicit), self.preflight_fixture({'project': 'gitposted'}) as (_, bound):
                with self.assertRaises(p.Failure) as raised:
                    p.preflight(host=host, ip='8.8.8.8', explicit_host=explicit)
                self.assertEqual('SECOND_HOST_REQUIRED', raised.exception.code)
                self.assertEqual([], bound)

    def test_shared_packages_skip_apt_and_dpkg_when_already_present(self):
        names = list(p.SYSTEM_PACKAGES)
        inventory = ''.join(name + '\t1.0\tii \n' for name in names).encode()
        with patch.object(p, 'run', return_value=inventory) as run:
            p.prepare_system_packages(True, shared_host=True)
        self.assertEqual(1, run.call_count)
        self.assertEqual('dpkg-query', run.call_args.args[0][0])

    def test_shared_apt_adds_only_missing_packages_without_upgrading_peer(self):
        names = [name for name in p.SYSTEM_PACKAGES if name != 'logrotate']
        versions = {name: '1.0' for name in names}
        with patch.object(p, 'run', side_effect=[b'', b'Inst logrotate (1.0 Ubuntu [amd64])\nConf logrotate (1.0 Ubuntu [amd64])\n', b'']) as run, \
             patch.object(p, 'shared_package_inventory', return_value=versions), patch.object(p, 'wait_package_locks'), \
             patch.object(p, 'shared_package_pins', side_effect=lambda _: contextlib.nullcontext(['-o', 'Dir::Etc::preferences=fixture-frozen'])):
            p.prepare_system_packages(shared_host=True)
        command = run.call_args.args[0]
        self.assertIn('--no-upgrade', command)
        self.assertIn('--no-remove', command)
        self.assertIn('logrotate', command)
        self.assertIn('Dir::Etc::preferences=fixture-frozen', command)
        self.assertIn('--simulate', run.call_args_list[1].args[0])
        self.assertNotIn('nginx', command)
        self.assertNotIn('mysql-server', command)
        self.assertFalse(any(call.args[0][0] == 'dpkg' for call in run.call_args_list))

    def test_damaged_shared_core_does_not_trigger_automatic_reinstallation(self):
        with patch.object(p, 'run', return_value=b'nginx\t1.0\tii \n') as run:
            with self.assertRaises(p.Failure) as raised:
                p.prepare_system_packages(shared_host=True)
        self.assertEqual('SHARED_STACK_CHANGED', raised.exception.code)
        self.assertEqual(1, run.call_count)

    def test_legacy_missing_php_module_refuses_before_apt_or_dpkg_changes(self):
        versions = {name: '1.0' for name in p.SYSTEM_PACKAGES if name != 'php8.3-mysql'}
        with patch.object(p, 'shared_package_inventory', return_value=versions), patch.object(p, 'run') as run:
            with self.assertRaises(p.Failure) as raised:
                p.prepare_system_packages(shared_host=True)
        self.assertEqual('SHARED_PACKAGE_CHANGE_REQUIRED', raised.exception.code)
        run.assert_not_called()

    def test_dependency_plan_cannot_upgrade_remove_reinstall_or_add_php(self):
        for plan in [b'Inst php8.3-common [1.0] (2.0 Ubuntu)\n', b'Remv nginx [1.0]\n',
                     b'Conf nginx (1.0 Ubuntu)\n', b'Inst php8.3-new (1.0 Ubuntu)\n',
                     b'Inst mysql-server-new (1.0 Ubuntu)\n']:
            with self.subTest(plan=plan), self.assertRaises(p.Failure) as raised:
                p.validate_shared_package_plan(plan, {'php8.3-common': '1.0', 'nginx': '1.0'})
            self.assertEqual('SHARED_PACKAGE_CHANGE_REQUIRED', raised.exception.code)
        p.validate_shared_package_plan(b'Inst unzip (1.0 Ubuntu)\nConf unzip (1.0 Ubuntu)\n', {'nginx': '1.0'})

    def test_changed_package_snapshot_stops_before_real_apt_install(self):
        versions = {'nginx': '1.0', 'mysql-server': '1.0', 'php8.3-fpm': '1.0'}
        with patch.object(p, 'wait_package_locks'), \
             patch.object(p, 'shared_package_pins', side_effect=lambda _: contextlib.nullcontext([])), \
             patch.object(p, 'run', side_effect=[b'', b'Inst unzip (1.0 Ubuntu)\n']) as run, \
             patch.object(p, 'shared_package_inventory', return_value={**versions, 'nginx': '2.0'}):
            with self.assertRaises(p.Failure) as raised: p.add_shared_packages(['unzip'], versions)
        self.assertEqual('SHARED_STACK_CHANGED', raised.exception.code)
        self.assertEqual(2, run.call_count)
        self.assertFalse(any('-y' in call.args[0] for call in run.call_args_list))

    def test_pin_preferences_freeze_architectures_and_reject_injected_values(self):
        pins = p.frozen_package_preferences({'nginx:amd64': '1:1.0+ubuntu~1'})
        self.assertIn(b'Package: nginx:amd64\nPin: version 1:1.0+ubuntu~1\nPin-Priority: 1001', pins)
        self.assertIn(b'Pin: version ?*\nPin-Priority: -1', pins)
        with self.assertRaises(p.Failure): p.frozen_package_preferences({'nginx': '1.0\nPackage: bad'})

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'POSIX root file ownership fixture')
    def test_version_pins_are_private_ephemeral_and_preserve_existing_files(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(p, 'STATE', Path(temporary)):
            root = Path(temporary); sentinel = root / 'existing-state'; sentinel.write_bytes(b'preserve first state')
            with p.shared_package_pins({'nginx': '1.0'}) as options:
                pin = Path(next(value.split('=', 1)[1] for value in options if value.startswith('Dir::Etc::preferences=')))
                parts = Path(next(value.split('=', 1)[1] for value in options if value.startswith('Dir::Etc::preferencesparts=')))
                self.assertEqual(0o600, pin.stat().st_mode & 0o777)
                self.assertEqual(0, pin.stat().st_uid)
                self.assertEqual(p.frozen_package_preferences({'nginx': '1.0'}), pin.read_bytes())
                self.assertEqual([], list(parts.iterdir()))
            self.assertFalse(pin.exists()); self.assertFalse(parts.exists())
            self.assertEqual([sentinel], list(root.iterdir()))
            self.assertEqual(b'preserve first state', sentinel.read_bytes())

    def test_inventory_includes_held_packages_and_refuses_pending_configuration(self):
        with patch.object(p, 'run', return_value=b'nginx\t1.0\thi \nremoved\t\tun \n'):
            self.assertEqual({'nginx': '1.0'}, p.shared_package_inventory())
        with patch.object(p, 'run', return_value=b'nginx\t1.0\tiU \n'), self.assertRaises(p.Failure) as raised:
            p.shared_package_inventory()
        self.assertEqual('SHARED_PACKAGE_CHANGE_REQUIRED', raised.exception.code)

    def test_shared_fpm_reload_preserves_other_application_processes(self):
        with patch.object(p, 'atomic'), patch.object(p, 'run', return_value=b'') as run:
            p.pools(shared_host=True)
        self.assertIn(['systemctl', 'reload', 'php8.3-fpm'], [call.args[0] for call in run.call_args_list])
        self.assertFalse(any('restart' in call.args[0] for call in run.call_args_list))

    def test_nginx_host_conflict_is_checked_inside_lease_before_any_write(self):
        events = []
        @contextlib.contextmanager
        def lease(**_):
            events.append('lock')
            yield
        def conflict(_):
            events.append('validate')
            raise p.Failure('HOST_IN_USE', 'Fixture collision')
        with patch.object(p, 'shared_lock', lease), patch.object(p, 'ensure_hosts_available', side_effect=conflict), \
             patch.object(p, 'atomic') as write, patch.object(p, 'run') as run:
            with self.assertRaises(p.Failure): p.configure_nginx(self.public())
            write.assert_not_called(); run.assert_not_called()
        self.assertEqual(['lock', 'validate'], events)

    def test_certificate_checks_host_and_prepares_http_candidate_before_issuance(self):
        public = self.public()
        events = []
        with patch.object(p, 'shared_lock', lambda **_: contextlib.nullcontext()), \
             patch.object(p, 'read_json', return_value=public), patch.object(p, 'ensure_hosts_available', side_effect=lambda value: events.append(('validate', value['pending_host']))), \
             patch.object(p, 'configure_nginx', side_effect=lambda value: events.append(('http', value['pending_host']))), \
             patch.object(p, '_obtain_certificate', side_effect=lambda host, *_: events.append(('certificate', host))):
            p.obtain_certificate('new.example.org', '8.8.8.8')
        self.assertEqual([('validate', 'new.example.org'), ('http', 'new.example.org'), ('certificate', 'new.example.org')], events)

    def test_renewal_is_scoped_to_own_certificate_names_and_skips_unissued_alias(self):
        public = {**self.public(), 'acme_hosts': ['historic.example.org', 'unissued.example.org']}
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', lambda **_: contextlib.nullcontext()), patch.object(p, 'read_json', return_value=public), \
             patch.object(p, 'ensure_hosts_available'), patch.object(p, 'renewal_config_exists', side_effect=lambda host: host != 'unissued.example.org'), \
             patch.object(p, 'run', return_value=b'') as run:
            p.renew_certificates()
        self.assertEqual(2, run.call_count)
        self.assertEqual({p.cert_name('relay.example.org'), p.cert_name('historic.example.org')},
                         {call.args[0][call.args[0].index('--cert-name') + 1] for call in run.call_args_list})
        self.assertTrue(all(call.args[0][1] == 'renew' for call in run.call_args_list))
        self.assertTrue(all('--no-random-sleep-on-renew' in call.args[0] for call in run.call_args_list))

    def test_missing_active_certificate_configuration_is_reported(self):
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', lambda **_: contextlib.nullcontext()), patch.object(p, 'read_json', return_value=self.public()), \
             patch.object(p, 'ensure_hosts_available'), patch.object(p, 'renewal_config_exists', return_value=False), patch.object(p, 'run') as run:
            with self.assertRaises(p.Failure) as raised: p.renew_certificates()
            run.assert_not_called()
        self.assertEqual('TLS_STATE', raised.exception.code)

    def test_dry_run_never_creates_the_common_lease_or_state(self):
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(sys, 'argv', ['provision.py', '--dry-run', '--host', 'relay.example.org', '--public-ip', '8.8.8.8']), \
             patch.object(p, 'shared_lock', side_effect=lambda **_: contextlib.nullcontext()) as lock, \
             patch.object(p, 'peer_installation', return_value=None), \
             patch.object(p, 'preflight', return_value=True), patch.object(p, 'dns_matches'), patch.object(p, 'initialize_state') as state, \
             patch.object(p, 'install') as install, contextlib.redirect_stdout(io.StringIO()) as output:
            p.main()
        lock.assert_called_once_with(create=False)
        state.assert_not_called(); install.assert_not_called()
        self.assertEqual(False, json.loads(output.getvalue())['writes'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink transaction fixture')
    def test_failed_new_site_removes_only_its_own_config_and_link(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root = Path(temporary); (root / 'enabled').mkdir()
            own = root / 'site'; sibling = root / 'sibling'; sibling.write_bytes(b'first application unchanged')
            enabled = root / 'enabled' / 'gitreposted-installer'
            stack.enter_context(patch.object(p, 'SITE', own))
            stack.enter_context(patch.object(p, 'ENABLED_SITE', enabled))
            stack.enter_context(patch.object(p, 'atomic', side_effect=lambda path, value, *_: Path(path).write_bytes(value.encode() if isinstance(value, str) else value)))
            stack.enter_context(patch.object(p, 'run', side_effect=p.Failure('NGINX_TEST', 'Fixture nginx check failed')))
            with self.assertRaises(p.Failure): p._configure_nginx(self.public())
            self.assertFalse(own.exists()); self.assertFalse(enabled.exists()); self.assertFalse(enabled.is_symlink())
            self.assertEqual(b'first application unchanged', sibling.read_bytes())

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink transaction fixture')
    def test_failed_reload_restores_the_previous_file_and_reloads_it(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root = Path(temporary); (root / 'enabled').mkdir()
            own = root / 'site'; own.write_bytes(b'previous configuration')
            enabled = root / 'enabled' / 'gitreposted-installer'; enabled.symlink_to(own)
            stack.enter_context(patch.object(p, 'SITE', own))
            stack.enter_context(patch.object(p, 'ENABLED_SITE', enabled))
            stack.enter_context(patch.object(p, 'atomic', side_effect=lambda path, value, *_: Path(path).write_bytes(value.encode() if isinstance(value, str) else value)))
            run = stack.enter_context(patch.object(p, 'run', side_effect=[b'', p.Failure('RELOAD_FAILED', 'Fixture reload failed'), b'', b'']))
            with self.assertRaises(p.Failure): p._configure_nginx(self.public())
            self.assertEqual(b'previous configuration', own.read_bytes())
            self.assertEqual(own, enabled.resolve())
            self.assertEqual([['nginx', '-t'], ['systemctl', 'reload', 'nginx'], ['nginx', '-t'], ['systemctl', 'reload', 'nginx']],
                             [call.args[0] for call in run.call_args_list])

    @unittest.skipUnless(os.name == 'posix', 'POSIX atomic-write transaction fixture')
    def test_failure_after_rename_restores_previous_config_before_reporting_error(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root = Path(temporary); (root / 'enabled').mkdir()
            own = root / 'site'; own.write_bytes(b'previous configuration')
            enabled = root / 'enabled' / 'gitreposted-installer'; enabled.symlink_to(own)
            calls = []
            def atomic(path, value, *_):
                Path(path).write_bytes(value.encode() if isinstance(value, str) else value)
                calls.append(path)
                if len(calls) == 1: raise OSError('fixture private fsync detail')
            stack.enter_context(patch.object(p, 'SITE', own))
            stack.enter_context(patch.object(p, 'ENABLED_SITE', enabled))
            stack.enter_context(patch.object(p, 'atomic', side_effect=atomic))
            run = stack.enter_context(patch.object(p, 'run'))
            with self.assertRaises(p.Failure) as raised: p._configure_nginx(self.public())
            self.assertEqual('NGINX_CONFIGURATION_FAILED', raised.exception.code)
            self.assertNotIn('private', str(raised.exception))
            self.assertEqual(b'previous configuration', own.read_bytes())
            self.assertEqual(own, enabled.resolve())
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
