#!/usr/bin/env python3
"""Offline coexistence tests; real POSIX permissions use a disposable root tree."""
from __future__ import annotations
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

if os.name != 'posix':
    sys.modules.setdefault('pwd', types.SimpleNamespace())
    sys.modules.setdefault('grp', types.SimpleNamespace())
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *_: None))

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('suite_provision', ROOT / 'lib/provision.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
co = p.coinstall


class RenderAndProvisionTests(unittest.TestCase):
    def public(self, shared=False):
        return {'host': 'posts.example.org', 'site_host': 'posts.example.org', 'tls_ready': True,
                'installed': True, 'shared_host': shared, 'public_ip': '8.8.8.8'}

    def test_only_first_is_default_and_both_own_named_http_challenges(self):
        first = p.nginx_content(self.public())
        second = p.nginx_content(self.public(True))
        self.assertEqual(2, first.count('default_server'))
        self.assertNotIn('default_server', second)
        self.assertIn('server_name posts.example.org;', first)
        self.assertIn('server_name posts.example.org;', second)
        self.assertNotIn('server_name _;', first + second)

    def test_pending_and_previous_hosts_only_extend_http_not_tls(self):
        value = self.public(True)
        value.update({'pending_host': 'future.example.org', 'acme_hosts': ['old.example.org', 'posts.example.org']})
        rendered = p.nginx_content(value)
        http, https = rendered.split('listen 443 ssl;', 1)
        self.assertIn('server_name posts.example.org old.example.org future.example.org;', http)
        self.assertNotIn('future.example.org', https)
        self.assertNotIn('old.example.org', https)
        self.assertIn('location ^~ /.well-known/acme-challenge/', http)

    def test_aliases_and_pending_hosts_are_validated_before_render(self):
        for extra in ({'pending_host': 'bad; include /etc/passwd;'}, {'acme_hosts': ['bad\nname']},
                      {'acme_hosts': ['a.example.org'] * 33}, {'shared_host': 'false'}):
            with self.subTest(extra=extra), self.assertRaises(p.Failure):
                p.nginx_content({**self.public(True), **extra})

    def test_aliases_reserved_in_common_host_validation(self):
        value = {**self.public(True), 'pending_host': 'next.example.org', 'acme_hosts': ['old.example.org']}
        with patch.object(co, 'validate_hosts') as validate:
            p.ensure_hosts_available(value)
        self.assertIn('old.example.org', validate.call_args.args[1])
        self.assertIn('next.example.org', validate.call_args.args[1])

    def test_shared_php_pool_changes_reload_instead_of_restart(self):
        with patch.object(p, 'atomic'), patch.object(p, 'run', return_value=b'') as run:
            p.pools(True)
        self.assertEqual(['systemctl', 'reload', 'php8.3-fpm'], run.call_args.args[0])
        self.assertFalse(any('restart' in call.args[0] for call in run.call_args_list))

    def test_shared_packages_are_never_upgraded_or_removed(self):
        versions = {name: '1.0' for name in p.SYSTEM_PACKAGES if name != 'unzip'}
        with patch.object(p, 'shared_package_inventory', return_value=versions), patch.object(p, 'wait_package_locks'), \
             patch.object(p, 'shared_package_pins', side_effect=lambda _: contextlib.nullcontext([])), \
             patch.object(p, 'run', side_effect=[b'', b'Inst unzip (1.0 Ubuntu)\nConf unzip (1.0 Ubuntu)\n', b'']) as run:
            p.prepare_system_packages(shared_host=True)
        install = run.call_args.args[0]
        self.assertIn('--no-upgrade', install)
        self.assertIn('--no-remove', install)
        self.assertNotIn('nginx', install)
        self.assertNotIn('mysql-server', install)
        self.assertNotIn('php8.3-fpm', install)

    def test_missing_shared_core_does_not_install_any_package(self):
        with patch.object(p, 'run', return_value=b'nginx\t1.0\tii \n') as run, self.assertRaises(p.Failure) as caught:
            p.prepare_system_packages(shared_host=True)
        self.assertEqual('SHARED_STACK_CHANGED', caught.exception.code)
        self.assertEqual(1, run.call_count)

    def test_existing_complete_dependency_set_skips_apt(self):
        names = ['nginx', 'mysql-server', 'php8.3-fpm', 'php8.3-cli', 'php8.3-mysql', 'php8.3-curl',
                 'php8.3-mbstring', 'python3-venv', 'ca-certificates', 'curl', 'cron', 'logrotate', 'unzip']
        value = ''.join(name + '\t1.0\tii \n' for name in names).encode()
        with patch.object(p, 'run', return_value=value) as run:
            p.prepare_system_packages(shared_host=True)
        self.assertEqual(1, run.call_count)

    def test_host_conflict_is_reported_without_system_writes(self):
        with patch.object(co, 'inspect_peer', return_value={'hosts': ['same.example.org']}), \
                self.assertRaises(co.CoInstallError) as caught:
            co.validate_hosts('gitreposted', ['same.example.org'])
        self.assertEqual('HOST_IN_USE', caught.exception.code)

    def test_certificate_prepares_named_http_for_new_host_before_provider(self):
        records = []
        with patch.object(p, 'shared_lock', return_value=contextlib.nullcontext()), \
             patch.object(p, 'ensure_hosts_available'), patch.object(p, 'read_json', return_value=self.public(True)), \
             patch.object(p, 'configure_nginx', side_effect=lambda value: records.append(('http', value['pending_host']))), \
             patch.object(p, '_obtain_certificate', side_effect=lambda host, *_: records.append(('cert', host))):
            p.obtain_certificate('new.example.org', '8.8.8.8')
        self.assertEqual([('http', 'new.example.org'), ('cert', 'new.example.org')], records)

    def test_renewal_unit_uses_serialized_project_scoped_helper(self):
        values = {}
        with patch.object(p, 'atomic', side_effect=lambda path, value, *_: values.update({str(path): value})):
            p.units()
        unit = values['/etc/systemd/system/gitreposted-cert-renew.service']
        self.assertIn('lib/provision.py --renew-certificates', unit)
        self.assertNotIn('certbot renew', unit)

    def preflight_fixture(self, peer=None, marker=None):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(p.os, 'geteuid', return_value=0, create=True))
        stack.enter_context(patch.object(p.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=10 * 1024**3)))
        stack.enter_context(patch.object(Path, 'read_text', autospec=True, side_effect=lambda path, **kw:
                                        'ID=ubuntu\nVERSION_ID="24.04"\n' if str(path).endswith('os-release') else 'MemTotal: 2000000 kB\n'))
        stack.enter_context(patch.object(Path, 'exists', return_value=False))
        stack.enter_context(patch.object(Path, 'is_symlink', return_value=False))
        stack.enter_context(patch.object(p, 'read_json', return_value=marker))
        stack.enter_context(patch.object(p.pwd, 'getpwnam', side_effect=KeyError(), create=True))
        stack.enter_context(patch.object(p.shutil, 'which', return_value=None))
        stack.enter_context(patch.object(p, 'peer_installation', return_value=peer))
        stack.enter_context(patch.object(p, 'ensure_hosts_available'))
        stack.enter_context(patch.object(p, 'node_archive'))
        return stack

    def test_second_explicit_host_reuses_verified_peer_but_checks_private_node_port(self):
        self.preflight_fixture(peer={'project': 'gitposted'})
        with patch.object(p.socket, 'socket') as socket:
            self.assertTrue(p.preflight(host='posts.example.org', ip='8.8.8.8', explicit_host=True))
        self.assertEqual(2, socket.call_count)
        self.assertEqual([(('0.0.0.0', 3010),), (('::', 3010),)],
                         [call.args for call in socket.return_value.__enter__.return_value.bind.call_args_list])

    def test_second_without_explicit_host_fails_before_adoption(self):
        self.preflight_fixture(peer={'project': 'gitposted'})
        with self.assertRaises(p.Failure) as caught:
            p.preflight(host='8.8.8.8', ip='8.8.8.8', explicit_host=False)
        self.assertEqual('SECOND_HOST_REQUIRED', caught.exception.code)

    def test_unknown_existing_nginx_still_fails_closed(self):
        self.preflight_fixture()
        with patch.object(p.shutil, 'which', side_effect=lambda name: '/usr/sbin/nginx' if name == 'nginx' else None), \
             self.assertRaises(p.Failure) as caught:
            p.preflight(host='posts.example.org', ip='8.8.8.8')
        self.assertEqual('EXISTING_SERVICE', caught.exception.code)

    def test_shared_resume_cannot_adopt_services_after_peer_disappears(self):
        self.preflight_fixture(marker={'installer': 'gitreposted-clean-v1', 'shared_host': True})
        with self.assertRaises(p.Failure) as caught:
            p.preflight(True, host='posts.example.org', ip='8.8.8.8')
        self.assertEqual('PEER_MISSING', caught.exception.code)

    def test_rootless_main_never_touches_shared_lock(self):
        with patch.object(p.sys, 'argv', ['provision.py', '--dry-run']), \
             patch.object(p.os, 'geteuid', return_value=10001, create=True), \
             patch.object(p, 'shared_lock') as lock, contextlib.redirect_stderr(io.StringIO()) as error:
            with self.assertRaises(SystemExit):
                p.main()
        lock.assert_not_called()
        self.assertIn('ROOT_REQUIRED', error.getvalue())


@unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Real root-owned POSIX filesystem fixture')
class TrustedPeerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.patch_root = patch.object(co, 'ROOT', self.root)
        self.patch_root.start()
        self.patch_identity = patch.object(co.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=10001))
        self.patch_identity.start()
        self.addCleanup(self.patch_identity.stop)
        self.addCleanup(self.patch_root.stop)
        self.addCleanup(self.temporary.cleanup)

    def write(self, relative, value, mode=0o600):
        path = self.root / relative.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        path.write_text(json.dumps(value) if isinstance(value, dict) else value, encoding='utf-8')
        path.chmod(mode)
        return path

    def peer(self, project='gitposted', complete=True):
        other = 'gitreposted' if project == 'gitposted' else 'gitposted'
        prefix = '/var/lib/' + other + '-installer/'
        state = self.root / prefix.lstrip('/')
        self.write(prefix + 'bootstrap.json', {'installer': other + '-clean-v1', 'host': 'peer.example.org', 'public_ip': '8.8.8.8'})
        if not complete:
            return state
        self.write(prefix + 'public.json', {'host': 'peer.example.org', 'site_host': 'peer.example.org', 'site_url': 'https://peer.example.org',
                                          'public_ip': '8.8.8.8', 'installed': True, 'tls_ready': True}, 0o640)
        self.write(prefix + 'installed.json', {'installed_at': 1700000000, 'version': '0.1.0-rc.5', 'admin_url': 'https://peer.example.org/control/'})
        config = self.write('/etc/' + other + ('/config.php' if other == 'gitposted' else '/config.json'), 'credentials-must-never-be-read')
        os.chown(config, 10001, 10001)
        config.parent.chmod(0o770)
        self.write('/etc/nginx/sites-available/' + other + '-installer', 'server { server_name peer.example.org; }', 0o644)
        self.write('/etc/nginx/nginx.conf', 'include /etc/nginx/modules-enabled/*.conf;\nhttp { include /etc/nginx/mime.types; include /etc/nginx/conf.d/*.conf; include /etc/nginx/sites-enabled/*; }', 0o644)
        enabled = self.root / 'etc/nginx/sites-enabled'
        enabled.mkdir(mode=0o755)
        (enabled / (other + '-installer')).symlink_to('/etc/nginx/sites-available/' + other + '-installer')
        return state

    def test_complete_legacy_peer_is_supported_in_either_order(self):
        self.peer()
        value = co.inspect_peer('gitposted', '8.8.8.8')
        self.assertEqual(['peer.example.org'], value['hosts'])
        self.assertFalse(value['shared_host'])

    def test_reverse_order_peer_metadata_has_same_contract(self):
        self.peer('gitreposted')
        self.assertEqual('gitposted', co.inspect_peer('gitreposted', '8.8.8.8')['project'])

    def test_only_bootstrap_reserves_host_but_cannot_authorize_service_reuse(self):
        self.peer(complete=False)
        with self.assertRaises(co.CoInstallError) as caught:
            co.inspect_peer('gitposted')
        self.assertEqual('PEER_INCOMPLETE', caught.exception.code)
        with self.assertRaises(co.CoInstallError) as caught:
            co.validate_hosts('gitposted', ['peer.example.org'])
        self.assertEqual('HOST_IN_USE', caught.exception.code)

    def test_pending_and_retired_certificate_hosts_remain_reserved(self):
        state = self.peer()
        public = json.loads((state / 'public.json').read_text())
        public['acme_hosts'] = ['retired.example.org']
        self.write('/var/lib/gitreposted-installer/public.json', public, 0o640)
        self.write('/var/lib/gitreposted-installer/private.json', {'host_settings': {'host': 'pending.example.org'}})
        for host in ['retired.example.org', 'pending.example.org']:
            with self.subTest(host=host), self.assertRaises(co.CoInstallError):
                co.validate_hosts('gitposted', [host])

    def test_root_state_does_not_make_a_symlink_trustworthy(self):
        state = self.peer()
        path = state / 'installed.json'
        path.rename(state / 'outside.json')
        path.symlink_to(state / 'outside.json')
        with self.assertRaises(co.CoInstallError):
            co.inspect_peer('gitposted')

    def test_app_owned_or_group_writable_attestation_is_rejected(self):
        state = self.peer()
        path = state / 'installed.json'
        path.chmod(0o660)
        with self.assertRaises(co.CoInstallError):
            co.inspect_peer('gitposted')
        path.chmod(0o600)
        os.chown(path, 10001, 10001)
        with self.assertRaises(co.CoInstallError):
            co.inspect_peer('gitposted')

    def test_unknown_site_and_missing_peer_link_are_rejected(self):
        self.peer()
        enabled = self.root / 'etc/nginx/sites-enabled'
        other = enabled / 'unrelated'
        other.symlink_to('/etc/nginx/sites-available/unrelated')
        with self.assertRaises(co.CoInstallError):
            co.inspect_peer('gitposted')
        other.unlink()
        (enabled / 'gitreposted-installer').unlink()
        with self.assertRaises(co.CoInstallError):
            co.inspect_peer('gitposted')

    def test_arbitrary_root_alias_and_wrong_ip_are_rejected(self):
        self.peer()
        with self.assertRaises(co.CoInstallError) as caught:
            co.inspect_peer('gitposted', '1.1.1.1')
        self.assertEqual('PEER_ADDRESS_MISMATCH', caught.exception.code)

    def test_only_stock_inactive_apache_fragment_is_accepted(self):
        self.write('/etc/apache2/conf-available/php8.3-fpm.conf', '# PHP-FPM integration', 0o644)
        self.assertTrue(co.passive_apache_stub())
        extra = self.write('/etc/apache2/apache2.conf', '# actual Apache configuration', 0o644)
        with self.assertRaises(co.CoInstallError):
            co.passive_apache_stub()
        extra.unlink()
        stub = self.root / 'etc/apache2/conf-available/php8.3-fpm.conf'
        stub.rename(stub.with_suffix('.saved'))
        stub.symlink_to(stub.with_suffix('.saved'))
        with self.assertRaises(co.CoInstallError):
            co.passive_apache_stub()

    def test_inline_and_external_main_sites_are_rejected_but_comments_are_ignored(self):
        self.peer()
        main = self.root / 'etc/nginx/nginx.conf'
        original = main.read_text()
        for extra in ('\nhttp { server { listen 8080; } }', '\ninclude /etc/custom-sites/*.conf;'):
            main.write_text(original + extra)
            with self.subTest(extra=extra), self.assertRaises(co.CoInstallError):
                co.inspect_peer('gitposted')
        main.write_text(original + '\n# server { listen 8080; }\n# include /etc/custom-sites/*.conf;\n')
        self.assertTrue(co.inspect_peer('gitposted')['complete'])

    def test_lock_is_reentrant_and_nonblocking_between_threads(self):
        (self.root / 'run').mkdir(mode=0o755)
        errors = []
        def contender():
            try:
                with co.shared_lock():
                    errors.append('unexpected-success')
            except co.CoInstallError as error:
                errors.append(error.code)
        with co.shared_lock(), co.shared_lock():
            thread = threading.Thread(target=contender)
            thread.start()
            thread.join(3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(['SHARED_INSTALL_BUSY'], errors)

    def test_read_only_lock_does_not_create_file(self):
        (self.root / 'run').mkdir(mode=0o755)
        with co.shared_lock(create=False):
            pass
        self.assertFalse((self.root / 'run/gitposted-suite.lock').exists())

    def test_locked_body_io_error_keeps_original_failure(self):
        (self.root / 'run').mkdir(mode=0o755)
        error = OSError('fixture disk failure')
        with self.assertRaises(OSError) as caught:
            with co.shared_lock():
                raise error
        self.assertIs(error, caught.exception)

    def test_failed_new_vhost_removes_only_new_project_files(self):
        site = self.root / 'nginx/sites-available/gitreposted-installer'
        enabled = self.root / 'nginx/sites-enabled/gitreposted-installer'
        site.parent.mkdir(parents=True)
        enabled.parent.mkdir(parents=True)
        peer = site.parent / 'gitposted-installer'
        peer.write_bytes(b'unchanged peer')
        with patch.object(p, 'SITE', site), patch.object(p, 'ENABLED_SITE', enabled), \
             patch.object(p, 'run', side_effect=[p.Failure('NGINX_FAILED', 'fixture'), b'', b'']):
            with self.assertRaises(p.Failure):
                p._configure_nginx(RenderAndProvisionTests().public(True))
        self.assertFalse(site.exists())
        self.assertFalse(enabled.is_symlink())
        self.assertEqual(b'unchanged peer', peer.read_bytes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
