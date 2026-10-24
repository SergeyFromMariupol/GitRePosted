#!/usr/bin/env python3
"""Offline Node provisioning contracts. No packages, network, DB or service changes."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('node_provision_fixtures', Path(__file__).with_name('provision-test.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
p = fixtures.module


class NodeProvisionTests(unittest.TestCase):
    def test_admin_requested_clean_exit_restarts_bridge_under_systemd(self):
        captured = {}
        with mock.patch.object(p, 'atomic', side_effect=lambda path, content, *args, **kwargs: captured.setdefault(str(path), content)), \
                mock.patch.object(p, 'run', return_value=b''):
            p.units()
        unit = captured['/etc/systemd/system/gitreposted-bridge.service']
        self.assertIn('Restart=always\n', unit)
        self.assertIn('KillMode=control-group\n', unit)
        self.assertIn('User=gitreposted\n', unit)

    def test_admin_scrypt_format_uses_binary_salt_and_utf8_without_php_process(self):
        with mock.patch.object(p.secrets, 'token_hex', return_value='0123456789abcdef' * 2), mock.patch.object(p, 'run') as run:
            encoded = p.php_password('Unicode пароль 🔑')
        scheme, n, r, parallel, salt, digest = encoded.split('$')
        self.assertEqual(('scrypt', '16384', '8', '1'), (scheme, n, r, parallel))
        self.assertEqual(32, len(salt)); self.assertEqual(64, len(digest))
        expected = hashlib.scrypt('Unicode пароль 🔑'.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32).hex()
        self.assertEqual(expected, digest)
        run.assert_not_called()

    def test_enrollment_retains_separate_php_password_verify_contract(self):
        with mock.patch.object(p, 'run', return_value=b'fixture-php-password-hash') as run:
            self.assertEqual('fixture-php-password-hash', p.enrollment_password('fixture-one-time-code'))
        self.assertEqual('php', run.call_args.args[0][0])
        self.assertNotIn('fixture-one-time-code', repr(run.call_args.args))
        self.assertEqual({'password': 'fixture-one-time-code'}, json.loads(run.call_args.kwargs['data']))

    def test_node_is_pinned_per_supported_architecture_without_apt_nodejs(self):
        for machine, suffix in (('x86_64', 'x64'), ('aarch64', 'arm64')):
            with self.subTest(machine=machine), mock.patch.object(p.platform, 'machine', return_value=machine):
                prefix, digest = p.node_archive()
                self.assertEqual('node-v24.22.1-linux-' + suffix, prefix)
                self.assertRegex(digest, r'^[a-f0-9]{64}$')
        with mock.patch.object(p.platform, 'machine', return_value='unknown'), self.assertRaises(p.Failure) as error:
            p.node_archive()
        self.assertEqual('UNSUPPORTED_ARCH', error.exception.code)

    def archive(self, path, entries):
        with tarfile.open(path, 'w:xz') as archive:
            for name, kind, value in entries:
                member = tarfile.TarInfo(name)
                if kind == 'file':
                    payload = value.encode(); member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
                else:
                    member.type = kind; member.linkname = value
                    archive.addfile(member)

    def test_vendor_archive_rejects_unsafe_entries_before_any_extraction(self):
        prefix = 'node-fixture'
        cases = [('../outside', 'file', 'unsafe'),
                 ('node-fixture/../outside', 'file', 'unsafe'),
                 ('node-fixture/bin/link', tarfile.SYMTYPE, '../../../outside'),
                 ('node-fixture/bin/link', tarfile.SYMTYPE, '/outside'),
                 ('node-fixture/bin/link', tarfile.LNKTYPE, 'node-fixture/bin/node'),
                 ('node-fixture/device', tarfile.CHRTYPE, ''),
                 ('node-fixture/bin/node', 'file', 'duplicate')]
        for unsafe in cases:
            with self.subTest(entry=unsafe), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); archive = root / 'node.tar.xz'
                self.archive(archive, [(prefix + '/bin/node', 'file', 'preserve'), unsafe])
                with self.assertRaises(p.Failure): p.extract_node(archive, root, prefix)
                self.assertFalse((root / prefix).exists(), 'Validation must finish before any archive entry is extracted')

    def test_vendor_archive_extracts_valid_regular_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); archive = root / 'node.tar.xz'
            self.archive(archive, [('node-fixture/bin/node', 'file', 'fixture-node')])
            p.extract_node(archive, root, 'node-fixture')
            self.assertEqual('fixture-node', (root / 'node-fixture/bin/node').read_text())

    def test_wrong_node_checksum_never_extracts_or_executes_and_removes_only_own_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'node'; keep = Path(temporary) / 'keep'; keep.write_text('preserve')
            calls = []
            def system(argv, **kwargs):
                calls.append(argv)
                self.assertEqual('curl', argv[0])
                Path(argv[argv.index('--output') + 1]).write_bytes(b'wrong-vendor-archive')
                return b''
            with mock.patch.object(p.platform, 'machine', return_value='x86_64'), mock.patch.object(p, 'NODE_ROOT', root), mock.patch.object(p, 'run', side_effect=system), mock.patch.object(p, 'extract_node') as extract:
                with self.assertRaises(p.Failure) as error: p.prepare_node()
            self.assertEqual('NODE_CHECKSUM', error.exception.code)
            self.assertEqual(1, len(calls)); extract.assert_not_called()
            self.assertEqual([], list(root.iterdir())); self.assertEqual('preserve', keep.read_text())

    def package(self, root):
        source = root / 'src'; source.mkdir()
        dependencies = {'mysql2': '^3.24.4'}
        (source / 'package.json').write_text(json.dumps({'type': 'module', 'dependencies': dependencies}))
        (source / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {'dependencies': dependencies}}}))
        (source / 'server.js').write_text('fixture-immutable-server')
        return source

    def test_npm_failure_runs_without_root_scripts_and_preserves_source_for_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = self.package(root)
            with mock.patch.object(p, 'validate_source'), mock.patch.object(p, 'identity', return_value=(1001, 1001)), \
                 mock.patch.object(p.os, 'chown', create=True), mock.patch.object(p, 'atomic', side_effect=lambda path, value, *_: Path(path).write_bytes(value)), \
                 mock.patch.object(p, 'run', side_effect=p.Failure('SYSTEM_COMMAND_FAILED', 'Fixture npm unavailable')) as run:
                for _ in range(2):
                    with self.assertRaises(p.Failure): p.prepare_dependencies(root)
            self.assertEqual(2, run.call_count)
            for call in run.call_args_list:
                argv = call.args[0]
                self.assertEqual(['runuser', '-u', 'gitreposted', '--', 'env'], argv[:5])
                self.assertIn('--ignore-scripts', argv); self.assertIn('--omit=dev', argv)
                self.assertIn('--no-audit', argv); self.assertIn(p.NODE, argv)
            self.assertFalse((source / 'node_modules').exists())
            self.assertEqual('fixture-immutable-server', (source / 'server.js').read_text())
            self.assertEqual(['src'], [item.name for item in root.iterdir()])

    def test_completed_npm_tree_publishes_atomically_with_lock_checkpoint_and_resumes_without_npm(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = self.package(root)
            def system(argv, **kwargs):
                stage = Path(argv[argv.index('--prefix') + 1])
                target = stage / 'node_modules/mysql2/promise.js'; target.parent.mkdir(parents=True); target.write_text('fixture-mysql2')
                self.assertFalse((source / 'node_modules').exists())
                return b''
            with mock.patch.object(p, 'validate_source'), mock.patch.object(p, 'identity', return_value=(1001, 1001)), \
                 mock.patch.object(p.os, 'chown', create=True), mock.patch.object(p, 'atomic', side_effect=lambda path, value, *_: Path(path).write_bytes(value.encode() if isinstance(value, str) else value)), \
                 mock.patch.object(p, 'sync_directory'), mock.patch.object(p, 'seal_dependencies') as seal, mock.patch.object(p, 'run', side_effect=system) as run:
                p.prepare_dependencies(root)
                p.prepare_dependencies(root)
                run.assert_called_once(); seal.assert_called_once()
            checkpoint = p.read_json(source / 'node_modules/.gitreposted-install.json')
            self.assertEqual(hashlib.sha256((source / 'package-lock.json').read_bytes()).hexdigest(), checkpoint['lock_sha256'])
            self.assertEqual(p.NODE_VERSION, checkpoint['node'])
            self.assertEqual(['src'], [item.name for item in root.iterdir()])

    def test_units_have_only_setup_php_and_deferred_single_node_bridge(self):
        writes = {}
        with mock.patch.object(p, 'atomic', side_effect=lambda path, value, *_: writes.update({str(path): value})), mock.patch.object(p, 'run', return_value=b'') as run:
            p.units(); p.pools()
        bridge = writes['/etc/systemd/system/gitreposted-bridge.service']
        self.assertIn('ExecStart=' + str(p.NODE) + ' ' + str(p.APP) + '/current/src/server.js', bridge)
        self.assertIn('User=gitreposted\n', bridge); self.assertIn('KillMode=control-group', bridge)
        self.assertIn('Environment=GITREPOSTED_ENV_FILE=' + str(p.CONFIG), bridge)
        self.assertIn('NODE_EXTRA_CA_CERTS=', bridge)
        self.assertNotIn('/etc/cron.d/gitreposted', writes)
        self.assertNotIn('/etc/php/8.3/fpm/pool.d/gitreposted.conf', writes)
        self.assertIn('User=gitreposted-setup\n', writes['/etc/systemd/system/gitreposted-rate-limit-cleanup.service'])
        self.assertFalse(any('gitreposted-bridge.service' in call.args[0] for call in run.call_args_list))

    def test_stage_cleanup_refuses_parent_and_noncanonical_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            keep = root / 'important'; keep.mkdir(); (keep / 'keep').write_text('preserve')
            for path in (root, keep, root / 'unrelated'):
                with self.assertRaises(p.Failure): p.clean_stage(path, root, '.npm-stage.')
            self.assertEqual('preserve', (keep / 'keep').read_text())


if __name__ == '__main__':
    unittest.main()
