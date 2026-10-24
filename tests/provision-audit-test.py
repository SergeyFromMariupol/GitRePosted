#!/usr/bin/env python3
"""Independent bootstrap failure tests. No packages, sockets, services or server writes."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name != 'posix':
    for name in ('pwd', 'grp'):
        sys.modules.setdefault(name, types.SimpleNamespace())
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *_: None))

spec = importlib.util.spec_from_file_location('installer_provision_audit', Path(__file__).resolve().parents[1] / 'lib/provision.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class ProvisionAuditTests(unittest.TestCase):
    def public_bundle(self, source):
        builder_path = Path(__file__).resolve().parents[1] / 'scripts/build.py'
        builder_spec = importlib.util.spec_from_file_location('provision_package_fixture', builder_path)
        builder = importlib.util.module_from_spec(builder_spec); builder_spec.loader.exec_module(builder)
        for name in builder.REQUIRED_FILES:
            path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'fixture public file')
        (source / 'scripts/build.py').write_bytes(builder_path.read_bytes())
        (source / 'VERSION').write_text('0.1.0-rc.1\n')
        dependencies = {'mysql2': '^3.24.4'}
        (source / 'payload/src/package.json').write_text(json.dumps({'type': 'module', 'scripts': {'start': 'node server.js'}, 'dependencies': dependencies}))
        (source / 'payload/src/package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {'dependencies': dependencies}}}))
        for name in ('payload/src/.env.example', 'payload/src/telegram-bot-api.env.example'):
            (source / name).write_text('# Public example\n')
        return builder

    def test_dependency_failure_leaves_a_complete_durable_resume_bundle(self):
        events = []
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            source.mkdir()
            target = Path(temporary) / 'durable'
            with patch.object(p, 'INSTALL', target), patch.object(p, 'package_files', return_value={}), \
                 patch.object(p, 'dns_matches'), patch.object(p, 'directory'), patch.object(p, 'save_json'), \
                 patch.object(p, 'persist_bundle', side_effect=lambda *_: events.append('persisted')), \
                 patch.object(p, 'run', side_effect=lambda *_args, **_kwargs: events.append('dependency') or (_ for _ in ()).throw(p.Failure('APT_FAILED', 'Fixture dependency failure'))), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(p.Failure):
                    p.install(source, '8.8.8.8', '8.8.8.8', checked=True)
            self.assertEqual(['persisted', 'dependency'], events,
                             'The curl loader deletes its temporary bundle on failure; resume must exist before apt runs.')

    def test_untrusted_source_is_rejected_before_the_first_install_write(self):
        with patch.object(p, 'validate_source', side_effect=p.Failure('UNSAFE_PACKAGE', 'Fixture source failure'), create=True) as validate, \
             patch.object(p, 'dns_matches'), patch.object(p, 'directory') as directory, patch.object(p, 'save_json') as save, \
             patch.object(p, 'run', side_effect=p.Failure('APT_FAILED', 'Fixture dependency failure')) as run, \
             patch.object(p, 'copy_tree') as copy, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(p.Failure):
                p.install(Path('/fixture'), '8.8.8.8', '8.8.8.8', checked=True)
        validate.assert_called_once()
        directory.assert_not_called()
        save.assert_not_called()
        copy.assert_not_called()
        run.assert_not_called()

    def test_main_checks_package_before_creating_state_or_lock(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(p, 'STATE', Path(temporary) / 'absent'), \
             patch.object(sys, 'argv', ['provision.py', '--public-ip', '8.8.8.8']), patch.object(p, 'preflight'), \
             patch.object(p, 'dns_matches'), patch.object(p, 'validate_source', side_effect=p.Failure('UNSAFE_PACKAGE', 'Fixture source failure'), create=True), \
             patch.object(p, 'directory') as directory, patch.object(p, 'installer_lock', contextlib.nullcontext), \
             patch.object(p, 'install') as install, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                p.main()
            self.assertEqual(1, error.exception.code)
        directory.assert_not_called()
        install.assert_not_called()

    def test_ipv4_requirement_does_not_depend_on_ipv6_kernel_support(self):
        text = p.nginx_content({'host': '8.8.8.8', 'site_host': 'example.org', 'tls_ready': True, 'installed': True})
        self.assertNotIn('listen [::]', text,
                         'An IPv4-only Ubuntu host must not fail nginx startup with EAFNOSUPPORT.')
        self.assertIn('listen 80 default_server', text)
        self.assertIn('listen 443 ssl', text)


    def test_source_rejects_a_non_root_owned_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'bundle'
            source.mkdir()
            child = source / 'bootstrap.sh'
            child.write_text('fixture')
            original = Path.lstat
            def lstat(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                mode = stat.S_IFMT(info.st_mode) | (0o755 if stat.S_ISDIR(info.st_mode) else 0o644)
                return types.SimpleNamespace(st_mode=mode, st_uid=1001 if path == child else 0)
            with patch.object(Path, 'lstat', lstat), self.assertRaises(p.Failure) as error:
                p.validate_source(source)
            self.assertEqual('UNSAFE_PACKAGE', error.exception.code)

    def test_source_rejects_root_owned_leaf_inside_user_owned_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / 'home'
            source = home / 'bundle'
            source.mkdir(parents=True)
            (source / 'bootstrap.sh').write_text('fixture')
            original = Path.lstat
            def lstat(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                mode = stat.S_IFMT(info.st_mode) | (0o755 if stat.S_ISDIR(info.st_mode) else 0o644)
                return types.SimpleNamespace(st_mode=mode, st_uid=1001 if path == home else 0)
            with patch.object(Path, 'lstat', lstat), self.assertRaises(p.Failure) as error:
                p.validate_source(source)
            self.assertEqual('UNSAFE_PACKAGE', error.exception.code)

    def test_direct_clone_skips_git_metadata_and_rejects_extra_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'bundle'
            builder = self.public_bundle(source)
            (source / '.git').mkdir()
            (source / '.git/config').write_text('fixture private Git credential')
            with patch.object(p, 'validate_source'):
                files = p.package_files(source)
                self.assertEqual(set(builder.REQUIRED_FILES), set(files))
                (source / 'private-credentials.txt').write_text('fixture private credential')
                with self.assertRaises(p.Failure) as error:
                    p.package_files(source)
                self.assertEqual('INVALID_PACKAGE', error.exception.code)

    def test_modified_manifest_fails_before_persisting_any_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'bundle'
            builder = self.public_bundle(source)
            (source / 'MANIFEST.sha256').write_bytes(builder.manifest_bytes(builder.collect(source)))
            (source / 'bootstrap.sh').write_text('changed fixture')
            with patch.object(p, 'validate_source'), patch.object(p, 'dns_matches'), \
                 patch.object(p, 'directory') as directory, patch.object(p, 'save_json') as save, \
                 patch.object(p, 'run') as run, self.assertRaises(p.Failure) as error:
                p.install(source, '8.8.8.8', '8.8.8.8', checked=True)
            self.assertEqual('INVALID_PACKAGE', error.exception.code)
            directory.assert_not_called(); save.assert_not_called(); run.assert_not_called()

    def test_persisted_bundle_contains_only_validated_members(self):
        files = {'bootstrap.sh': b'bootstrap', 'scripts/build.py': b'fixture builder'}
        writes = {}
        with patch.object(p, 'directory'), patch.object(p, 'atomic', side_effect=lambda path, value, *_: writes.update({path:value})):
            p.persist_bundle(Path('/fixture/source'), files)
        self.assertEqual({p.INSTALL / name:value for name,value in files.items()}, writes)

    @unittest.skipUnless(os.name == 'posix', 'Linux umask and file modes')
    def test_persisted_multilevel_bundle_remains_app_readable_under_private_umask(self):
        files = {'bootstrap.sh': b'fixture bootstrap\n',
                 'bin/helper.py': b'fixture helper\n',
                 'payload/resources/assets/schedule.jpg': b'fixture resource bytes\x00\xff',
                 'payload/src/control/panel.php': b'fixture nested PHP\n'}
        files['MANIFEST.sha256'] = ''.join(hashlib.sha256(value).hexdigest() + '  ' + name + '\n'
                                          for name, value in sorted(files.items())).encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o755)
            public_parent = root / 'public-parent'; public_parent.mkdir(mode=0o751)
            public_parent.chmod(0o751)
            target = public_parent / 'installer'
            private = root / 'private-state'; private.mkdir(mode=0o700)
            marker = private / 'marker'; marker.write_bytes(b'private fixture'); marker.chmod(0o600)
            previous_umask = os.umask(0o077)
            try:
                # Non-root developer runs cannot chown to root; preserve the
                # real filesystem writes/modes while avoiding that unrelated requirement.
                ownership = contextlib.nullcontext() if os.geteuid() == 0 else patch.object(p.os, 'fchown')
                with patch.object(p, 'INSTALL', target), ownership:
                    p.persist_bundle(root / 'source', files)
            finally:
                os.umask(previous_umask)
            self.assertEqual(0o751, stat.S_IMODE(public_parent.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(private.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(marker.stat().st_mode))
            for path in [target, *(item for item in target.rglob('*') if item.is_dir())]:
                self.assertEqual(0o755, stat.S_IMODE(path.stat().st_mode), str(path.relative_to(target)))
            for name, value in files.items():
                path = target / name
                self.assertEqual(value, path.read_bytes())
                self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))
            # --resume may run from the persisted bundle itself. Repair only
            # its public ancestors without rewriting the files being executed.
            (target / 'payload').chmod(0o700)
            (target / 'payload/resources').chmod(0o700)
            with patch.object(p, 'INSTALL', target), patch.object(p, 'atomic') as rewrite:
                p.persist_bundle(target, files)
                rewrite.assert_not_called()
            for path in [target, *(item for item in target.rglob('*') if item.is_dir())]:
                self.assertEqual(0o755, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(0o751, stat.S_IMODE(public_parent.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(private.stat().st_mode))
            if os.geteuid() == 0:
                try:
                    app = p.pwd.getpwnam(p.APP_USER)
                except KeyError:
                    app = p.pwd.getpwnam('nobody')
                reader, writer = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(reader)
                    try:
                        os.setgroups([]); os.setgid(app.pw_gid); os.setuid(app.pw_uid)
                        valid = all((target / name).read_bytes() == value for name, value in files.items())
                        os.write(writer, b'1' if valid else b'0'); os._exit(0 if valid else 1)
                    except BaseException:
                        os.write(writer, b'0'); os._exit(1)
                os.close(writer)
                try:
                    self.assertEqual(b'1', os.read(reader, 1), 'Application UID could not read the persisted package')
                finally:
                    os.close(reader)
                    _, status = os.waitpid(child, 0)
                self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)

    def test_persist_bundle_rejects_noncanonical_or_escaping_members_before_writes(self):
        for name in ('../outside', '/outside', './bootstrap.sh', 'scripts/../outside',
                     'scripts//helper.py', 'scripts\\helper.py', '', 'scripts/./helper.py'):
            with self.subTest(name=name), patch.object(p, 'directory') as directory, \
                 patch.object(p, 'atomic') as atomic, self.assertRaises(p.Failure) as error:
                p.persist_bundle(Path('/fixture/source'), {'bootstrap.sh': b'valid', name: b'invalid'})
            self.assertEqual('UNSAFE_PACKAGE', error.exception.code)
            directory.assert_not_called(); atomic.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'Linux intermediate symlink protection')
    def test_persist_bundle_refuses_linked_ancestor_without_chmod_or_writes_outside_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'installer'; target.mkdir()
            outside = root / 'outside'; outside.mkdir(mode=0o700)
            marker = outside / 'resource'; marker.write_bytes(b'preserve fixture')
            (target / 'payload').symlink_to(outside, target_is_directory=True)
            with patch.object(p, 'INSTALL', target), self.assertRaises(p.Failure) as error:
                p.persist_bundle(root / 'source', {'payload/resources/assets/file': b'public fixture'})
            self.assertEqual('UNSAFE_PATH', error.exception.code)
            self.assertEqual(0o700, stat.S_IMODE(outside.stat().st_mode))
            self.assertEqual([marker], list(outside.iterdir()))
            self.assertEqual(b'preserve fixture', marker.read_bytes())





if __name__ == '__main__':
    unittest.main()
