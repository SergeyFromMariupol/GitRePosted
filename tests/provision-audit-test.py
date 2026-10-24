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
    @contextlib.contextmanager
    def bundle_io(self, target):
        """Real temp files; adapt only unavailable ownership/fsync/rename APIs.

        Linux root runs use the actual renameat2 publication and permissions.
        Windows' exchange adapter verifies transaction ordering, not atomicity.
        """
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(p, 'INSTALL', target))
            if os.name != 'posix':
                original = Path.lstat
                def lstat(path, *args, **kwargs):
                    info = original(path, *args, **kwargs)
                    mode = stat.S_IFMT(info.st_mode) | (0o755 if stat.S_ISDIR(info.st_mode) else 0o644)
                    return types.SimpleNamespace(st_mode=mode, st_uid=0, st_dev=info.st_dev,
                                                 st_ino=info.st_ino, st_nlink=info.st_nlink)
                def atomic(path, value, *_args, **_kwargs):
                    Path(path).write_bytes(value.encode() if isinstance(value, str) else value)
                def publish(stage, replace_existing):
                    if replace_existing:
                        retired = stage.with_name(stage.name + '.exchange-fixture')
                        target.rename(retired); stage.rename(target); retired.rename(stage)
                    else:
                        if target.exists():
                            raise p.Failure('BUNDLE_UNAVAILABLE', 'Fixture no-replace conflict')
                        stage.rename(target)
                stack.enter_context(patch.object(Path, 'lstat', lstat))
                stack.enter_context(patch.object(p, 'atomic', side_effect=atomic))
                stack.enter_context(patch.object(p, 'sync_directory'))
                stack.enter_context(patch.object(p, 'publish_bundle', side_effect=publish))
            elif os.geteuid() != 0:
                original = Path.lstat
                def lstat(path, *args, **kwargs):
                    info = original(path, *args, **kwargs)
                    return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_dev=info.st_dev,
                                                 st_ino=info.st_ino, st_nlink=info.st_nlink)
                stack.enter_context(patch.object(Path, 'lstat', lstat))
                stack.enter_context(patch.object(p.os, 'fchown'))
            yield

    def bundle_fixture(self, prefix=b'new'):
        return {'bootstrap.sh': prefix + b' bootstrap', 'lib/provision.py': prefix + b' provision',
                'payload/src/server.js': prefix + b' server', 'scripts/build.py': prefix + b' builder'}

    def bundle_bytes(self, target):
        return {path.relative_to(target).as_posix(): path.read_bytes()
                for path in target.rglob('*') if path.is_file()}

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
             patch.object(p, 'directory') as directory, patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', contextlib.nullcontext), patch.object(p, 'installer_lock', contextlib.nullcontext), \
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
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'installer'
            with self.bundle_io(target):
                p.persist_bundle(root / 'source', files)
            self.assertEqual(files, self.bundle_bytes(target))
            self.assertEqual([target], list(root.iterdir()))

    def test_midcopy_failure_never_publishes_initial_or_changes_previous_complete_bundle(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); target = root / 'installer'
                files = self.bundle_fixture()
                with self.bundle_io(target):
                    if replacement:
                        p.persist_bundle(root / 'old-source', self.bundle_fixture(b'old'))
                    before = self.bundle_bytes(target) if replacement else None
                    writer = p.atomic
                    def fail_midcopy(path, value, *args, **kwargs):
                        self.assertEqual(before, self.bundle_bytes(target) if target.exists() else None)
                        if Path(path).name == 'server.js':
                            raise OSError('Injected write interruption before the complete bundle exists')
                        return writer(path, value, *args, **kwargs)
                    with patch.object(p, 'atomic', side_effect=fail_midcopy), self.assertRaises(OSError):
                        p.persist_bundle(root / 'new-source', files)
                self.assertEqual(before, self.bundle_bytes(target) if target.exists() else None)
                self.assertEqual([target] if replacement else [], list(root.iterdir()))

    def test_complete_replacement_keeps_old_bytes_until_commit_and_local_resume_does_not_rewrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'installer'
            old, new = self.bundle_fixture(b'old'), self.bundle_fixture(b'new')
            with self.bundle_io(target):
                p.persist_bundle(root / 'old-source', old)
                publisher = p.publish_bundle
                def commit(stage, replacement):
                    self.assertTrue(replacement)
                    self.assertEqual(old, self.bundle_bytes(target))
                    self.assertEqual(new, self.bundle_bytes(stage))
                    return publisher(stage, replacement)
                with patch.object(p, 'publish_bundle', side_effect=commit) as publish:
                    p.persist_bundle(root / 'new-source', new)
                    publish.assert_called_once()
                before = {path: path.stat().st_ino for path in target.rglob('*') if path.is_file()}
                with patch.object(p, 'atomic') as rewrite, patch.object(p, 'publish_bundle') as publish:
                    p.persist_bundle(target, new)
                    rewrite.assert_not_called(); publish.assert_not_called()
                self.assertEqual(before, {path: path.stat().st_ino for path in before})
            self.assertEqual(new, self.bundle_bytes(target))
            self.assertEqual([target], list(root.iterdir()))

    def test_external_retry_replaces_only_allowlisted_partial_previous_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'installer'; target.mkdir(mode=0o755)
            (target / 'bootstrap.sh').write_bytes(b'old partial entrypoint')
            (target / 'bootstrap.sh').chmod(0o644)
            with self.bundle_io(target):
                p.persist_bundle(root / 'external-release', self.bundle_fixture())
            self.assertEqual(self.bundle_fixture(), self.bundle_bytes(target))
            self.assertEqual([target], list(root.iterdir()))

    def test_unknown_existing_file_is_preserved_and_prevents_any_staging_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'installer'; target.mkdir(mode=0o755)
            foreign = target / 'unrelated-private-file'; foreign.write_bytes(b'preserve unrelated fixture')
            foreign.chmod(0o600)
            with self.bundle_io(target), patch.object(p, 'atomic') as write, self.assertRaises(p.Failure) as error:
                p.persist_bundle(root / 'external-release', self.bundle_fixture())
            self.assertEqual('UNSAFE_PATH', error.exception.code); write.assert_not_called()
            self.assertEqual(b'preserve unrelated fixture', foreign.read_bytes())
            self.assertEqual([foreign], list(target.iterdir())); self.assertEqual([target], list(root.iterdir()))

    def test_failed_publish_preserves_previous_bundle_and_removes_only_own_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'installer'
            with self.bundle_io(target):
                p.persist_bundle(root / 'old-source', self.bundle_fixture(b'old'))
                with patch.object(p, 'publish_bundle', side_effect=p.Failure('BUNDLE_UNAVAILABLE', 'Injected commit failure')):
                    with self.assertRaises(p.Failure):
                        p.persist_bundle(root / 'new-source', self.bundle_fixture())
            self.assertEqual(self.bundle_fixture(b'old'), self.bundle_bytes(target))
            self.assertEqual([target], list(root.iterdir()))

    def test_flush_failure_never_publishes_or_cleans_a_different_staging_sibling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'installer'
            unrelated = root / '.installer-bundle.unrelated'; unrelated.mkdir(mode=0o700)
            sentinel = unrelated / 'private-fixture'; sentinel.write_bytes(b'preserve separate tree')
            with self.bundle_io(target):
                sync = p.sync_directory
                failed = False
                def fail_once(path):
                    nonlocal failed
                    if not failed:
                        failed = True
                        raise OSError('Injected directory fsync failure before publication')
                    return sync(path)
                with patch.object(p, 'sync_directory', side_effect=fail_once), patch.object(p, 'publish_bundle') as publish:
                    with self.assertRaises(OSError):
                        p.persist_bundle(root / 'external-source', self.bundle_fixture())
                    publish.assert_not_called()
            self.assertFalse(target.exists()); self.assertEqual([unrelated], list(root.iterdir()))
            self.assertEqual(b'preserve separate tree', sentinel.read_bytes())

    def test_parent_fsync_failure_after_publication_preserves_retired_bundle_for_recovery(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); target = root / 'installer'
                old, new = self.bundle_fixture(b'old'), self.bundle_fixture(b'new')
                with self.bundle_io(target):
                    if replacement:
                        p.persist_bundle(root / 'old-source', old)
                    publisher, sync = p.publish_bundle, p.sync_directory
                    published, retired = False, None
                    def commit(stage, replace_existing):
                        nonlocal published, retired
                        publisher(stage, replace_existing)
                        published = True
                        retired = stage if replace_existing else None
                    def fail_parent_sync(path):
                        if published and Path(path) == root:
                            raise OSError('fixture-private raw fsync detail')
                        return sync(path)
                    with patch.object(p, 'publish_bundle', side_effect=commit), patch.object(p, 'sync_directory', side_effect=fail_parent_sync):
                        with self.assertRaises(p.Failure) as error:
                            p.persist_bundle(root / 'new-source', new)
                    self.assertEqual('BUNDLE_UNAVAILABLE', error.exception.code)
                    self.assertNotIn('fixture-private raw fsync detail', str(error.exception))
                    self.assertIn('--resume', str(error.exception))
                    self.assertEqual(new, self.bundle_bytes(target))
                    if replacement:
                        self.assertIn(str(retired), str(error.exception))
                        self.assertEqual(old, self.bundle_bytes(retired))
                    else:
                        self.assertEqual([target], list(root.iterdir()))
                    # A safe external retry operates only on INSTALL and its
                    # newly-created stage. The retained sibling is not adopted
                    # or automatically deleted after storage becomes healthy.
                    p.persist_bundle(root / 'retry-source', new)
                    self.assertEqual(new, self.bundle_bytes(target))
                    if replacement:
                        self.assertEqual(old, self.bundle_bytes(retired))
                        self.assertEqual({target, retired}, set(root.iterdir()))
                    else:
                        self.assertEqual([target], list(root.iterdir()))

    def test_existing_allowlisted_hardlink_is_preserved_and_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'installer'; target.mkdir(mode=0o755)
            outside = root / 'unrelated-file'; outside.write_bytes(b'preserve linked private fixture')
            outside.chmod(0o600)
            try:
                os.link(outside, target / 'bootstrap.sh')
            except OSError:
                self.skipTest('Host does not permit fixture hardlinks')
            with self.bundle_io(target), self.assertRaises(p.Failure) as error:
                p.persist_bundle(root / 'external-source', self.bundle_fixture())
            self.assertEqual('UNSAFE_PATH', error.exception.code)
            self.assertEqual(b'preserve linked private fixture', outside.read_bytes())
            self.assertEqual(b'preserve linked private fixture', (target / 'bootstrap.sh').read_bytes())
            self.assertEqual(2, outside.stat().st_nlink)

    def test_bundle_file_directory_collision_is_rejected_before_any_write(self):
        with patch.object(p, 'directory') as directory, patch.object(p, 'atomic') as atomic, self.assertRaises(p.Failure) as error:
            p.persist_bundle(Path('/fixture/source'), {'bootstrap.sh': b'file', 'bootstrap.sh/child': b'collision'})
        self.assertEqual('UNSAFE_PACKAGE', error.exception.code)
        directory.assert_not_called(); atomic.assert_not_called()

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root actual renameat2 publication')
    def test_real_linux_no_replace_and_exchange_publish_complete_bundle_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'installer'
            with patch.object(p, 'INSTALL', target):
                p.persist_bundle(root / 'first-release', self.bundle_fixture(b'old'))
                old_inode = target.stat().st_ino
                p.persist_bundle(root / 'second-release', self.bundle_fixture())
            self.assertNotEqual(old_inode, target.stat().st_ino)
            self.assertEqual(self.bundle_fixture(), self.bundle_bytes(target))
            self.assertEqual([target], list(root.iterdir()))

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
                with self.bundle_io(target):
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
            with self.bundle_io(target), patch.object(p, 'atomic') as rewrite:
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
            with self.bundle_io(target), self.assertRaises(p.Failure) as error:
                p.persist_bundle(root / 'source', {'payload/resources/assets/file': b'public fixture'})
            self.assertEqual('UNSAFE_PATH', error.exception.code)
            self.assertEqual(0o700, stat.S_IMODE(outside.stat().st_mode))
            self.assertEqual([marker], list(outside.iterdir()))
            self.assertEqual(b'preserve fixture', marker.read_bytes())

    def test_package_resume_configures_pending_before_bounded_no_remove_install(self):
        for resume in (False, True):
            with self.subTest(resume=resume), patch.object(p, 'wait_package_locks') as wait, patch.object(p, 'run', return_value=b'') as run:
                p.prepare_system_packages(resume)
                commands = [call.args[0] for call in run.call_args_list]
                self.assertEqual(1 if resume else 0, wait.call_count)
                self.assertEqual(3 if resume else 2, len(commands))
                if resume:
                    self.assertEqual(['dpkg', '--force-confdef', '--force-confold', '--configure', '--pending'], commands[0])
                for argv in commands[-2:]:
                    self.assertIn('DPkg::Lock::Timeout=120', argv)
                    self.assertIn('Dpkg::Options::=--force-confold', argv)
                self.assertIn('--no-remove', commands[-1]); self.assertNotIn('--fix-broken', commands[-1])
                self.assertEqual('apt-get', commands[-1][0]); self.assertIn('mysql-server', commands[-1])

    def test_package_repair_is_bounded_and_only_normal_configuration_failure_can_reach_apt(self):
        for returncode in (1, 2, None):
            with self.subTest(returncode=returncode):
                error = p.Failure('SYSTEM_COMMAND_FAILED', 'Captured safe failure')
                if returncode is not None: error.command_returncode = returncode
                calls = []
                def run(argv, **kwargs):
                    calls.append(argv)
                    if argv[0] == 'dpkg': raise error
                    return b''
                with patch.object(p, 'wait_package_locks'), patch.object(p, 'run', side_effect=run):
                    if returncode == 1:
                        p.prepare_system_packages(True)
                        self.assertEqual(3, len(calls)); self.assertIn('--fix-broken', calls[-1]); self.assertIn('--no-remove', calls[-1])
                    else:
                        with self.assertRaises(p.Failure) as caught: p.prepare_system_packages(True)
                        self.assertEqual('PACKAGE_CONFIGURATION_FAILED', caught.exception.code); self.assertEqual(1, len(calls))

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root actual POSIX package lock')
    def test_package_lock_wait_respects_live_owner_and_never_deletes_lock_files(self):
        with tempfile.TemporaryDirectory(prefix='gitreposted-package-lock.', dir='/var/tmp') as temporary:
            root = Path(temporary); lock = root / 'lock'; lock.write_bytes(b'preserve lock inode')
            inode = lock.stat().st_ino
            ready_read, ready_write = os.pipe(); release_read, release_write = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(ready_read); os.close(release_write)
                try:
                    descriptor = os.open(lock, os.O_RDWR)
                    p.fcntl.lockf(descriptor, p.fcntl.LOCK_EX)
                    os.write(ready_write, b'1'); os.read(release_read, 1)
                    os.close(descriptor); os._exit(0)
                except BaseException: os._exit(1)
            os.close(ready_write); os.close(release_read)
            try:
                self.assertEqual(b'1', os.read(ready_read, 1))
                with patch.object(p, 'PACKAGE_LOCKS', (lock, root / 'absent')):
                    with self.assertRaises(p.Failure) as error: p.wait_package_locks(timeout=0)
                    self.assertEqual('PACKAGE_MANAGER_BUSY', error.exception.code)
                    os.write(release_write, b'1'); _, status = os.waitpid(child, 0); child = None
                    self.assertEqual(0, os.waitstatus_to_exitcode(status)); p.wait_package_locks(timeout=1)
                self.assertEqual(inode, lock.stat().st_ino); self.assertEqual(b'preserve lock inode', lock.read_bytes())
                self.assertFalse((root / 'absent').exists())
            finally:
                if child is not None:
                    try: os.write(release_write, b'1')
                    except BrokenPipeError: pass
                    os.waitpid(child, 0)
                os.close(ready_read); os.close(release_write)

    @contextlib.contextmanager
    def release_selection(self):
        with tempfile.TemporaryDirectory(prefix='gitreposted-select-release.', dir='/var/tmp') as temporary:
            root = Path(temporary); app = root / 'app'; state = root / 'state'; state.mkdir()
            old, new = app / 'releases/0.0.1-rc.1', app / 'releases' / p.VERSION
            for release, prefix in ((old, 'old'), (new, 'new')):
                source = release / 'src'; source.mkdir(parents=True)
                for name in ('server.js', 'package.json', 'package-lock.json'): (source / name).write_text(prefix + ' fixture bytes')
            (app / 'current').symlink_to(old)
            (state / 'public.json').write_text('{"tls_ready":false,"installed":false}')
            (state / 'private.json').write_text('{}')
            with patch.object(p, 'APP', app), patch.object(p, 'STATE', state), patch.object(p, 'CONFIG', root / 'config.json'):
                yield root, old, new

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root pre-wizard cross-release resume')
    def test_early_resume_can_select_new_complete_release_and_preserves_previous(self):
        with self.release_selection() as (root, old, new), patch.object(p, 'run', return_value=b'') as run:
            before = (old / 'src/server.js').read_bytes()
            p.select_application_release(new, resume=True)
            self.assertEqual(new, (p.APP / 'current').resolve()); self.assertEqual(before, (old / 'src/server.js').read_bytes())
            self.assertEqual([p.APP / 'current', p.APP / 'releases'], sorted(p.APP.iterdir()))
            self.assertEqual(['systemctl', 'list-units'], run.call_args.args[0][:2])
            run.reset_mock(); p.select_application_release(new, resume=True); run.assert_not_called()

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root configured-release guards')
    def test_cross_release_resume_refuses_configured_or_started_wizard_and_unrequested_upgrade(self):
        for case in ('fresh', 'tls', 'settings', 'job', 'config', 'installed'):
            with self.subTest(case=case), self.release_selection() as (root, old, new), patch.object(p, 'run') as run:
                if case == 'tls': (p.STATE / 'public.json').write_text('{"tls_ready":true}')
                elif case in ('settings', 'job'): (p.STATE / 'private.json').write_text(json.dumps({case: {'fixture': True}}))
                elif case == 'config': p.CONFIG.write_text('preserve existing config')
                elif case == 'installed': (p.STATE / 'installed.json').write_text('{}')
                with self.assertRaises(p.Failure): p.select_application_release(new, resume=case != 'fresh')
                self.assertEqual(old, (p.APP / 'current').resolve()); run.assert_not_called()
                if case == 'config': self.assertEqual('preserve existing config', p.CONFIG.read_text())

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root canonical-release and live-process guards')
    def test_cross_release_resume_rejects_foreign_target_and_running_bridge(self):
        for case in ('foreign', 'active'):
            with self.subTest(case=case), self.release_selection() as (root, old, new), patch.object(p, 'run', return_value=b'gitreposted-bridge.service loaded active running fixture') as run:
                selected = old
                if case == 'foreign':
                    selected = root / 'foreign'; selected.mkdir(); (p.APP / 'current').unlink(); (p.APP / 'current').symlink_to(selected)
                with self.assertRaises(p.Failure): p.select_application_release(new, resume=True)
                self.assertEqual(selected, (p.APP / 'current').resolve())
                self.assertEqual(0 if case == 'foreign' else 1, run.call_count)

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root atomic release selection failure')
    def test_failed_release_selection_preserves_previous_link_and_removes_only_own_temporary(self):
        with self.release_selection() as (root, old, new), patch.object(p, 'run', return_value=b''), \
             patch.object(p.os, 'replace', side_effect=OSError('Captured atomic rename failure')):
            with self.assertRaises(p.Failure) as error: p.select_application_release(new, resume=True)
            self.assertEqual('RELEASE_UNAVAILABLE', error.exception.code)
            self.assertNotIn('Captured', str(error.exception))
            self.assertEqual(old, (p.APP / 'current').resolve())
            self.assertEqual([p.APP / 'current', p.APP / 'releases'], sorted(p.APP.iterdir()))





if __name__ == '__main__':
    unittest.main()
