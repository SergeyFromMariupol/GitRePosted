#!/usr/bin/env python3
"""Temporary-fixture cleanup checks. No services, real DATA_DIR or API calls."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name != 'posix':
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *_: None))

spec=importlib.util.spec_from_file_location('cleanup_under_test',Path(__file__).resolve().parents[1]/'bin/cleanup.py')
cleanup=importlib.util.module_from_spec(spec);spec.loader.exec_module(cleanup)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.data=Path(self.temporary.name)/'gitreposted-installer';self.root=self.data/'sessions';self.root.mkdir(parents=True)
        self.now=1700000000
        self.uid=self.root.stat().st_uid
        self.uid_patch=patch.object(cleanup.os,'getuid',return_value=self.uid,create=True);self.uid_patch.start();self.addCleanup(self.uid_patch.stop)
        if not hasattr(os,'O_NOFOLLOW'):
            nofollow=patch.object(os,'O_NOFOLLOW',0,create=True);nofollow.start();self.addCleanup(nofollow.stop)
        if os.name != 'posix':
            # NTFS does not expose Unix permission bits. Keep validation real
            # on Linux and supply only the unavailable mode bits in this adapter.
            original_lstat,original_fstat=Path.lstat,os.fstat
            def lstat(path,*args,**kwargs):
                info=original_lstat(path,*args,**kwargs)
                return types.SimpleNamespace(st_mode=info.st_mode&~0o022,st_uid=info.st_uid,st_mtime=info.st_mtime)
            def fstat(fd):
                info=original_fstat(fd)
                return types.SimpleNamespace(st_mode=info.st_mode&~0o077,st_uid=info.st_uid)
            for adapter in (patch.object(Path,'lstat',lstat),patch.object(os,'fstat',fstat)):
                adapter.start();self.addCleanup(adapter.stop)

    def file(self,name,age=301,parent=None):
        path=(self.root if parent is None else parent)/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text('fixture');os.utime(path,(self.now-age,self.now-age));return path

    def test_only_expired_owned_counter_removed_preserving_fresh_and_persistent_files(self):
        stale=self.file('rate-'+'a'*64);fresh=self.file('rate-'+'b'*64,299);boundary=self.file('rate-'+'c'*64,300)
        unrelated=[self.file('admin-login-throttle.json'),self.file('rate-'+'d'*64+'.lock'),self.file('rate-'+'D'*64),
            self.file('e'*64+'.json',parent=self.data/'storage/posted_webhook_updates'),
            self.file('f'*64+'.json',parent=self.data/'runtime'),self.file('sess_fixture',parent=self.data/'sessions')]
        self.assertEqual(1,cleanup.cleanup(self.root,now=self.now));self.assertFalse(stale.exists())
        for path in [fresh,boundary,*unrelated]:self.assertTrue(path.exists(),str(path))
        self.assertEqual(0,cleanup.cleanup(self.root,now=self.now))

    def test_lookalike_directory_is_not_a_counter(self):
        path=self.root/('rate-'+'a'*64);path.mkdir();os.utime(path,(self.now-1000,self.now-1000))
        self.assertEqual(0,cleanup.cleanup(self.root,now=self.now));self.assertTrue(path.is_dir())

    def test_foreign_owned_counter_is_not_removed(self):
        path=self.file('rate-'+'a'*64);original=Path.lstat
        def lstat(candidate,*args,**kwargs):
            info=original(candidate,*args,**kwargs)
            if candidate==path:return types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=self.uid+1,st_mtime=self.now-1000)
            return info
        with patch.object(Path,'lstat',lstat):self.assertEqual(0,cleanup.cleanup(self.root,now=self.now))
        self.assertTrue(path.exists())

    def test_foreign_owned_ancestor_stops_cleanup(self):
        path=self.file('rate-'+'a'*64)
        with patch.object(cleanup.os,'getuid',return_value=self.uid+1):self.assertEqual(0,cleanup.cleanup(self.root,now=self.now))
        self.assertTrue(path.exists())

    def test_wrong_directory_or_absent_counter_directory_is_ignored(self):
        for path in (self.data/'storage/rate-limits',self.data/'runtime/rate_limits',self.data/'storage/missing',Path('storage/rate_limits')):
            self.assertEqual(0,cleanup.cleanup(path,now=self.now))

    @unittest.skipUnless(os.name=='posix','Linux symlink fixtures')
    def test_counter_symlink_never_removes_private_target(self):
        target=self.file('private.json',parent=self.data/'runtime');link=self.root/('rate-'+'a'*64);link.symlink_to(target)
        self.assertEqual(0,cleanup.cleanup(self.root,now=self.now));self.assertTrue(target.exists());self.assertTrue(link.is_symlink())

    @unittest.skipUnless(os.name=='posix','Linux symlink fixtures')
    def test_symlink_ancestor_never_traverses_another_storage_tree(self):
        outside=self.data/'other';outside.mkdir();target=self.file('rate-'+'a'*64,parent=outside/'sessions')
        self.root.rmdir();self.root.symlink_to(outside/'sessions',target_is_directory=True)
        self.assertEqual(0,cleanup.cleanup(self.root,now=self.now));self.assertTrue(target.exists())

    def test_busy_shared_rate_lock_preserves_counters_until_request_finishes(self):
        path=self.file('rate-'+'a'*64)
        with patch.object(cleanup.fcntl,'flock',side_effect=BlockingIOError):
            self.assertEqual(0,cleanup.cleanup(self.root,now=self.now))
        self.assertTrue(path.exists())


if __name__=='__main__':unittest.main()
