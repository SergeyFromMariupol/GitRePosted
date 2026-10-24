#!/usr/bin/env python3
"""Isolated broker child lifetime checks. No API, database or live config."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('machine_recovery_fixtures', Path(__file__).with_name('broker_test.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
broker, p = fixtures.broker, fixtures.p
import pwd


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0 and shutil.which('php') and shutil.which('runuser'),
                     'Requires Linux root and the dedicated installer test users')
class ChildLifetime(unittest.TestCase):
    def setUp(self):
        account = pwd.getpwnam(p.APP_USER)
        self.uid, self.gid = account.pw_uid, account.pw_gid
        self.root = Path(tempfile.mkdtemp(prefix='gitreposted-helper-lifetime.', dir='/var/tmp'));self.root.chmod(0o755)
        (self.root/'bin').mkdir(mode=0o755)
        self.effects = self.root/'effects';self.effects.mkdir(mode=0o700);os.chown(self.effects,self.uid,self.gid)
        self.addCleanup(self.cleanup_root)
        self.patches = [mock.patch.object(p,'INSTALL',self.root),mock.patch.object(p,'CONFIG',self.root/'unused-config.php')]
        for item in self.patches:item.start();self.addCleanup(item.stop)

    def script(self, body):
        path=self.root/'bin/application.php';path.write_text('<?php '+body,encoding='utf-8');path.chmod(0o644)

    def cleanup_root(self):
        root=self.root
        self.assertEqual(root.resolve(),root)
        self.assertEqual(root.parent,Path('/var/tmp'))
        self.assertTrue(root.name.startswith('gitreposted-helper-lifetime.'))
        entries=list(root.rglob('*'))
        self.assertTrue(all(not path.is_symlink() and (path.is_file() or path.is_dir()) and root in path.resolve().parents for path in entries))
        for path in sorted(entries,key=lambda item:len(item.parts),reverse=True):
            path.rmdir() if path.is_dir() else path.unlink()
        root.rmdir()

    def test_timeout_cannot_leave_a_php_child_that_later_performs_effects(self):
        pidfile=self.effects/'pid.json';effect=self.effects/'late-effect'
        self.script('$info=["pid"=>getmypid(),"pgid"=>posix_getpgid(0),"sid"=>posix_getsid(0)];'
                    'file_put_contents('+json.dumps(str(pidfile))+',json_encode($info));'
                    'usleep(1500000);file_put_contents('+json.dumps(str(effect))+',"fixture effect");'
                    'echo json_encode(["ok"=>true,"result"=>[]]);')
        pid=None
        try:
            started=time.monotonic()
            with self.assertRaises(p.Failure):broker.helper({'action':'fixture'},timeout=1)
            self.assertLess(time.monotonic()-started,2.5,'Timeout handling did not return within a finite bound')
            self.assertTrue(pidfile.exists(),'Fixture PHP did not start before its timeout')
            identity=json.loads(pidfile.read_text());pid=identity['pid']
            time.sleep(0.85)
            self.assertFalse(effect.exists(),'Timed-out helper PHP kept running and performed a later external-effect analogue; process identity='+str(identity))
            status=Path('/proc')/str(pid)/'stat'
            self.assertTrue(not status.exists() or status.read_text().split()[2]=='Z','Helper descendant remains live after timeout')
        finally:
            if pid is None and pidfile.exists():pid=json.loads(pidfile.read_text())['pid']
            if pid is not None:
                try:
                    command=(Path('/proc')/str(pid)/'cmdline').read_bytes()
                    if os.fsencode(str(self.root/'bin/application.php')) in command:
                        os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except FileNotFoundError:pass

    def test_completed_child_has_only_the_application_identity_and_valid_result(self):
        self.script('echo json_encode(["ok"=>true,"result"=>["uid"=>posix_getuid(),"gid"=>posix_getgid()]]);')
        self.assertEqual(broker.helper({'action':'fixture'},timeout=3),{'uid':self.uid,'gid':self.gid})

    def test_provision_timeout_stops_runuser_descendants_before_dependency_stage_cleanup(self):
        # The same real orphan/effect fixture exercises the generic provisioner
        # launcher used by npm, independently of broker.helper's launcher.
        def provision_child(request, timeout):
            return p.run(['runuser', '-u', p.APP_USER, '--', '/usr/bin/php', self.root/'bin/application.php'], timeout=timeout)
        with mock.patch.object(broker, 'helper', side_effect=provision_child):
            self.test_timeout_cannot_leave_a_php_child_that_later_performs_effects()

    def test_nonzero_oversized_or_nonobject_result_fails_closed_without_raw_output(self):
        for body in ('echo json_encode(["ok"=>true,"result"=>[]]);exit(1);',
                     'echo str_repeat("fixture-private-value",5000);',
                     'echo json_encode(["ok"=>true,"result"=>"fixture-private-value"]);'):
            self.script(body)
            with self.assertRaises(p.Failure) as raised:broker.helper({'action':'fixture'},timeout=3)
            self.assertNotIn('fixture-private-value',str(raised.exception))


if __name__=='__main__':unittest.main()
