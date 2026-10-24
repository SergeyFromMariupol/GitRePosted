#!/usr/bin/env python3
"""Regression probes for shared package operations; never run apt or providers."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

if os.name != 'posix':
    sys.modules.setdefault('pwd', types.SimpleNamespace())
    sys.modules.setdefault('grp', types.SimpleNamespace())
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *_: None))

spec = importlib.util.spec_from_file_location('deep_coinstall_package_provision', Path(__file__).resolve().parents[1] / 'lib/provision.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class PackageCommandLifetimeTests(unittest.TestCase):
    def test_cli_signal_handlers_restore_on_success_failure_and_repeated_interrupt(self):
        watched = [signal.SIGTERM] + ([signal.SIGHUP] if hasattr(signal, 'SIGHUP') else [])
        for exit_kind in ('normal', 'failure', 'interrupted'):
            with self.subTest(exit_kind=exit_kind):
                previous = {number: signal.getsignal(number) for number in watched}
                try:
                    with p.interruption_signals():
                        self.assertTrue(callable(signal.getsignal(signal.SIGTERM)))
                        if exit_kind == 'failure':
                            raise p.Failure('FIXTURE_FAILURE', 'Fixture operation failed')
                        if exit_kind == 'interrupted':
                            handler = signal.getsignal(signal.SIGTERM)
                            with self.assertRaises(p.BootstrapInterrupted) as raised:
                                handler(signal.SIGTERM, None)
                            self.assertEqual('BOOTSTRAP_INTERRUPTED', raised.exception.code)
                            handler(signal.SIGTERM, None)  # Repeated cancellation cannot abort cleanup.
                except p.Failure as error:
                    self.assertEqual('FIXTURE_FAILURE', error.code)
                self.assertEqual(previous, {number: signal.getsignal(number) for number in watched})

    def test_cli_cancellation_bypasses_ip_validation_failure_catches(self):
        # Both parsers intentionally catch ordinary Failure to skip invalid IPs.
        # A one-shot signal handler must unwind instead of being swallowed there.
        for entrypoint in ('host_name', 'detect_ip'):
            with self.subTest(entrypoint=entrypoint), p.interruption_signals():
                def cancel(*_args, **_kwargs):
                    signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                with patch.object(p, 'public_ip', side_effect=cancel), \
                        patch.object(p, 'run', return_value=b'[{"addr_info":[{"local":"8.8.8.8"}]}]'):
                    with self.assertRaises(p.BootstrapInterrupted) as raised:
                        if entrypoint == 'host_name':
                            p.host_name('install.example.org')
                        else:
                            p.detect_ip()
                    self.assertEqual('BOOTSTRAP_INTERRUPTED', raised.exception.code)

    def test_signal_context_does_not_change_handlers_in_worker_threads(self):
        errors = []
        completed = []
        def worker():
            try:
                with p.interruption_signals(): completed.append(True)
            except BaseException as error:
                errors.append(type(error).__name__)
        with patch.object(p.signal, 'signal') as register:
            thread = threading.Thread(target=worker)
            thread.start(); thread.join(2)
            self.assertFalse(thread.is_alive())
            register.assert_not_called()
        self.assertEqual([], errors)
        self.assertEqual([True], completed)

    @unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0,
                         'POSIX root CLI signal and shared-lock fixture')
    def test_cli_sigterm_and_sighup_clean_package_group_before_unlock(self):
        import fcntl
        for requested_signal in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=requested_signal), tempfile.TemporaryDirectory(prefix='coinstall-cli-interrupt-') as temporary:
                root = Path(temporary); root.chmod(0o700); (root / 'run').mkdir(mode=0o755)
                effect = root / 'late-effect'
                identity = root / 'child.json'
                cleanup = root / 'package-cleanup-complete'
                lease = root / 'lease-order'; lease.write_text('held by CLI')
                child_source = ('import pathlib,time; time.sleep(0.9); pathlib.Path(' + repr(str(effect)) + ').write_text('
                                'pathlib.Path(' + repr(str(lease)) + ').read_text())')
                operation_source = ('import json,os,pathlib,subprocess,sys,time; '
                                    'child=subprocess.Popen([sys.executable,"-c",' + repr(child_source) + '],'
                                    'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
                                    'pathlib.Path(' + repr(str(identity)) + ').write_text(json.dumps({"pid":child.pid,"operation_pid":os.getpid()})); '
                                    'time.sleep(10)')
                worker_source = '\n'.join([
                    'import importlib.util,pathlib,sys',
                    'root=pathlib.Path(' + repr(str(root)) + ')',
                    'spec=importlib.util.spec_from_file_location("signal_fixture_provision",' + repr(str(Path(p.__file__))) + ')',
                    'p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)',
                    'p.coinstall.ROOT=root',
                    'p.STATE=root/"not-installed"',
                    'def package_operation(*args,**kwargs):',
                    '    try:',
                    '        p.run([sys.executable,"-c",' + repr(operation_source) + '],timeout=20,safe="Fixture package command failed")',
                    '    finally:',
                    '        pathlib.Path(' + repr(str(cleanup)) + ').write_text("run cleanup completed before suite unlock")',
                    '    return False',
                    'p.preflight=package_operation',
                    'sys.argv=["provision.py","--public-ip","8.8.8.8","--host","install.example.org"]',
                    'p.main()',
                ]) + '\n'
                worker_script = root / 'worker.py'; worker_script.write_text(worker_source, encoding='utf-8')
                worker = subprocess.Popen([sys.executable, '-B', str(worker_script)],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          start_new_session=True)
                try:
                    deadline = time.monotonic() + 5
                    while not identity.exists() and worker.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(identity.exists(), 'CLI fixture did not reach its package operation')
                    worker.send_signal(requested_signal)
                    worker.wait(timeout=5)
                    with (root / 'run/gitposted-suite.lock').open('r+b') as lock:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        lease.write_text('reacquired after CLI return')
                        cleaned_before_reacquire = cleanup.exists()
                        time.sleep(1.0)
                        self.assertTrue(cleaned_before_reacquire, 'Shared lock became available before package-group cleanup; late_effect=' +
                                        (effect.read_text() if effect.exists() else 'none'))
                        self.assertFalse(effect.exists(), 'CLI interruption left a late package effect after suite unlock')
                        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                    self.assertEqual(1, worker.returncode, 'CLI must report a safe interrupted failure, not terminate before cleanup')
                finally:
                    if worker.poll() is None:
                        worker.kill(); worker.wait(timeout=5)
                    if identity.exists():
                        identities = json.loads(identity.read_text())
                        for pid in (identities['pid'], identities['operation_pid']):
                            command = Path('/proc') / str(pid) / 'cmdline'
                            try:
                                if command.exists() and os.fsencode(str(root)) in command.read_bytes():
                                    os.kill(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                    for stream in (worker.stdout, worker.stderr):
                        if stream is not None: stream.close()

    def test_package_environment_never_requests_automatic_service_restarts(self):
        # Noble's apt hook normally invokes needrestart in automatic mode.
        # Even a newly added unrelated package can otherwise restart a sibling
        # whose libraries were changed by an earlier maintenance operation.
        with patch.dict(os.environ, {'NEEDRESTART_MODE': 'a'}):
            result = p.run([sys.executable, '-c', 'import os; print(os.environ.get("NEEDRESTART_MODE", ""))'])
            self.assertEqual('l', result.decode('utf-8').strip(),
                             'APT children must override inherited automatic needrestart with list-only mode')
            self.assertEqual('a', os.environ['NEEDRESTART_MODE'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX failed-leader process-group fixture')
    def test_failed_leader_exit_stops_background_descendant_before_unlock(self):
        # A nonzero leader may already be reaped when its error is handled.
        # Its DEVNULL descendant can still mutate the shared host afterwards.
        with tempfile.TemporaryDirectory(prefix='coinstall-failed-leader-') as temporary:
            root = Path(temporary)
            effect = root / 'late-effect'
            identity = root / 'child.json'
            lease = root / 'operation-lease'; lease.write_text('held')
            child_source = ('import pathlib,time; time.sleep(0.8); pathlib.Path(' + repr(str(effect)) + ').write_text('
                            'pathlib.Path(' + repr(str(lease)) + ').read_text())')
            leader_source = ('import json,pathlib,subprocess,sys; '
                             'child=subprocess.Popen([sys.executable,"-c",' + repr(child_source) + '],'
                             'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
                             'pathlib.Path(' + repr(str(identity)) + ').write_text(json.dumps({"pid":child.pid})); '
                             'sys.exit(7)')
            try:
                with self.assertRaises(p.Failure) as raised:
                    p.run([sys.executable, '-c', leader_source], timeout=5, safe='Fixture leader failed')
                self.assertEqual(7, raised.exception.command_returncode)
                self.assertEqual('Fixture leader failed', str(raised.exception))
                self.assertTrue(identity.exists(), 'The background fixture did not start')
                lease.write_text('released after failed leader')
                time.sleep(1.0)
                self.assertFalse(effect.exists(), 'Failed command left a descendant with lease=' +
                                 (effect.read_text() if effect.exists() else 'no-effect'))
            finally:
                if identity.exists():
                    pid = json.loads(identity.read_text())['pid']
                    command = Path('/proc') / str(pid) / 'cmdline'
                    try:
                        if command.exists() and os.fsencode(str(root)) in command.read_bytes():
                            os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0,
                         'POSIX root interrupted-communicate process-group fixture')
    def test_cli_interruption_after_successful_leader_exit_stops_pipe_descendant(self):
        import fcntl
        with tempfile.TemporaryDirectory(prefix='coinstall-exited-leader-') as temporary:
            root = Path(temporary); root.chmod(0o700); (root / 'run').mkdir(mode=0o755)
            effect = root / 'late-effect'
            identity = root / 'child.json'
            lease = root / 'operation-lease'; lease.write_text('held by CLI')
            child_source = ('import pathlib,time; time.sleep(1.5); pathlib.Path(' + repr(str(effect)) + ').write_text('
                            'pathlib.Path(' + repr(str(lease)) + ').read_text())')
            # Inherit the PIPEs so communicate() remains pending even after the
            # zero-exit leader is a zombie. poll()==0 must not skip group cleanup.
            leader_source = ('import json,os,pathlib,subprocess,sys; '
                             'child=subprocess.Popen([sys.executable,"-c",' + repr(child_source) + '],stdin=subprocess.DEVNULL); '
                             'pathlib.Path(' + repr(str(identity)) + ').write_text(json.dumps({"pid":child.pid,"leader":os.getpid()})); '
                             'sys.exit(0)')
            worker_source = '\n'.join([
                'import importlib.util,pathlib,sys',
                'root=pathlib.Path(' + repr(str(root)) + ')',
                'spec=importlib.util.spec_from_file_location("exited_leader_provision",' + repr(str(Path(p.__file__))) + ')',
                'p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)',
                'p.coinstall.ROOT=root',
                'p.STATE=root/"not-installed"',
                'def package_operation(*args,**kwargs):',
                '    p.run([sys.executable,"-c",' + repr(leader_source) + '],timeout=20,safe="Fixture package command failed")',
                '    return False',
                'p.preflight=package_operation',
                'sys.argv=["provision.py","--public-ip","8.8.8.8","--host","install.example.org"]',
                'p.main()',
            ]) + '\n'
            worker_script = root / 'worker.py'; worker_script.write_text(worker_source, encoding='utf-8')
            worker = subprocess.Popen([sys.executable, '-B', str(worker_script)], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                leader_exited = False
                while worker.poll() is None and time.monotonic() < deadline:
                    if identity.exists():
                        identities = json.loads(identity.read_text())
                        proc = Path('/proc') / str(identities['leader']) / 'stat'
                        try:
                            leader_exited = proc.read_text().split(') ', 1)[1].split()[0] == 'Z'
                        except FileNotFoundError:
                            leader_exited = True
                        if leader_exited:
                            break
                    time.sleep(0.01)
                self.assertTrue(leader_exited, 'Leader did not exit before the cancellation probe')
                self.assertIsNone(worker.poll(), 'CLI must still be waiting for inherited PIPE EOF')
                worker.send_signal(signal.SIGTERM)
                worker.wait(timeout=5)
                with (root / 'run/gitposted-suite.lock').open('r+b') as lock:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    lease.write_text('reacquired after CLI cancellation')
                    time.sleep(1.7)
                    self.assertFalse(effect.exists(), 'Interrupted communicate left a descendant with lease=' +
                                     (effect.read_text() if effect.exists() else 'no-effect'))
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                self.assertEqual(1, worker.returncode, 'CLI must report a safe interrupted failure')
            finally:
                if worker.poll() is None:
                    worker.kill(); worker.wait(timeout=5)
                if identity.exists():
                    identities = json.loads(identity.read_text())
                    for pid in (identities['pid'], identities['leader']):
                        command = Path('/proc') / str(pid) / 'cmdline'
                        try:
                            if command.exists() and os.fsencode(str(root)) in command.read_bytes():
                                os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                for stream in (worker.stdout, worker.stderr):
                    if stream is not None:
                        stream.close()

    @unittest.skipUnless(os.name == 'posix', 'POSIX child-process lifetime fixture')
    def test_timeout_stops_descendants_before_releasing_shared_package_operation(self):
        # This models apt -> dpkg/postinst with Python children only. A child
        # that survives the timeout may alter the host after the suite lock
        # has been released, even though the installer has reported failure.
        with tempfile.TemporaryDirectory(prefix='coinstall-package-lifetime-') as temporary:
            root = Path(temporary)
            effect = root / 'late-effect'
            identity = root / 'child.json'
            lease = root / 'operation-lease'
            lease.write_text('held')
            child_source = ('import pathlib,time; time.sleep(0.8); pathlib.Path(' + repr(str(effect)) + ').write_text('
                            'pathlib.Path(' + repr(str(lease)) + ').read_text())')
            parent_source = ('import json,pathlib,subprocess,sys,time; '
                             'child=subprocess.Popen([sys.executable,"-c",' + repr(child_source) + '],'
                             'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
                             'pathlib.Path(' + repr(str(identity)) + ').write_text(json.dumps({"pid":child.pid})); '
                             'time.sleep(10)')
            try:
                with self.assertRaises(p.Failure):
                    p.run([sys.executable, '-c', parent_source], timeout=0.3, safe='Fixture package operation timed out')
                lease.write_text('released')
                self.assertTrue(identity.exists(), 'The child fixture did not start before the timeout')
                time.sleep(0.9)
                self.assertFalse(effect.exists(),
                                 'Timed-out package command left a descendant with lease=' +
                                 (effect.read_text() if effect.exists() else 'no-effect'))
            finally:
                if identity.exists():
                    pid = json.loads(identity.read_text())['pid']
                    command = Path('/proc') / str(pid) / 'cmdline'
                    try:
                        if command.exists() and os.fsencode(str(root)) in command.read_bytes():
                            os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main(verbosity=2)
