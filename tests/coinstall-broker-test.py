"""Cross-installer transaction boundaries without system or provider mutations."""
from contextlib import contextmanager
import copy
import json
import os
import unittest
from unittest import mock

import broker_test as base

broker, p = base.broker, base.p


class SharedBrokerTests(unittest.TestCase):
    setUp = base.BrokerTests.setUp
    tearDown = base.BrokerTests.tearDown
    save_json = base.BrokerTests.save_json
    persist = base.BrokerTests.persist
    make = base.BrokerTests.make
    execute = base.BrokerTests.execute

    @contextmanager
    def lease(self):
        self.assertFalse(getattr(self, 'leased', False))
        self.leased = True
        try:
            yield
        finally:
            self.leased = False

    def test_host_conflict_fails_before_durable_reservation_or_worker_start(self):
        app = self.make()
        before = (self.state / 'private.json').read_bytes()
        with mock.patch.object(p, 'shared_lock', side_effect=self.lease), \
                mock.patch.object(p, 'ensure_hosts_available', side_effect=[None, p.Failure('HOST_IN_USE', 'Fixed host conflict')]), \
                mock.patch.object(broker.threading, 'Thread') as thread:
            with self.assertRaises(p.Failure) as error:
                app.prepare_job('host', {'host': 'other.example.org', 'email': ''})
        self.assertEqual(error.exception.code, 'HOST_IN_USE')
        self.assertEqual((self.state / 'private.json').read_bytes(), before)
        thread.assert_not_called()
        self.assertFalse(self.leased)

    def test_host_reservation_is_durable_and_lease_released_before_worker_handoff(self):
        app = self.make()
        seen = []
        test = self
        class Worker:
            def __init__(self, *, target, args, daemon):
                self.fd = args[0]
            def start(self):
                test.assertFalse(test.leased)
                saved = json.loads((test.state / 'private.json').read_text())
                seen.append(saved['host_settings']['host'])
                test.assertEqual(saved['job']['status'], 'running')
                os.close(self.fd)  # Captured worker owns its descriptor.
        with mock.patch.object(p, 'shared_lock', side_effect=self.lease), \
                mock.patch.object(broker.threading, 'Thread', Worker):
            result = app.prepare_job('host', {'host': 'relay.example.org', 'email': ''})
        self.assertEqual(seen, ['relay.example.org'])
        self.assertEqual(result['job']['status'], 'running')

    def test_entire_job_and_terminal_save_hold_common_lease(self):
        self.public['job'] = {'id': 'job', 'type': 'host', 'status': 'running', 'steps': [{'id': 'fixture', 'status': 'pending'}]}
        app = self.make()
        app.public['job']['status'] = 'running'
        events = []
        original = app.save
        def save():
            self.assertTrue(self.leased)
            events.append(('save', app.public['job']['status']))
            original()
        app.save = save
        app.host_step = lambda step: self.assertTrue(self.leased)
        with mock.patch.object(p, 'shared_lock', side_effect=self.lease):
            self.execute(app)
        self.assertIn(('save', 'complete'), events)
        self.assertFalse(self.leased)

    def test_busy_global_lease_does_not_run_any_job_step_and_closes_job_descriptor(self):
        self.public['job'] = {'id': 'job', 'type': 'host', 'status': 'running', 'steps': [{'id': 'fixture', 'status': 'pending'}]}
        app = self.make()
        app.public['job']['status'] = 'running'
        descriptor = os.open(self.state / 'captured.lock', os.O_CREAT | os.O_RDWR, 0o600)
        @contextmanager
        def busy():
            raise p.Failure('COINSTALL_BUSY', 'Another setup is running')
            yield
        with mock.patch.object(p, 'shared_lock', side_effect=busy), mock.patch.object(app, 'host_step') as step:
            app.execute(descriptor)
        step.assert_not_called()
        self.assertEqual(app.public['job']['status'], 'failed')
        self.assertEqual(app.public['job']['error']['code'], 'COINSTALL_BUSY')
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_failed_step_releases_common_lease_and_keeps_error_retryable(self):
        self.public['job'] = {'id': 'job', 'type': 'host', 'status': 'running', 'steps': [{'id': 'certificate', 'status': 'pending'}]}
        self.private['host_settings'] = {'host': 'new.example.org', 'email': ''}
        app = self.make()
        app.public['job']['status'] = 'running'
        app.host_step = lambda step: (_ for _ in ()).throw(p.Failure('TLS_FAILED', 'Fixed certificate failure'))
        with mock.patch.object(p, 'shared_lock', side_effect=self.lease):
            self.execute(app)
        self.assertFalse(self.leased)
        self.assertEqual(app.public['job']['error']['code'], 'TLS_FAILED')
        self.assertEqual(app.private['host_settings']['host'], 'new.example.org')

    def test_certificate_routes_http_and_preserves_history_before_issuance(self):
        app = self.make()
        app.public.update(site_host='old.example.org', acme_hosts=['past.example.org'])
        app.private['host_settings'] = {'host': 'new.example.org', 'email': ''}
        events = []
        def configure(candidate):
            events.append('http')
            self.assertEqual(candidate['site_host'], 'old.example.org')
            self.assertEqual(candidate['pending_host'], 'new.example.org')
            self.assertIn('past.example.org', candidate['acme_hosts'])
            saved = json.loads((self.state / 'private.json').read_text())
            self.assertIn('new.example.org', saved['public_state']['acme_hosts'])
        with mock.patch.object(p, 'configure_nginx', side_effect=configure), \
                mock.patch.object(p, 'obtain_certificate', side_effect=lambda *args: events.append('certificate')):
            app.host_step('certificate')
        self.assertEqual(events, ['http', 'certificate'])
        self.assertEqual(app.public['site_host'], 'old.example.org')

    def test_resume_directly_at_nginx_retains_old_domain_and_all_prior_aliases(self):
        app = self.make()
        app.public.update(site_host='old.example.org', acme_hosts=['past.example.org'])
        app.private['host_settings'] = {'host': 'new.example.org', 'email': ''}
        with mock.patch.object(p, 'configure_nginx') as configure:
            app.host_step('nginx')
        candidate = configure.call_args.args[0]
        self.assertEqual(candidate['site_host'], 'new.example.org')
        self.assertTrue({'old.example.org', 'past.example.org', 'new.example.org'}.issubset(candidate['acme_hosts']))
        self.assertNotIn('pending_host', candidate)

    def test_host_alias_limit_is_bounded_and_deduplicated(self):
        public = {'host': 'base.example.org', 'site_host': 'base.example.org', 'acme_hosts': ['base.example.org']}
        self.assertEqual(broker.host_aliases(public), ['base.example.org'])
        public['acme_hosts'] = ['host' + str(n) + '.example.org' for n in range(31)]
        self.assertEqual(len(broker.host_aliases(public)), 32)
        with self.assertRaises(p.Failure) as error:
            broker.host_aliases(public, 'overflow.example.org')
        self.assertEqual(error.exception.code, 'HOST_LIMIT')


if __name__ == '__main__':
    unittest.main(verbosity=2)
