#!/usr/bin/env python3
"""Isolated TLS continuation regressions: no DNS, HTTP, services or root files."""
from __future__ import annotations
import contextlib
import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

if os.name != 'posix':
    sys.modules.setdefault('pwd', types.SimpleNamespace())
    sys.modules.setdefault('grp', types.SimpleNamespace())
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *_: None))

spec = importlib.util.spec_from_file_location('deep_coinstall_nginx_provision', Path(__file__).resolve().parents[1] / 'lib/provision.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class RenewalContinuationTests(unittest.TestCase):
    def test_cli_interruption_stops_renewal_without_starting_another_certificate(self):
        attempted = []
        def interrupted(argv, **_kwargs):
            attempted.append(argv[argv.index('--cert-name') + 1])
            raise p.BootstrapInterrupted('Fixture CLI interruption')
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', return_value=contextlib.nullcontext()), \
             patch.object(p, 'read_json', return_value=self.public()), patch.object(p, 'ensure_hosts_available'), \
             patch.object(p, 'renewal_config_exists', return_value=True), patch.object(p, 'run', side_effect=interrupted):
            with self.assertRaises(p.BootstrapInterrupted) as caught:
                p.renew_certificates()
        self.assertEqual('BOOTSTRAP_INTERRUPTED', caught.exception.code)
        self.assertEqual(1, len(attempted), 'An explicit CLI interruption must not start more external operations')

    def public(self):
        # A real wizard domain change keeps the bootstrap host for redirects.
        # Its DNS may subsequently stop working while the current site is valid.
        return {'host': 'bootstrap.example.org', 'site_host': 'current.example.org',
                'public_ip': '8.8.8.8', 'tls_ready': True, 'installed': True,
                'shared_host': True, 'acme_hosts': ['bootstrap.example.org', 'current.example.org']}

    def test_one_failed_certificate_must_not_prevent_current_site_renewal(self):
        public = self.public()
        attempted = []
        def renew(argv, **kwargs):
            certificate = argv[argv.index('--cert-name') + 1]
            attempted.append(certificate)
            if certificate == p.cert_name(public['host']):
                raise p.Failure('SYSTEM_COMMAND_FAILED', 'fixture-private-api-response-must-not-leak')
            return b''
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', return_value=contextlib.nullcontext()), \
             patch.object(p, 'read_json', return_value=public), patch.object(p, 'ensure_hosts_available'), \
             patch.object(p, 'renewal_config_exists', return_value=True), patch.object(p, 'run', side_effect=renew):
            with self.assertRaises(p.Failure) as caught:
                p.renew_certificates()
        self.assertIn(p.cert_name(public['site_host']), attempted,
                      'One unreachable bootstrap domain must not starve the healthy current HTTPS site indefinitely.')
        self.assertEqual('TLS_RENEW_FAILED', caught.exception.code)
        self.assertNotIn('fixture-private-api-response-must-not-leak', str(caught.exception))

    def test_missing_bootstrap_renewal_record_must_not_prevent_current_site_renewal(self):
        public = self.public()
        attempted = []
        def renew(argv, **kwargs):
            attempted.append(argv[argv.index('--cert-name') + 1])
            return b''
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', return_value=contextlib.nullcontext()), \
             patch.object(p, 'read_json', return_value=public), patch.object(p, 'ensure_hosts_available'), \
             patch.object(p, 'renewal_config_exists', side_effect=lambda host: host == public['site_host']), \
             patch.object(p, 'run', side_effect=renew):
            with self.assertRaises(p.Failure):
                p.renew_certificates()
        self.assertIn(p.cert_name(public['site_host']), attempted,
                      'A broken redirect-host certificate record must be reported after protecting other valid certificates.')

    def test_unsafe_old_config_is_skipped_and_reported_after_current_site_attempt(self):
        public = self.public()
        attempted = []
        def config_exists(host):
            if host == public['host']:
                raise p.Failure('UNSAFE_PATH', 'fixture-private-path-must-not-leak')
            return True
        def renew(argv, **kwargs):
            attempted.append(argv[argv.index('--cert-name') + 1])
            return b''
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', return_value=contextlib.nullcontext()), \
             patch.object(p, 'read_json', return_value=public), patch.object(p, 'ensure_hosts_available'), \
             patch.object(p, 'renewal_config_exists', side_effect=config_exists), patch.object(p, 'run', side_effect=renew):
            with self.assertRaises(p.Failure) as caught:
                p.renew_certificates()
        self.assertEqual([p.cert_name(public['site_host'])], attempted)
        self.assertEqual('UNSAFE_PATH', caught.exception.code)
        self.assertNotIn('fixture-private-path-must-not-leak', str(caught.exception))

    def test_current_site_failure_remains_visible_after_successful_bootstrap_attempt(self):
        public = self.public()
        attempted = []
        def renew(argv, **kwargs):
            certificate = argv[argv.index('--cert-name') + 1]
            attempted.append(certificate)
            if certificate == p.cert_name(public['site_host']):
                raise p.Failure('SYSTEM_COMMAND_FAILED', 'fixture-private-response')
            return b''
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', return_value=contextlib.nullcontext()), \
             patch.object(p, 'read_json', return_value=public), patch.object(p, 'ensure_hosts_available'), \
             patch.object(p, 'renewal_config_exists', return_value=True), patch.object(p, 'run', side_effect=renew):
            with self.assertRaises(p.Failure) as caught:
                p.renew_certificates()
        self.assertEqual(2, len(attempted))
        self.assertEqual('TLS_RENEW_FAILED', caught.exception.code)

    def test_successful_certificates_and_unissued_alias_need_no_aggregate_error(self):
        public = self.public()
        public['acme_hosts'].append('unissued.example.org')
        attempted = []
        def renew(argv, **kwargs):
            attempted.append(argv[argv.index('--cert-name') + 1])
            return b''
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', return_value=contextlib.nullcontext()), \
             patch.object(p, 'read_json', return_value=public), patch.object(p, 'ensure_hosts_available'), \
             patch.object(p, 'renewal_config_exists', side_effect=lambda host: host != 'unissued.example.org'), \
             patch.object(p, 'run', side_effect=renew):
            p.renew_certificates()
        self.assertEqual([p.cert_name(public['host']), p.cert_name(public['site_host'])], attempted)

    def test_missing_current_config_does_not_hide_error_or_stop_other_valid_certificates(self):
        public = self.public()
        attempted = []
        def renew(argv, **kwargs):
            attempted.append(argv[argv.index('--cert-name') + 1])
            return b''
        with patch.object(p.os, 'geteuid', return_value=0, create=True), \
             patch.object(p, 'shared_lock', return_value=contextlib.nullcontext()), \
             patch.object(p, 'read_json', return_value=public), patch.object(p, 'ensure_hosts_available'), \
             patch.object(p, 'renewal_config_exists', side_effect=lambda host: host == public['host']), \
             patch.object(p, 'run', side_effect=renew):
            with self.assertRaises(p.Failure) as caught:
                p.renew_certificates()
        self.assertEqual([p.cert_name(public['host'])], attempted)
        self.assertEqual('TLS_STATE', caught.exception.code)


if __name__ == '__main__':
    unittest.main(verbosity=2)
