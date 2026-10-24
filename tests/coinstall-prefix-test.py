#!/usr/bin/env python3
"""Trust checks for shared hosts; all files belong to a disposable root tree."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name != 'posix':
    sys.modules.setdefault('pwd', types.SimpleNamespace())
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *_: None))

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prefix_coin', BASE / 'lib/coinstall.py')
co = importlib.util.module_from_spec(spec)
spec.loader.exec_module(co)


class HostDecisionTests(unittest.TestCase):
    def peer(self, **extra):
        return {'project': 'gitreposted', 'hosts': ['shared.example.org'], 'path_prefix': '/GitRePosted',
                'routing_verified': True, 'complete': True, **extra}

    def test_overlap_needs_both_fixed_prefixes_and_independent_routing_verification(self):
        for own, extra, allowed in [('/GitPosted', {}, True), (None, {}, False), ('', {}, False),
                                    ('/GitPosted', {'path_prefix': ''}, False),
                                    ('/GitPosted', {'routing_verified': False}, False)]:
            with self.subTest(own=own, extra=extra), patch.object(co, 'inspect_peer', return_value=self.peer(**extra)):
                if allowed:
                    self.assertEqual('gitreposted', co.validate_hosts('gitposted', ['shared.example.org'], path_prefix=own)['project'])
                else:
                    with self.assertRaises(co.CoInstallError) as caught:
                        co.validate_hosts('gitposted', ['shared.example.org'], path_prefix=own)
                    self.assertEqual('HOST_IN_USE', caught.exception.code)

    def test_unknown_own_prefix_fails_before_reading_peer(self):
        for prefix in ['/GitRePosted', '/gitposted', '/GitPosted/', '']:
            with self.subTest(prefix=prefix), patch.object(co, 'inspect_peer', return_value=None) as inspect:
                if prefix == '':
                    co.validate_hosts('gitposted', ['own.example.org'], path_prefix=prefix)
                else:
                    with self.assertRaises(co.CoInstallError):
                        co.validate_hosts('gitposted', ['own.example.org'], path_prefix=prefix)
                    inspect.assert_not_called()

    def test_partial_domain_projection_only_tolerates_already_claimed_authorities(self):
        gateway = co._gateway()
        public = {'host': 'shared.example.org', 'site_host': 'shared.example.org', 'public_ip': '8.8.8.8',
                  'path_prefix': '/GitRePosted', 'tls_ready': True, 'installed': False,
                  'acme_hosts': ['shared.example.org', 'new.example.org']}
        expected = gateway._descriptor('gitreposted', public)
        authorities = {'shared.example.org': {}, 'new.example.org': {}}
        for field in ('pending_host', 'site_host'):
            with self.subTest(field=field):
                committed = {**expected, field: 'new.example.org'}
                self.assertTrue(co._routing_projection_matches(committed, expected, authorities, complete=False))
                self.assertFalse(co._routing_projection_matches(committed, expected, authorities, complete=True))
                self.assertFalse(co._routing_projection_matches(committed, expected, {'shared.example.org': {}}, complete=False))
                self.assertFalse(co._routing_projection_matches({**committed, field: 'foreign.example.org'}, expected,
                                                               {**authorities, 'foreign.example.org': {}}, complete=False))
                for key, value in [('host', 'other.example.org'), ('public_ip', '1.1.1.1'), ('path_prefix', '/GitPosted'),
                                   ('acme_hosts', ['shared.example.org'])]:
                    self.assertFalse(co._routing_projection_matches({**committed, key: value}, expected,
                                                                   authorities, complete=False), key)


@unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Disposable filesystem requires real root-owned POSIX metadata')
class PrefixPeerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.top = Path(self.temporary.name)
        self.top.chmod(0o700)
        self.count = 0
        self.root_patch = patch.object(co, 'ROOT', self.top)
        self.root_patch.start()
        self.identity_patch = patch.object(co.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=10001))
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.temporary.cleanup)

    def fresh(self):
        self.count += 1
        self.root = self.top / str(self.count)
        self.root.mkdir(mode=0o700)
        co.ROOT = self.root
        return self.root

    def write(self, path, value, mode=0o600):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        target.write_text(json.dumps(value) if isinstance(value, dict) else value, encoding='utf-8')
        target.chmod(mode)
        return target

    def link(self, name):
        directory = self.root / 'etc/nginx/sites-enabled'
        directory.mkdir(parents=True, exist_ok=True, mode=0o755)
        (directory / name).symlink_to('/etc/nginx/sites-available/' + name)

    def peer(self, own='gitposted', *, host='shared.example.org', site_host=None, legacy=False,
             complete=True, topology=True, own_route=False):
        self.fresh()
        peer = co._project(own)
        site_host = site_host or host
        prefix = '' if legacy else co.PREFIXES[peer]
        state = '/var/lib/' + peer + '-installer/'
        bootstrap = {'installer': peer + '-clean-v1', 'host': host, 'public_ip': '8.8.8.8', 'shared_host': False}
        if prefix:
            bootstrap.update(path_prefix=prefix, routing_schema=1)
        self.write(state + 'bootstrap.json', bootstrap)
        public = {'host': host, 'site_host': site_host, 'public_ip': '8.8.8.8', 'installed': complete,
                  'tls_ready': True, 'site_url': 'https://' + site_host + prefix}
        if prefix:
            public.update(path_prefix=prefix, base_url='https://' + host + prefix)
        self.write(state + 'public.json', public, 0o640)
        if complete:
            self.write(state + 'installed.json', {'installed_at': 1700000000, 'version': 'fixture',
                                                'path_prefix': prefix, 'admin_url': 'https://' + site_host + prefix + '/control/'})
        config = self.write('/etc/' + peer + ('/config.php' if peer == 'gitposted' else '/config.json'), 'PRIVATE CONTENT MUST NOT BE READ')
        os.chown(config, 10001, 10001)
        config.parent.chmod(0o770)
        self.write('/etc/nginx/nginx.conf', 'http { include /etc/nginx/conf.d/*.conf; include /etc/nginx/sites-enabled/*; }', 0o644)
        if legacy:
            self.write('/etc/nginx/sites-available/' + peer + '-installer', 'server { server_name ' + host + ' ' + site_host + '; }', 0o644)
            self.link(peer + '-installer')
        elif topology:
            gateway = co._gateway()
            descriptor = gateway._descriptor(peer, public)
            registry = {'version': 1, 'projects': {peer: descriptor}, 'authorities': {}, 'default_host': host}
            if own_route:
                registry['projects'][own] = gateway._descriptor(own, {**public, 'path_prefix': co.PREFIXES[own]})
            for name, value in registry['projects'].items():
                for candidate in gateway._hosts(value):
                    registry['authorities'].setdefault(candidate, {**gateway._authority(name, candidate), 'tls_ready': True})
                backend = 'server { listen 127.0.0.1:' + str(gateway.PORTS[name]) + '; server_name _; location / { return 200; } }\n'
                self.write('/etc/nginx/sites-available/' + name + '-installer', gateway._backend(name, backend), 0o644)
                self.link(name + '-installer')
            self.write(gateway.REGISTRY, registry)
            self.write(gateway.SITE, gateway.render_registry(registry), 0o644)
            self.link('gitposted-suite')
        return peer, public

    def test_shared_ip_shared_domain_and_distinct_domains_in_both_orders(self):
        for own in co.PROJECTS:
            for peer_host, candidate in [('8.8.8.8', '8.8.8.8'), ('shared.example.org', 'shared.example.org'),
                                         ('peer.example.org', 'own.example.org')]:
                with self.subTest(own=own, peer_host=peer_host, candidate=candidate):
                    peer, public = self.peer(own, host=peer_host)
                    result = co.validate_hosts(own, [candidate], '8.8.8.8', path_prefix=co.PREFIXES[own])
                    self.assertTrue(result['complete'] and result['routing_verified'])
                    self.assertEqual(co.PREFIXES[peer], result['path_prefix'])
                    self.assertEqual(public['site_host'], result['site_host'])
                    self.assertNotIn('PRIVATE CONTENT', repr(result))

    def test_current_site_host_is_returned_after_first_started_on_ip(self):
        self.peer(host='8.8.8.8', site_host='current.example.org')
        result = co.inspect_peer('gitposted', '8.8.8.8')
        self.assertEqual('8.8.8.8', result['host'])
        self.assertEqual('current.example.org', result['site_host'])
        self.assertEqual('https://current.example.org/GitRePosted', result['site_url'])

    def test_legacy_peer_allows_distinct_domain_but_never_shared_host_in_both_orders(self):
        for own in co.PROJECTS:
            self.peer(own, legacy=True)
            result = co.validate_hosts(own, ['own.example.org'], path_prefix=co.PREFIXES[own])
            self.assertEqual('', result['path_prefix'])
            with self.assertRaises(co.CoInstallError) as caught:
                co.validate_hosts(own, ['shared.example.org'], path_prefix=co.PREFIXES[own])
            self.assertEqual('HOST_IN_USE', caught.exception.code)

    def test_partial_prefix_without_gateway_reserves_host_without_adopting_services(self):
        self.peer(complete=False, topology=False)
        with self.assertRaises(co.CoInstallError) as caught:
            co.inspect_peer('gitposted')
        self.assertEqual('PEER_INCOMPLETE', caught.exception.code)
        with self.assertRaises(co.CoInstallError) as caught:
            co.validate_hosts('gitposted', ['shared.example.org'], path_prefix='/GitPosted')
        self.assertEqual('HOST_IN_USE', caught.exception.code)
        result = co.validate_hosts('gitposted', ['own.example.org'], path_prefix='/GitPosted')
        self.assertFalse(result['complete'] or result['routing_verified'])

    def test_partial_verified_gateway_allows_first_project_operations_but_not_stack_adoption(self):
        self.peer(complete=False)
        result = co.validate_hosts('gitposted', ['shared.example.org'], path_prefix='/GitPosted')
        self.assertFalse(result['complete'])
        self.assertTrue(result['routing_verified'])
        with self.assertRaises(co.CoInstallError) as caught:
            co.inspect_peer('gitposted', require_complete=True)
        self.assertEqual('PEER_INCOMPLETE', caught.exception.code)

    def test_crash_after_gateway_commit_only_tolerates_partial_progress_flag_difference(self):
        self.peer(complete=False, host='8.8.8.8', site_host='current.example.org')
        public_path = self.root / 'var/lib/gitreposted-installer/public.json'
        public = json.loads(public_path.read_text())
        public.update(installed=False, tls_ready=False)
        self.write('/var/lib/gitreposted-installer/public.json', public, 0o640)
        gateway = co._gateway()
        registry = gateway.read_registry()
        registry['projects']['gitreposted'].update(installed=True, tls_ready=True)
        self.write(gateway.REGISTRY, registry)
        self.write(gateway.SITE, gateway.render_registry(registry), 0o644)
        result = co.validate_hosts('gitposted', ['8.8.8.8', 'current.example.org'], path_prefix='/GitPosted')
        self.assertTrue(result['routing_verified'])
        self.assertFalse(result['complete'])
        with self.assertRaises(co.CoInstallError) as caught:
            co.inspect_peer('gitposted', require_complete=True)
        self.assertEqual('PEER_INCOMPLETE', caught.exception.code)
        for flag in ['installed', 'tls_ready']:
            public[flag] = 'true'
            self.write('/var/lib/gitreposted-installer/public.json', public, 0o640)
            with self.assertRaises(co.CoInstallError):
                co.inspect_peer('gitposted', require_complete=False)
            public[flag] = False
        self.write('/var/lib/gitreposted-installer/public.json', public, 0o640)
        # Even in this seam an uncommitted different host is not trusted.
        public['site_host'] = 'different.example.org'
        self.write('/var/lib/gitreposted-installer/public.json', public, 0o640)
        with self.assertRaises(co.CoInstallError):
            co.inspect_peer('gitposted', require_complete=False)

    def test_complete_peer_never_tolerates_stale_gateway_progress_flags(self):
        self.peer()
        gateway = co._gateway()
        registry = gateway.read_registry()
        registry['projects']['gitreposted']['installed'] = False
        self.write(gateway.REGISTRY, registry)
        self.write(gateway.SITE, gateway.render_registry(registry), 0o644)
        with self.assertRaises(co.CoInstallError):
            co.inspect_peer('gitposted')

    def test_failed_domain_certificate_keeps_first_project_usable_in_both_orders(self):
        for own in co.PROJECTS:
            with self.subTest(own=own):
                peer, public = self.peer(own, complete=False, own_route=True)
                gateway = co._gateway()
                domain = 'new.example.org'
                public['acme_hosts'] = [public['host'], domain]
                self.write('/var/lib/' + peer + '-installer/public.json', public, 0o640)
                self.write('/var/lib/' + peer + '-installer/private.json', {'host_settings': {'host': domain, 'email': ''}})
                state = gateway.read_registry()
                # Normal failed issuance: HTTP claim is committed, but the
                # broker public projection has aliases without pending_host.
                state['projects'][peer] = gateway._descriptor(peer, {**public, 'pending_host': domain})
                state['authorities'][domain] = gateway._authority(peer, domain)
                state['authorities'][public['host']] = {**gateway._authority(own, public['host']), 'tls_ready': True}
                self.write(gateway.REGISTRY, state)
                self.write(gateway.SITE, gateway.render_registry(state), 0o644)
                result = co.validate_hosts(own, [public['host']], path_prefix=co.PREFIXES[own])
                self.assertTrue(result['routing_verified'])
                self.assertFalse(result['complete'])
                with self.assertRaises(co.CoInstallError) as caught:
                    co.inspect_peer(own, require_complete=True)
                self.assertEqual('PEER_INCOMPLETE', caught.exception.code)
                public['acme_hosts'] = [public['host']]
                self.write('/var/lib/' + peer + '-installer/public.json', public, 0o640)
                with self.assertRaises(co.CoInstallError):
                    co.validate_hosts(own, [public['host']], path_prefix=co.PREFIXES[own])

    def test_post_nginx_canonical_checkpoint_keeps_first_project_usable_in_both_orders(self):
        for own in co.PROJECTS:
            with self.subTest(own=own):
                peer, public = self.peer(own, complete=False, own_route=True)
                gateway = co._gateway()
                domain = 'new.example.org'
                public['acme_hosts'] = [public['host'], domain]
                self.write('/var/lib/' + peer + '-installer/public.json', public, 0o640)
                state = gateway.read_registry()
                # Crash after canonical gateway commit and before public save.
                state['projects'][peer] = gateway._descriptor(peer, {**public, 'site_host': domain})
                state['authorities'][domain] = {**gateway._authority(peer, domain), 'tls_ready': True}
                self.write(gateway.REGISTRY, state)
                self.write(gateway.SITE, gateway.render_registry(state), 0o644)
                result = co.validate_hosts(own, [public['host']], path_prefix=co.PREFIXES[own])
                self.assertTrue(result['routing_verified'])
                self.assertFalse(result['complete'])
                with self.assertRaises(co.CoInstallError) as caught:
                    co.inspect_peer(own, require_complete=True)
                self.assertEqual('PEER_INCOMPLETE', caught.exception.code)
                public['site_host'] = 'foreign.example.org'
                self.write('/var/lib/' + peer + '-installer/public.json', public, 0o640)
                with self.assertRaises(co.CoInstallError):
                    co.validate_hosts(own, [public['host']], path_prefix=co.PREFIXES[own])

    def test_missing_or_modified_gateway_cannot_attest_a_new_peer(self):
        for change in ['missing registry', 'modified gateway', 'missing gateway link', 'writable registry', 'unknown enabled site']:
            with self.subTest(change=change):
                self.peer()
                gateway = co._gateway()
                if change == 'missing registry':
                    (self.root / gateway.REGISTRY.lstrip('/')).unlink()
                elif change == 'modified gateway':
                    target = self.root / gateway.SITE.lstrip('/')
                    target.write_text(target.read_text() + '\nserver { listen 9000; }')
                elif change == 'missing gateway link':
                    (self.root / gateway.ENABLED.lstrip('/')).unlink()
                elif change == 'writable registry':
                    (self.root / gateway.REGISTRY.lstrip('/')).chmod(0o640)
                else:
                    self.link('foreign-site')
                with self.assertRaises(co.CoInstallError):
                    co.inspect_peer('gitposted')

    def test_backend_marker_listen_and_include_are_checked_for_every_registered_project(self):
        for change in ['marker', 'public listen', 'wrong port', 'foreign include', 'other backend']:
            with self.subTest(change=change):
                self.peer(own_route=True)
                target = self.root / 'etc/nginx/sites-available' / ('gitposted-installer' if change == 'other backend' else 'gitreposted-installer')
                value = target.read_text()
                if change == 'marker': value = value[value.index('\n') + 1:]
                elif change == 'public listen': value = value.replace('127.0.0.1:', '0.0.0.0:')
                elif change == 'wrong port': value = value.replace(':8182', ':9999')
                else: value = value.replace('location /', 'include /private/foreign.conf; location /')
                target.write_text(value)
                with self.assertRaises(co.CoInstallError):
                    co.inspect_peer('gitposted')

    def test_symlinked_registry_or_backend_is_rejected(self):
        for name in ['var/lib/gitposted-suite/routes.json', 'etc/nginx/sites-available/gitreposted-installer']:
            with self.subTest(name=name):
                self.peer()
                target = self.root / name
                saved = target.with_name(target.name + '.fixture')
                target.rename(saved)
                target.symlink_to(saved)
                with self.assertRaises(co.CoInstallError):
                    co.inspect_peer('gitposted')

    def test_prefix_urls_and_metadata_must_agree(self):
        state = '/var/lib/gitreposted-installer/'
        for name, key, value in [('bootstrap.json', 'path_prefix', '/GitPosted'), ('public.json', 'path_prefix', ''),
                                 ('bootstrap.json', 'host', 'different.example.org'),
                                 ('public.json', 'base_url', 'https://shared.example.org'),
                                 ('installed.json', 'admin_url', 'https://shared.example.org/control/'),
                                 ('bootstrap.json', 'routing_schema', True)]:
            with self.subTest(name=name, key=key):
                self.peer()
                path = self.root / (state + name).lstrip('/')
                changed = json.loads(path.read_text()); changed[key] = value
                self.write(state + name, changed, 0o640 if name == 'public.json' else 0o600)
                with self.assertRaises(co.CoInstallError):
                    co.inspect_peer('gitposted')

    def test_gateway_is_not_permitted_by_a_legacy_attestation(self):
        self.peer(legacy=True)
        self.write('/etc/nginx/sites-available/gitposted-suite', '# forged gateway', 0o644)
        self.link('gitposted-suite')
        with self.assertRaises(co.CoInstallError):
            co.inspect_peer('gitposted')


if __name__ == '__main__':
    unittest.main(verbosity=2)
