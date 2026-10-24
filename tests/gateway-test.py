#!/usr/bin/env python3
"""Isolated suite routing fixtures. No providers, database or services run.

The optional real nginx fixture binds ephemeral loopback ports only and uses
generated test certificates and captured HTTP echo backends.
"""
from __future__ import annotations

import copy
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location('fixture_suite_gateway', Path(__file__).resolve().parents[1] / 'lib/gateway.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
IP = '8.8.8.8'  # A host-name fixture only. Never contacted.
ROOT_POSIX = os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0


def public(project, host=IP, **changes):
    result = {'host': host, 'site_host': host, 'public_ip': IP,
              'path_prefix': g.PREFIXES[project], 'tls_ready': False,
              'installed': False, 'acme_hosts': [host]}
    result.update(changes)
    return result


def backend(project, echo_port=None):
    body = 'return 200 "' + project + '";'
    if echo_port is not None:
        body = 'proxy_pass http://127.0.0.1:' + str(echo_port) + '; proxy_set_header Host $http_host;'
    return 'server { listen 127.0.0.1:' + str(g.PORTS[project]) + '; server_name _; location / { ' + body + ' } }\n'


def registry(projects, *, ready=True):
    result = {'version': 1, 'projects': {}, 'authorities': {}, 'default_host': None}
    for project, value in projects:
        value = copy.deepcopy(value)
        result['projects'][project] = value
        for host in g._hosts(value):
            if host not in result['authorities']:
                result['authorities'][host] = g._authority(project, host)
            result['authorities'][host]['tls_ready'] = ready
            if result['default_host'] is None:
                result['default_host'] = host
    return result


def snapshot(root):
    result = {}
    for base in (root / 'etc/nginx', root / 'var/lib/gitposted-suite'):
        if not base.exists():
            continue
        for path in sorted(base.rglob('*')):
            if path.is_symlink():
                result[str(path.relative_to(root))] = ('link', os.readlink(path), path.lstat().st_uid)
            elif path.is_file():
                info = path.stat()
                result[str(path.relative_to(root))] = ('file', hashlib.sha256(path.read_bytes()).hexdigest(),
                                                       info.st_mode & 0o777, info.st_uid)
    return result


class PureRoutingTests(unittest.TestCase):
    def test_fixed_mounts_url_derivation_and_public_whitelist(self):
        for project in g.PREFIXES:
            result = g.project_public(project, {**public(project, 'base.example.org', site_host='site.example.org'),
                                                'token': 'must never enter routes', 'base_url': 'https://wrong.invalid'})
            self.assertEqual('https://base.example.org' + g.PREFIXES[project], result['base_url'])
            self.assertEqual('https://site.example.org' + g.PREFIXES[project] + '/control/', result['admin_url'])
            self.assertEqual('https://base.example.org' + g.PREFIXES[project] + '/install/', result['install_url'])
            self.assertNotIn('token', result)
            with self.assertRaises(g.GatewayError):
                g.project_public(project, public(project, path_prefix='/anything'))

    def test_both_orders_shared_ip_shared_domain_and_distinct_domains(self):
        for first, second in (('gitposted', 'gitreposted'), ('gitreposted', 'gitposted')):
            for first_host, second_host in ((IP, IP), ('shared.example.org', 'shared.example.org'),
                                             ('posted.example.org', 'reposted.example.org')):
                with self.subTest(first=first, hosts=(first_host, second_host)):
                    state = registry([(first, public(first, first_host)), (second, public(second, second_host))])
                    text = g.render_registry(state)
                    for host in {first_host, second_host}:
                        self.assertEqual(2, text.count('server_name ' + host + ';'))
                    self.assertEqual(1, text.count('listen 80 default_server;'))
                    self.assertEqual(1, text.count('listen 443 ssl default_server;'))
                    self.assertEqual(1, text.count('proxy_pass http://127.0.0.1:8181/;'))
                    self.assertEqual(1, text.count('proxy_pass http://127.0.0.1:8182/;'))
                    self.assertIn('proxy_set_header X-Forwarded-For $remote_addr;', text)
                    self.assertIn('proxy_set_header X-Original-URI $request_uri;', text)
                    self.assertIn('location / { return 404; }', text)
                    if first_host == second_host:
                        owner = state['authorities'][first_host]
                        self.assertEqual(first, owner['owner'])
                        self.assertIn('/etc/letsencrypt/live/' + owner['cert_name'] + '/fullchain.pem', text)
                        self.assertNotIn('/etc/letsencrypt/live/' + g._certificate(second, second_host), text)

    def test_pending_http_claim_never_publishes_missing_tls_and_old_alias_redirects(self):
        value = public('gitposted', 'old.example.org', site_host='new.example.org',
                       pending_host='pending.example.org', installed=True,
                       acme_hosts=['old.example.org', 'new.example.org'])
        state = registry([('gitposted', value)])
        state['authorities']['pending.example.org']['tls_ready'] = False
        text = g.render_registry(state)
        self.assertEqual(1, text.count('server_name pending.example.org;'))
        self.assertNotIn('/live/' + state['authorities']['pending.example.org']['cert_name'], text)
        self.assertIn('return 308 https://new.example.org$request_uri;', text)
        self.assertIn('location ^~ /GitPosted/', text)

    def test_registry_and_backend_reject_injection_and_unknown_ownership(self):
        baseline = registry([('gitposted', public('gitposted'))])
        mutations = [
            lambda s: s.update(version=True),
            lambda s: s.update(unrecognized='value'),
            lambda s: s['authorities'][IP].update(owner='other'),
            lambda s: s['authorities'][IP].update(cert_name='../../wrong'),
            lambda s: s['authorities'][IP].update(acme_root='/tmp/foreign'),
            lambda s: s['projects']['gitposted'].update(path_prefix='/GitRePosted'),
            lambda s: s['projects']['gitposted'].update(host='x; return 200;'),
            lambda s: s.update(default_host='unclaimed.example.org'),
        ]
        for mutate in mutations:
            state = copy.deepcopy(baseline); mutate(state)
            with self.assertRaises(g.GatewayError):
                g.render_registry(state)
        self.assertIn('127.0.0.1:8181', g._backend('gitposted', '# listen 80;\n' + backend('gitposted')))
        for bad in (backend('gitposted').replace('127.0.0.1:8181', '0.0.0.0:8181'),
                    backend('gitposted').replace('server_name', 'listen 443 ssl; server_name'),
                    backend('gitposted').replace('server_name', 'include /tmp/foreign.conf; server_name'),
                    backend('gitreposted')):
            with self.assertRaises(g.GatewayError):
                g._backend('gitposted', bad)


@unittest.skipUnless(ROOT_POSIX, 'POSIX root filesystem ownership and rollback fixture')
class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='gitposted-gateway-')
        self.root = Path(self.temporary.name).resolve(); self.root.chmod(0o700)
        self.previous_root = g.ROOT; g.ROOT = self.root
        self.commands = []

    def tearDown(self):
        g.ROOT = self.previous_root
        self.temporary.cleanup()

    def run_cmd(self, command, **_kwargs):
        self.commands.append(tuple(command))
        return b''

    def test_both_orders_reuse_authority_and_second_app_never_claims_certificate(self):
        for first, second in (('gitposted', 'gitreposted'), ('gitreposted', 'gitposted')):
            with self.subTest(first=first):
                with tempfile.TemporaryDirectory(dir=self.root) as child:
                    g.ROOT = Path(child); g.ROOT.chmod(0o700)
                    result = g.configure(first, public(first, tls_ready=True), backend(first), self.run_cmd)
                    self.assertFalse(result['tls_ready'], 'Public flag must not publish an unissued certificate')
                    original = g.get_authority(IP)
                    self.assertEqual(first, original['owner'])
                    g.mark_tls_ready(first, IP, self.run_cmd)
                    first_backend = (g.ROOT / ('etc/nginx/sites-available/' + first + '-installer')).read_bytes()
                    result = g.configure(second, public(second), backend(second), self.run_cmd)
                    self.assertTrue(result['tls_ready'], 'The shared ready authority is immediately reusable')
                    self.assertEqual(first, g.get_authority(IP)['owner'])
                    self.assertEqual(original['cert_name'], g.get_authority(IP)['cert_name'])
                    self.assertEqual(first_backend, (g.ROOT / ('etc/nginx/sites-available/' + first + '-installer')).read_bytes())
                    before = snapshot(g.ROOT)
                    with self.assertRaises(g.GatewayError) as caught:
                        g.mark_tls_ready(second, IP, self.run_cmd)
                    self.assertEqual('CERTIFICATE_OWNER_REQUIRED', caught.exception.code)
                    self.assertEqual(before, snapshot(g.ROOT))
                    self.assertEqual(0o600, (g.ROOT / g.REGISTRY.lstrip('/')).stat().st_mode & 0o777)
                    self.assertEqual(0o700, (g.ROOT / 'var/lib/gitposted-suite').stat().st_mode & 0o777)
                g.ROOT = self.root

    def test_failed_second_nginx_validation_or_reload_rolls_back_all_files_and_retry(self):
        for failing_command in (('nginx', '-t'), ('systemctl', 'reload', 'nginx')):
            with self.subTest(failing_command=failing_command):
                with tempfile.TemporaryDirectory(dir=self.root) as child:
                    g.ROOT = Path(child); g.ROOT.chmod(0o700)
                    g.configure('gitposted', public('gitposted'), backend('gitposted'), self.run_cmd)
                    g.mark_tls_ready('gitposted', IP, self.run_cmd)
                    before = snapshot(g.ROOT)
                    invoked = []
                    class InjectedFailure(Exception):
                        pass
                    def fail_once(command, **_kwargs):
                        command = tuple(command); invoked.append(command)
                        if command == failing_command and invoked.count(command) == 1:
                            raise InjectedFailure('Fixture command failure')
                        return b''
                    with self.assertRaises(InjectedFailure):
                        g.configure('gitreposted', public('gitreposted'), backend('gitreposted'), fail_once)
                    self.assertEqual(before, snapshot(g.ROOT), 'Failed second application changed first/registry/link state')
                    self.assertEqual({'gitposted'}, set(g.read_registry()['projects']))
                    if failing_command[0] == 'systemctl':
                        self.assertEqual(2, invoked.count(failing_command), 'Old config must be reloaded after an uncertain reload')
                    g.configure('gitreposted', public('gitreposted'), backend('gitreposted'), self.run_cmd)
                    self.assertEqual({'gitposted', 'gitreposted'}, set(g.read_registry()['projects']))
                g.ROOT = self.root

    def test_cancelled_transaction_and_tls_failure_preserve_previous_state(self):
        g.configure('gitposted', public('gitposted'), backend('gitposted'), self.run_cmd)
        before = snapshot(self.root)
        class Cancelled(BaseException):
            pass
        def cancel(*_args, **_kwargs):
            raise Cancelled()
        with self.assertRaises(Cancelled):
            g.mark_tls_ready('gitposted', IP, cancel)
        self.assertEqual(before, snapshot(self.root))
        self.assertFalse(g.get_authority(IP)['tls_ready'])
        g.mark_tls_ready('gitposted', IP, self.run_cmd)
        g.configure('gitposted', public('gitposted', 'posted.example.org'), backend('gitposted'), self.run_cmd)
        self.assertEqual(IP, g.read_registry()['default_host'], 'A new domain must not move the stable default authority')
        self.assertEqual('gitposted', g.get_authority(IP)['owner'], 'Historical certificate ownership is retained')

    def test_unsafe_registry_backend_and_enabled_link_are_rejected_without_foreign_mutation(self):
        g.configure('gitposted', public('gitposted'), backend('gitposted'), self.run_cmd)
        registry_path = self.root / g.REGISTRY.lstrip('/')
        registry_path.chmod(0o666)
        with self.assertRaises(g.GatewayError):
            g.read_registry()
        registry_path.chmod(0o600)
        enabled = self.root / g.ENABLED.lstrip('/')
        enabled.unlink(); enabled.symlink_to('/tmp/not-a-suite-site')
        before = snapshot(self.root)
        with self.assertRaises(g.GatewayError):
            g.configure('gitreposted', public('gitreposted'), backend('gitreposted'), self.run_cmd)
        self.assertEqual(before, snapshot(self.root))
        enabled.unlink(); enabled.symlink_to(g.SITE)
        peer = self.root / 'etc/nginx/sites-available/gitreposted-installer'
        peer.write_text('server { listen 9000; }'); peer.chmod(0o644)
        before = snapshot(self.root)
        with self.assertRaises(g.GatewayError):
            g.configure('gitreposted', public('gitreposted'), backend('gitreposted'), self.run_cmd)
        self.assertEqual(before, snapshot(self.root))


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        payload = json.dumps({'method': self.command, 'path': self.path, 'body': body.decode('utf-8'),
                              'headers': dict(self.headers), 'project': self.server.project}).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def log_message(self, *_args):
        pass


@unittest.skipUnless(ROOT_POSIX and shutil.which('nginx') and shutil.which('openssl'), 'POSIX root private nginx/openssl loopback fixture')
class RealNginxTests(unittest.TestCase):
    def test_real_composition_both_orders_and_all_host_layouts(self):
        for first, second in (('gitposted', 'gitreposted'), ('gitreposted', 'gitposted')):
            for first_host, second_host in ((IP, IP), ('shared.example.org', 'shared.example.org'),
                                             ('posted.example.org', 'reposted.example.org')):
                with self.subTest(first=first, hosts=(first_host, second_host)), tempfile.TemporaryDirectory(prefix='suite-nginx-') as temporary:
                    root = Path(temporary).resolve(); root.chmod(0o700)
                    previous_root = g.ROOT; g.ROOT = root
                    echoes, threads, nginx = {}, [], None
                    try:
                        contents = {}
                        for project in g.PREFIXES:
                            server = ThreadingHTTPServer(('127.0.0.1', 0), Echo); server.project = project
                            echoes[project] = server
                            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start(); threads.append(thread)
                            contents[project] = backend(project, server.server_port)
                        fake_run = lambda *_args, **_kwargs: b''
                        g.configure(first, public(first, first_host), contents[first], fake_run)
                        g.mark_tls_ready(first, first_host, fake_run)
                        g.configure(second, public(second, second_host), contents[second], fake_run)
                        owner = g.get_authority(second_host)['owner']
                        if not g.get_authority(second_host)['tls_ready']:
                            g.mark_tls_ready(owner, second_host, fake_run)
                        state = g.read_registry()
                        key, cert = root / 'test.key', root / 'test.pem'
                        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                                        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=suite-fixture'],
                                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
                        ports = set()
                        while len(ports) < 4:
                            ports.add(free_port())
                        http_port, tls_port, posted_port, reposted_port = sorted(ports)
                        back_ports = {'gitposted': posted_port, 'gitreposted': reposted_port}
                        text = g.render_registry(state) + '\n' + '\n'.join(contents.values())
                        text = text.replace('listen 80', 'listen 127.0.0.1:' + str(http_port)).replace('listen 443 ssl', 'listen 127.0.0.1:' + str(tls_port) + ' ssl')
                        for project in g.PREFIXES:
                            text = text.replace('127.0.0.1:' + str(g.PORTS[project]), '127.0.0.1:' + str(back_ports[project]))
                        acme_replacements = {}
                        for host, authority in state['authorities'].items():
                            text = text.replace('/etc/letsencrypt/live/' + authority['cert_name'] + '/fullchain.pem', str(cert))
                            text = text.replace('/etc/letsencrypt/live/' + authority['cert_name'] + '/privkey.pem', str(key))
                            acme = root / authority['acme_root'].lstrip('/')
                            challenge = acme / '.well-known/acme-challenge/probe'
                            challenge.parent.mkdir(parents=True, exist_ok=True); challenge.write_text(authority['owner'])
                            acme_replacements[authority['acme_root']] = str(acme)
                        for source, target in acme_replacements.items():
                            text = text.replace(source, target)
                        for name in ('client', 'proxy', 'fastcgi', 'scgi', 'uwsgi'):
                            (root / name).mkdir()
                        config = root / 'nginx.conf'
                        config.write_text('daemon off;\nmaster_process off;\npid ' + str(root / 'nginx.pid') + ';\nerror_log ' + str(root / 'nginx.log') + ' notice;\nevents {}\nhttp {\naccess_log off;\n' +
                                          '\n'.join(name + '_temp_path ' + str(root / directory) + ';' for name, directory in
                                                    (('client_body', 'client'), ('proxy', 'proxy'), ('fastcgi', 'fastcgi'), ('scgi', 'scgi'), ('uwsgi', 'uwsgi'))) + '\n' + text + '\n}\n')
                        command = ['nginx', '-p', str(root), '-c', str(config), '-e', str(root / 'nginx.log')]
                        check = subprocess.run(command + ['-t'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                        self.assertEqual(0, check.returncode, check.stderr.decode(errors='replace'))
                        nginx = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            try:
                                with socket.create_connection(('127.0.0.1', http_port), timeout=0.2):
                                    break
                            except OSError:
                                self.assertIsNone(nginx.poll(), 'Private nginx exited early'); time.sleep(0.03)
                        for project, host in ((first, first_host), (second, second_host)):
                            prefix = g.PREFIXES[project]
                            connection = http.client.HTTPSConnection('127.0.0.1', tls_port, context=ssl._create_unverified_context(), timeout=5)
                            uri = prefix + '/api/check?x=a%2Fb&x=2'
                            connection.request('POST', uri, body='{"fixture":true}', headers={'Host': host, 'X-Forwarded-For': 'evil', 'X-Real-IP': 'evil', 'X-Forwarded-Proto': 'http', 'X-Forwarded-Prefix': '/other', 'X-Original-URI': '/wrong'})
                            response = connection.getresponse(); response_body = response.read(); connection.close()
                            self.assertEqual(200, response.status, response_body.decode(errors='replace'))
                            payload = json.loads(response_body); self.assertEqual(project, payload['project'])
                            self.assertEqual('/api/check?x=a%2Fb&x=2', payload['path']); self.assertEqual('POST', payload['method'])
                            self.assertEqual('{"fixture":true}', payload['body'])
                            for header, expected in {'Host': host, 'X-Forwarded-Proto': 'https', 'X-Forwarded-Prefix': prefix,
                                                     'X-Original-URI': uri, 'X-Real-IP': '127.0.0.1', 'X-Forwarded-For': '127.0.0.1'}.items():
                                self.assertEqual(expected, payload['headers'].get(header), header)
                            connection = http.client.HTTPConnection('127.0.0.1', http_port, timeout=5)
                            connection.request('GET', '/.well-known/acme-challenge/probe', headers={'Host': host})
                            response = connection.getresponse(); self.assertEqual(200, response.status)
                            self.assertEqual(state['authorities'][host]['owner'], response.read().decode()); connection.close()
                            connection = http.client.HTTPSConnection('127.0.0.1', tls_port, context=ssl._create_unverified_context(), timeout=5)
                            connection.request('GET', prefix + '?query=keep', headers={'Host': host})
                            response = connection.getresponse(); response.read()
                            self.assertEqual(308, response.status); self.assertEqual('https://' + host + prefix + '/?query=keep', response.getheader('Location')); connection.close()
                            connection = http.client.HTTPSConnection('127.0.0.1', tls_port, context=ssl._create_unverified_context(), timeout=5)
                            connection.request('GET', prefix + 'Other/', headers={'Host': host})
                            response = connection.getresponse(); response.read(); self.assertEqual(404, response.status); connection.close()
                    finally:
                        if nginx is not None:
                            if nginx.poll() is None:
                                os.killpg(nginx.pid, signal.SIGTERM)
                            nginx.wait(timeout=5)
                        for server in echoes.values():
                            server.shutdown(); server.server_close()
                        for thread in threads:
                            thread.join(timeout=5)
                        g.ROOT = previous_root


if __name__ == '__main__':
    unittest.main(verbosity=2)
