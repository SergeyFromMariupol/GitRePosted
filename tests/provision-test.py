#!/usr/bin/env python3
"""Offline provisioning review: no subprocess, package installation, API or root writes."""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name != 'posix':
    # Provisioning is Linux-only. Allow pure render/validation tests on the
    # author's Windows machine without emulating any privileged operation.
    sys.modules.setdefault('pwd', types.SimpleNamespace())
    sys.modules.setdefault('grp', types.SimpleNamespace())
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *_: None))

spec=importlib.util.spec_from_file_location('provision_under_test',Path(__file__).resolve().parents[1]/'lib/provision.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProvisionTests(unittest.TestCase):
    def public(self,installed=False):
        return {'host':'8.8.8.8','site_host':'example.com','tls_ready':True,'installed':installed}

    def test_host_never_accepts_shell_path_url_or_private_ip(self):
        for host in ('example.com; id','https://example.com','example.com/path','evil\nserver','example.com:443','127.0.0.1','10.0.0.1','a.local'):
            with self.subTest(host=host),self.assertRaises(module.Failure): module.host_name(host)
        self.assertEqual('example.com',module.host_name('EXAMPLE.COM'))

    def test_dns_rejects_any_foreign_ipv6_or_a_record(self):
        with patch.object(socket,'getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',443)),(10,1,6,'',('::1',443,0,0))]):
            with self.assertRaises(module.Failure):module.dns_matches('example.com','8.8.8.8')
        with patch.object(socket,'getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',443))]):
            module.dns_matches('example.com','8.8.8.8')

    def test_nginx_proxies_only_to_loopback_and_keeps_setup_https_explicit(self):
        text=module.nginx_content(self.public(True))
        self.assertIn('fastcgi_param HTTPS on;',text)
        self.assertIn('php|py|sql|gz|ini|log|json|sh|md|pem|lock|env',text)
        self.assertNotIn('$http_x_forwarded_proto',text)
        self.assertNotIn('root '+str(module.APP),text)
        self.assertIn('proxy_pass http://127.0.0.1:3010;',text)
        self.assertIn('proxy_set_header X-Forwarded-For $remote_addr;',text)
        self.assertNotIn('$proxy_add_x_forwarded_for',text)
        self.assertIn('location = /webhooks/telegram { client_max_body_size 2m;',text)
        self.assertIn('location = /install/api.php { client_max_body_size 64k;',text)
        self.assertIn('fastcgi_read_timeout 50s;',text)

    def test_uninstalled_https_hosts_redirect_app_paths_to_wizard_until_schema_and_config_are_ready(self):
        text=module.nginx_content(self.public())
        self.assertEqual(2,text.count('location / { return 302 /install/; }'))
        self.assertEqual(2,text.count('location = /webhooks/telegram'))
        self.assertEqual(2,text.count('location = /webhooks/max'))
        self.assertIn('location = /install/api.php',text)
        self.assertIn('location ^~ /install/assets/',text)
        self.assertNotIn('control/index',text);self.assertNotIn('try_files',text)
        self.assertNotIn('index index.php',text)

    def test_installed_nginx_closes_ui_but_keeps_exact_status_endpoint(self):
        text=module.nginx_content(self.public(True))
        self.assertIn('location = /install/api.php',text)
        self.assertIn('location /install/ { return 404; }',text)
        self.assertNotIn('SCRIPT_FILENAME '+str(module.INSTALL)+'/web/index.php',text)
        self.assertNotIn('location ^~ /install/ { return 404; }',text)

    def test_nginx_does_not_interpolate_unvalidated_host(self):
        public=self.public();public['site_host']='example.com; include /etc/passwd;'
        with self.assertRaises(module.Failure):module.nginx_content(public)

    def test_command_failure_never_includes_stderr_or_stdin(self):
        response=types.SimpleNamespace(returncode=1,stdin=None,stdout=None,stderr=None,
            communicate=lambda **_: (b'',b'private-token-in-stderr'),poll=lambda:1)
        with patch.object(module.subprocess,'Popen',return_value=response):
            with self.assertRaises(module.Failure) as caught:module.run(['fake'],data=b'private-password',safe='Safe failure')
        self.assertEqual('Safe failure',str(caught.exception))
        self.assertNotIn('private',str(caught.exception))



    def test_ready_resume_only_reissues_link_not_provisions_or_resets_public(self):
        public=self.public();public.update({'base_url':'https://8.8.8.8','site_url':'https://example.com'})
        with tempfile.TemporaryDirectory()as temporary,patch.object(module,'STATE',Path(temporary)),patch.object(module,'read_json',return_value=public),\
             patch.object(module,'enrollment',return_value='fixture-personal-token')as enroll,patch.object(module,'run',return_value=b'')as run,\
             patch.object(module,'copy_tree')as copy,patch.object(module,'save_json')as save,contextlib.redirect_stdout(io.StringIO())as output:
            self.assertTrue(module.resume_ready());enroll.assert_called_once();copy.assert_not_called();save.assert_not_called()
            self.assertIn('/install/#setup=fixture-personal-token',output.getvalue())
            self.assertTrue(all(call.args[0][0]=='systemctl' for call in run.call_args_list))
            self.assertFalse(any('restart'in call.args[0]for call in run.call_args_list))

    def test_resume_after_installed_is_terminal(self):
        with tempfile.TemporaryDirectory()as temporary,patch.object(module,'STATE',Path(temporary)),patch.object(module,'read_json',return_value={'installed':True}),patch.object(module,'enrollment')as enroll:
            with self.assertRaises(module.Failure):module.resume_ready()
            enroll.assert_not_called()

    def test_durable_marker_reconciles_terminal_state_and_removes_duplicate_credentials(self):
        with tempfile.TemporaryDirectory()as temporary,patch.object(module,'STATE',Path(temporary)):
            state=Path(temporary);(state/'installed.json').write_text('{}');(state/'access.json').write_text('fixture-access')
            records={'installed.json':{'installed_at':1700000000,'version':'fixture-version','admin_url':'https://example.com/control/'},
                'public.json':{'host':'8.8.8.8','base_url':'https://8.8.8.8','installed':False,
                    'job':{'id':'existing-job','status':'failed','error':{'code':'INTERRUPTED'},'steps':[
                        {'id':'schema','status':'done'},{'id':'telegram','status':'skipped'},{'id':'finish','status':'running'}]}},
                'private.json':{'settings':{'token':'fixture-secret'},'config':{'password':'fixture-secret'},
                    'enrollment':{'hash':'fixture-hash'},'database_owned':True}}
            with patch.object(module,'read_json',side_effect=lambda path,default=None:copy.deepcopy(records.get(Path(path).name,default))),\
                 patch.object(module,'save_json',side_effect=lambda path,value,*_:records.update({Path(path).name:copy.deepcopy(value)})),\
                 patch.object(module,'enrollment')as enroll,patch.object(module,'run')as run:
                self.assertTrue(module.resume_ready())
                snapshot=copy.deepcopy(records)
                self.assertTrue(module.reconcile_installed());self.assertEqual(snapshot,records)
                enroll.assert_not_called();run.assert_not_called()
            public=records['public.json'];self.assertTrue(public['installed'])
            self.assertEqual('https://example.com/control/',public['admin_url'])
            self.assertEqual('https://8.8.8.8',public['base_url'])
            self.assertEqual('existing-job',public['job']['id']);self.assertEqual('complete',public['job']['status'])
            self.assertEqual(['done','skipped','done'],[x['status']for x in public['job']['steps']])
            self.assertEqual({'database_owned':True},records['private.json']);self.assertFalse((state/'access.json').exists())

    def test_invalid_terminal_marker_never_reopens_or_writes_state(self):
        invalid=[{}, {'installed_at':True,'version':'v','admin_url':'https://example.com/control/'},
            {'installed_at':1,'version':'v','admin_url':'http://example.com/control/'},
            {'installed_at':1,'version':'v','admin_url':'https://example.com/control/?token=secret'},
            {'installed_at':1,'version':'v','admin_url':'https://evil@example.com/control/'}]
        for marker in invalid:
            with self.subTest(marker=marker),tempfile.TemporaryDirectory()as temporary,patch.object(module,'STATE',Path(temporary)),\
                 patch.object(module,'read_json',return_value=marker),patch.object(module,'save_json')as save,patch.object(module,'enrollment')as enroll:
                (Path(temporary)/'installed.json').write_text('{}')
                with self.assertRaises(module.Failure):module.resume_ready()
                save.assert_not_called();enroll.assert_not_called()

    def test_reconciliation_failure_leaves_marker_authoritative_for_retry(self):
        with tempfile.TemporaryDirectory()as temporary,patch.object(module,'STATE',Path(temporary)):
            (Path(temporary)/'installed.json').write_text('{}')
            records={'installed.json':{'installed_at':1,'version':'v','admin_url':'https://example.com/control/'},
                     'public.json':{'installed':False},'private.json':{'config':{'secret':'fixture'}}}
            with patch.object(module,'read_json',side_effect=lambda path,default=None:copy.deepcopy(records.get(Path(path).name,default))),\
                 patch.object(module,'save_json',side_effect=module.Failure('WRITE_FAILED','Fixture failure')):
                with self.assertRaises(module.Failure):module.reconcile_installed()
            self.assertTrue((Path(temporary)/'installed.json').exists());self.assertFalse(records['public.json']['installed'])

    def test_installed_main_repairs_before_detection_or_preflight(self):
        with tempfile.TemporaryDirectory()as temporary,patch.object(module,'STATE',Path(temporary)),\
             patch.object(module.sys,'argv',['provision.py','--resume']),patch.object(module.os,'geteuid',return_value=0,create=True),\
             patch.object(module,'installer_lock',contextlib.nullcontext),patch.object(module,'reconcile_installed',return_value=True)as repair,\
             patch.object(module,'read_json',return_value={'admin_url':'https://example.com/control/'}),\
             patch.object(module,'detect_ip')as detect,patch.object(module,'preflight')as preflight,contextlib.redirect_stdout(io.StringIO())as output:
            (Path(temporary)/'installed.json').write_text('{}');module.main()
            repair.assert_called_once();detect.assert_not_called();preflight.assert_not_called()
            self.assertIn('https://example.com/control/',output.getvalue())

    def test_resume_never_reprovisions_started_settings_when_tls_metadata_missing(self):
        for key in ('settings','config','job'):
            with self.subTest(key=key),tempfile.TemporaryDirectory()as temporary,patch.object(module,'STATE',Path(temporary)),\
                 patch.object(module,'read_json',side_effect=[{'tls_ready':False},{key:{'existing':True}}]),patch.object(module,'enrollment')as enroll:
                with self.assertRaises(module.Failure):module.resume_ready()
                enroll.assert_not_called()

    def test_personal_link_uses_fragment_never_query_or_separate_manual_code(self):
        with contextlib.redirect_stdout(io.StringIO())as output:module.show_link('example.com','fixture-opaque-token')
        value=output.getvalue();self.assertIn('https://example.com/install/#setup=fixture-opaque-token',value)
        self.assertNotIn('?setup=',value);self.assertNotIn('Setup code',value)

    def test_enrollment_preserves_pending_settings_without_putting_raw_code_in_state(self):
        private={'settings':{'fake':'pending'},'job':{'status':'failed'}};writes={}
        with patch.object(module,'read_json',return_value=private),patch.object(module,'enrollment_password',return_value='fixture-hash'),\
             patch.object(module,'save_json',side_effect=lambda path,value,*_:writes.update({Path(path).name:value})):
            code=module.enrollment()
        self.assertEqual({'fake':'pending'},writes['private.json']['settings'])
        self.assertEqual('fixture-hash',writes['access.json']['code_hash'])
        self.assertNotIn(code,json.dumps(writes))

    def test_fixed_pool_has_separate_uids_no_shell_or_public_secret_path(self):
        writes={}
        with patch.object(module,'atomic',side_effect=lambda path,text,*_:writes.update({str(path):text})),patch.object(module,'run',return_value=b''):
            module.pools()
        self.assertIn('user = gitreposted-setup',writes['/etc/php/8.3/fpm/pool.d/gitreposted-installer.conf'])
        self.assertNotIn('/etc/php/8.3/fpm/pool.d/gitreposted.conf',writes)
        self.assertIn('clear_env = yes',writes['/etc/php/8.3/fpm/pool.d/gitreposted-installer.conf'])
        setup=writes['/etc/php/8.3/fpm/pool.d/gitreposted-installer.conf']
        self.assertIn('request_terminate_timeout = 60s',setup);self.assertIn('php_admin_value[max_execution_time] = 60',setup)
        for pool in (setup,):
            self.assertIn('php_admin_flag[opcache.validate_timestamps] = on',pool)
            self.assertIn('php_admin_value[opcache.revalidate_freq] = 0',pool)

    def test_release_directory_explicitly_opens_each_code_ancestor(self):
        with patch.object(module,'directory')as directory:
            release=module.release_directory()
        self.assertEqual(module.APP/'releases'/module.VERSION,release)
        self.assertEqual([((module.APP,0o755),{}),((module.APP/'releases',0o755),{}),((release,0o755),{})],
                         [(call.args,call.kwargs)for call in directory.call_args_list])

    @unittest.skipUnless(os.name=='posix','Linux permission fixture')
    def test_release_ancestors_remain_traversable_under_strict_bootstrap_umask(self):
        with tempfile.TemporaryDirectory()as temporary,patch.object(module,'APP',Path(temporary)/'gitreposted'):
            old=os.umask(0o077)
            try:release=module.release_directory()
            finally:os.umask(old)
            for directory in (module.APP,module.APP/'releases',release):
                self.assertEqual(0o755,directory.stat().st_mode&0o777)

    def test_python_services_never_write_cache_into_immutable_package(self):
        writes={}
        with patch.object(module,'atomic',side_effect=lambda path,text,*_:writes.update({str(path):text})):
            module.units()
        for name in ('gitreposted-installer','gitreposted-rate-limit-cleanup'):
            self.assertIn('ExecStart=/usr/bin/python3 -B ',writes['/etc/systemd/system/'+name+'.service'])
        self.assertEqual(module.STATE/'certbot/bin/certbot',module.CERTBOT)


if __name__=='__main__':unittest.main()
