#!/usr/bin/env python3
"""Independent failure-boundary tests. No real sockets, services, SQL, or API."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name!='posix':
    if not hasattr(os,'O_NOFOLLOW'):os.O_NOFOLLOW=0
    sys.modules.setdefault('pwd',types.SimpleNamespace())
    sys.modules.setdefault('grp',types.SimpleNamespace())
    sys.modules.setdefault('fcntl',types.SimpleNamespace(LOCK_EX=2,LOCK_NB=4,LOCK_UN=8,flock=lambda *_:None))
    import socketserver
    if not hasattr(socketserver,'ThreadingUnixStreamServer'):
        socketserver.ThreadingUnixStreamServer=type('OfflineUnixServer',(),{})

library=Path(__file__).resolve().parents[1]/'lib'
spec=importlib.util.spec_from_file_location('provision',library/'provision.py')
p=importlib.util.module_from_spec(spec);sys.modules['provision']=p;spec.loader.exec_module(p)
spec=importlib.util.spec_from_file_location('broker_under_test',library/'broker.py')
bmod=importlib.util.module_from_spec(spec);spec.loader.exec_module(bmod)


def configuration():
    return {'admin':{'username':'admin','password':'fixture-password-123','password_confirm':'fixture-password-123'},
        'telegram':{'enabled':False},'max':{'enabled':False},'timezone':'UTC','support_username':'',
        'hcaptcha':{'enabled':False},'mtproto':{'enabled':False}}


class BrokerReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.records={'public.json':{'installed':False,'host':'8.8.8.8','public_ip':'8.8.8.8','base_url':'https://8.8.8.8'},'private.json':{}}
        self.patches=[patch.object(p,'STATE',Path(self.temporary.name)),
            patch.object(p,'read_json',side_effect=lambda path,default=None:copy.deepcopy(self.records.get(Path(path).name,default))),
            patch.object(p,'save_json',side_effect=lambda path,value,*_:self.records.update({Path(path).name:copy.deepcopy(value)})),
            patch.object(p,'php_password',return_value='fixture-password-hash'),patch.object(bmod,'ZoneInfo',return_value=object())]
        for item in self.patches:item.start();self.addCleanup(item.stop)

    def test_finish_nginx_failure_does_not_publish_installed_marker(self):
        broker=bmod.Broker();broker.private={'settings':{},'config':{'base_url':'https://8.8.8.8'}}
        with patch.object(p,'configure_nginx',side_effect=p.Failure('NGINX_FAILED','Fixture failure')):
            with self.assertRaises(p.Failure):broker.install_step('finish')
        self.assertFalse(broker.public.get('installed'))
        self.assertFalse(self.records['public.json'].get('installed'))
        self.assertIn('config',broker.private)
        self.assertNotIn('installed.json',self.records)

    def test_busy_start_preserves_existing_state_and_does_not_poison_next_start(self):
        broker=bmod.Broker();before=(copy.deepcopy(broker.public),copy.deepcopy(broker.private))
        with patch.object(bmod.fcntl,'flock',side_effect=BlockingIOError()):
            with self.assertRaises(p.Failure):broker.dispatch('start',{'settings':configuration()})
        self.assertEqual(before,(broker.public,broker.private))

    def test_enrollment_cannot_consume_reissued_record_after_checking_old_record(self):
        old_code='a'*32;new_code='b'*32;salt='fixture-salt'
        def record(code):return {'salt':salt,'hash':hashlib.pbkdf2_hmac('sha256',code.encode(),salt.encode(),250000).hex(),
            'expires_at':4000000000,'consumed':False}
        old_record=record(old_code);new_record=record(new_code)
        self.records['private.json']={'enrollment':old_record};broker=bmod.Broker();held=False;reads=0
        @contextlib.contextmanager
        def installer_lock():
            nonlocal held
            held=True
            try:yield
            finally:held=False
        def read(path,default=None):
            nonlocal reads
            if Path(path).name=='private.json':
                reads+=1
                if reads==2 and not held:self.records['private.json']={'enrollment':new_record}
            return copy.deepcopy(self.records.get(Path(path).name,default))
        with patch.object(p,'installer_lock',installer_lock),patch.object(p,'read_json',side_effect=read):
            try:broker.dispatch('enroll',{'code':old_code})
            except p.Failure:pass
        persisted=self.records['private.json']['enrollment']
        if persisted['hash']==new_record['hash']:self.assertFalse(persisted['consumed'])
        else:self.assertEqual(old_record['hash'],persisted['hash'])


if __name__=='__main__':unittest.main()
