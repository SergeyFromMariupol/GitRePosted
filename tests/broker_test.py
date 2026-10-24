#!/usr/bin/env python3
"""Offline root-broker regressions. All system/API effects use temporary fixtures."""
from __future__ import annotations

import hashlib
from contextlib import nullcontext
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

LIB = Path(__file__).resolve().parents[1] / "lib"
sys.path.insert(0, str(LIB))
# Pure fixture tests can also run on Windows; production still requires Linux.
if os.name != "posix":
    fake_fcntl = types.ModuleType("fcntl")
    fake_fcntl.LOCK_EX, fake_fcntl.LOCK_NB, fake_fcntl.LOCK_UN = 1, 2, 8
    fake_fcntl.flock = lambda *_: None
    sys.modules["fcntl"] = fake_fcntl
    for name in ("pwd", "grp"):
        sys.modules.setdefault(name, types.ModuleType(name))
    socketserver.ThreadingUnixStreamServer = type("FixtureUnixServer", (), {})
    socket.SO_PEERCRED = 17

SPEC = importlib.util.spec_from_file_location("installer_broker", LIB / "broker.py")
broker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(broker)
p = broker.p


def valid_settings(telegram=False, max_enabled=False):
    return {"admin": {"username": "operator", "password": "long-fixture-password", "password_confirm": "long-fixture-password"},
            "telegram": {"enabled": telegram, "token": "123456:" + "a" * 32, "takeover": False},
            "max": {"enabled": max_enabled, "token": "fixture-max-token", "takeover": False},
            "timezone": "UTC", "support_username": "", "hcaptcha": {"enabled": False}, "mtproto": {"enabled": False}}


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gp-broker-fixture-")
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.patches = [mock.patch.object(p, "STATE", self.state), mock.patch.object(p, "CONFIG", self.root / "config.php"),
                        mock.patch.object(p, "INSTALL", self.root / "bundle"), mock.patch.object(p, "DATA", self.root / "data"),
                        mock.patch.object(p, "save_json", side_effect=self.save_json),
                        mock.patch.object(p, "php_password", return_value="hashed-fixture-password"),
                        mock.patch.object(p, "installer_lock", side_effect=lambda: nullcontext()),
                        mock.patch.object(p, "identity", return_value=(1001, 1001))]
        if not hasattr(os, "O_NOFOLLOW"):
            self.patches.append(mock.patch.object(os, "O_NOFOLLOW", 0, create=True))
        for patch in self.patches: patch.start()
        self.public = {"installed": False, "public_ip": "8.8.8.8", "host": "8.8.8.8", "base_url": "https://8.8.8.8", "job": {"status": "idle", "steps": []}}
        self.private = {}
        self.persist()

    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()
        self.temp.cleanup()

    def save_json(self, path, value, public=False):
        Path(path).write_text(json.dumps(value), encoding="utf-8")

    def persist(self):
        self.save_json(self.state / "public.json", self.public)
        self.save_json(self.state / "private.json", self.private)

    def make(self):
        self.persist()
        return broker.Broker()

    def execute(self, app):
        descriptor = os.open(self.state / "fixture-operation.lock", os.O_CREAT | os.O_RDWR, 0o600)
        app.execute(descriptor)  # execute owns/closes only this fixture descriptor

    def finish_fixture(self):
        self.public["job"] = {"id": "fixture-job", "type": "install", "status": "running", "steps": [{"id": "finish", "status": "running"}]}
        self.private = {"settings": {"admin": {"password_hash": "fixture"}}, "config": {"base_url": "https://local.example"}}
        return self.make()

    def test_settings_matrix_hashes_password_and_omits_disabled_platform_secrets(self):
        for telegram, max_enabled in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(telegram=telegram, max=max_enabled):
                result = broker.settings(valid_settings(telegram, max_enabled))
                self.assertEqual(result["admin"], {"username": "operator", "password_hash": "hashed-fixture-password"})
                self.assertNotIn("long-fixture-password", json.dumps(result))
                self.assertEqual(bool(result["telegram"]["token"]), telegram)
                self.assertEqual(bool(result["max"]["token"]), max_enabled)
                self.assertEqual(result["hcaptcha"], {"enabled": False, "sitekey": "", "secret": ""})
                self.assertEqual(result["mtproto"], {"enabled": False, "api_id": 0, "api_hash": ""})

    def test_settings_reject_unknown_keys_bool_coercion_password_mismatch_and_invalid_mtproto(self):
        values = []
        item = valid_settings(); item["shell"] = "anything"; values.append(item)
        item = valid_settings(); item["telegram"]["enabled"] = "false"; values.append(item)
        item = valid_settings(); item["admin"]["password_confirm"] += "x"; values.append(item)
        item = valid_settings(); item["mtproto"] = {"enabled": True, "api_id": 123, "api_hash": "a" * 32}; values.append(item)
        item = valid_settings(True); item["telegram"]["token"] += "\n"; values.append(item)
        item = valid_settings(); item["timezone"] = "../invalid"; values.append(item)
        item = valid_settings(); item["support_username"] = "https://bad.example"; values.append(item)
        for value in values:
            with self.subTest(fields=sorted(value)):
                with self.assertRaises(p.Failure): broker.settings(value)

    def test_restart_marks_running_job_failed_and_preserves_completed_steps_and_private_config(self):
        self.public["job"] = {"id": "job", "type": "install", "status": "running", "steps": [{"id": "database", "status": "done"}, {"id": "schema", "status": "running"}, {"id": "max", "status": "pending"}]}
        self.private = {"config": {"telegram_bot_enabled": False, "max_bot_enabled": False, "secret": "fixture-private"}}
        app = self.make()
        self.assertEqual(app.public["job"]["status"], "failed")
        self.assertEqual([step["status"] for step in app.public["job"]["steps"]], ["done", "failed", "pending"])
        self.assertEqual(p.read_json(self.state / "public.json")["job"]["error"]["code"], "INTERRUPTED")
        self.assertEqual({key: value for key, value in app.private.items() if key not in ('job', 'public_state')}, self.private)
        self.assertEqual(app.private['job'], app.public['job'])
        self.assertNotIn("fixture-private", json.dumps(app.dispatch("status", {})))

    def test_retry_executes_only_uncommitted_steps_and_redacts_unexpected_failure(self):
        self.public["job"] = {"id": "job", "type": "install", "status": "running", "steps": [{"id": "database", "status": "done"}, {"id": "schema", "status": "failed"}, {"id": "max", "status": "pending"}]}
        app = self.make(); called = []
        def fail_schema(step):
            called.append(step)
            raise RuntimeError("raw fixture-private credentials")
        app.install_step = fail_schema
        self.execute(app)
        self.assertEqual(called, ["schema"])
        self.assertNotIn("fixture-private", json.dumps(p.read_json(self.state / "public.json")))
        app.public["job"]["status"] = "running"
        app.install_step = lambda step: called.append(step) or "skipped"
        with mock.patch.object(p, "run", return_value=b""), mock.patch.object(broker.threading, "Timer"):
            self.execute(app)
        self.assertEqual(called, ["schema", "schema", "max"])
        self.assertEqual(app.public["job"]["status"], "complete")

    def test_failed_finish_does_not_set_installed_and_permanently_block_retry(self):
        app = self.finish_fixture()
        with mock.patch.object(p, "configure_nginx", side_effect=p.Failure("NGINX_FAILED", "Fixed safe failure")):
            self.execute(app)
        self.assertEqual(app.public["job"]["status"], "failed")
        self.assertFalse(app.public.get("installed"), "Failed finish incorrectly committed installed=true")
        self.assertFalse((self.state / "installed.json").exists())

    def test_post_commit_service_cleanup_failure_cannot_relabel_installation_failed(self):
        app = self.finish_fixture()
        with mock.patch.object(p, "configure_nginx"), mock.patch.object(p, "run", side_effect=p.Failure("SYSTEM_COMMAND_FAILED", "Cleanup failed")), mock.patch.object(broker.threading, "Timer"):
            self.execute(app)
        self.assertTrue(app.public["installed"])
        self.assertTrue((self.state / "installed.json").exists())
        self.assertEqual(app.public["job"]["status"], "complete", "A completed installation was relabeled failed by service cleanup")

    def test_restart_reconciles_committed_terminal_marker_before_exiting(self):
        self.finish_fixture()
        self.save_json(self.state / "installed.json", {"installed_at": 123, "version": "fixture", "admin_url": "https://local.example/control/"})
        self.save_json(self.state / "access.json", {"one_time_fixture": "not reusable"})
        with mock.patch.object(os, "geteuid", return_value=0, create=True), mock.patch.object(broker, "Server", side_effect=AssertionError("Completed installation must not reopen the privileged socket")):
            broker.main()
        durable = p.read_json(self.state / "public.json")
        self.assertTrue(durable.get("installed"), "Terminal marker was ignored and UI stayed pending")
        self.assertEqual(durable["job"]["status"], "complete")
        self.assertEqual(durable["job"]["steps"][-1]["status"], "done")
        self.assertEqual(durable["admin_url"], "https://local.example/control/")
        private = p.read_json(self.state / "private.json")
        self.assertFalse(any(name in private for name in ("settings", "config", "enrollment")))
        self.assertFalse((self.state / "access.json").exists())

    def test_helper_preserves_safe_error_envelope_from_nonzero_php_without_stderr_leak(self):
        response = json.dumps({"ok": False, "error": {"code": "TAKEOVER_REQUIRED", "message": "unsafe fixture-private"}}).encode()
        child = types.SimpleNamespace(returncode=1, stdin=None, stdout=None, stderr=None,
                                      communicate=lambda **_: (response, b"raw fixture-private stderr"), poll=lambda:1)
        with mock.patch.object(subprocess, "Popen", return_value=child):
            with self.assertRaises(p.Failure) as error:
                broker.helper({"action": "register", "platform": "max"})
        self.assertEqual(error.exception.code, "TAKEOVER_REQUIRED", "Valid child error code was discarded before JSON parsing")
        self.assertNotIn("fixture-private", str(error.exception))

    def test_invalid_fixed_verb_and_job_id_cannot_reach_system_operations(self):
        app = self.make()
        with mock.patch.object(p, "run") as system, mock.patch.object(broker, "helper") as application:
            for action, value in (("shell", {"command": "anything"}), ("retry", {"job_id": "different"}), ("start", [])):
                with self.assertRaises(p.Failure): app.dispatch(action, value)
            system.assert_not_called(); application.assert_not_called()

    def test_enrollment_is_single_use_expiring_and_never_stores_plaintext_fragment(self):
        code, salt = "a" * 64, "fixture-salt"
        self.private = {"enrollment": {"salt": salt, "hash": hashlib.pbkdf2_hmac("sha256", code.encode(), salt.encode(), 250000).hex(), "expires_at": 4102444800, "consumed": False}}
        app = self.make()
        self.assertEqual(app.dispatch("enroll", {"code": code}), {"enrolled": True})
        self.assertTrue(p.read_json(self.state / "private.json")["enrollment"]["consumed"])
        with self.assertRaises(p.Failure) as error: app.dispatch("enroll", {"code": code})
        self.assertEqual(error.exception.code, "CODE_USED")
        self.assertNotIn(code, (self.state / "private.json").read_text())

    def test_config_is_durably_false_before_schema_and_selected_api_then_activates_only_selected(self):
        for telegram, max_enabled in ((False, False), (True, False), (False, True)):
            with self.subTest(telegram=telegram, max=max_enabled):
                app = self.make()
                app.private["settings"] = broker.settings(valid_settings(telegram, max_enabled))
                writes, calls = [], []
                app.write_config = lambda value: writes.append(json.loads(json.dumps(value)))
                def system(argv, **kwargs):
                    self.assertNotIn("long-fixture-password", json.dumps([str(x) for x in argv]))
                    return b"0" if "-NBe" in argv else b""
                def application(value, **kwargs):
                    calls.append(value)
                    if value["action"] == "check": return {"identity": {"id": "123456" if value["platform"] == "telegram" else "987654", "username": "LocalTelegramBot" if value["platform"] == "telegram" else "LocalMaxBot"}}
                    self.assertTrue(writes)
                    self.assertIs(writes[-1]["telegram_bot_enabled"], False)
                    self.assertIs(writes[-1]["max_bot_enabled"], False)
                    return {}
                with mock.patch.object(p, "run", side_effect=system), mock.patch.object(broker, "helper", side_effect=application):
                    for step in ("database", "config", "schema", "telegram", "max", "verify", "activate"):
                        app.install_step(step)
                self.assertEqual([call["platform"] for call in calls if call["action"] == "register"], [name for name, enabled in (("telegram", telegram), ("max", max_enabled)) if enabled])
                self.assertEqual((writes[-1]["telegram_bot_enabled"], writes[-1]["max_bot_enabled"]), (telegram, max_enabled))
                self.assertEqual(p.read_json(self.state / "private.json")["config"]["admin_auth"]["password_hash"], "hashed-fixture-password")


class HandlerTests(unittest.TestCase):
    def request(self, uid, payload):
        dispatched = []
        handler = object.__new__(broker.Handler)
        handler.server = types.SimpleNamespace(setup_uid=1001, broker=types.SimpleNamespace(dispatch=lambda action, value: dispatched.append((action, value)) or {"installed": False}))
        handler.connection = types.SimpleNamespace(getsockopt=lambda *_: struct.pack("3i", 123, uid, 1001), settimeout=lambda *_: None)
        handler.rfile = io.BytesIO(payload)
        handler.wfile = io.BytesIO()
        handler.handle()
        return handler, dispatched

    def test_peer_uid_is_checked_before_parsing_or_dispatching(self):
        handler, dispatched = self.request(1002, b'{"action":"status","payload":{}}\n')
        self.assertEqual(dispatched, [])
        self.assertEqual(handler.rfile.tell(), 0)
        self.assertEqual(handler.wfile.getvalue(), b"")

    def test_only_bounded_exact_request_envelope_can_dispatch(self):
        for value in (b'{"action":"status","payload":{},"command":"anything"}\n', b"x" * 32769, b'{"action":"status","payload":{}}'):
            _, dispatched = self.request(1001, value)
            self.assertEqual(dispatched, [])
        handler, dispatched = self.request(1001, b'{"action":"status","payload":{}}\n')
        self.assertEqual(dispatched, [("status", {})])
        self.assertEqual(json.loads(handler.wfile.getvalue())["result"], {"installed": False})


if __name__ == "__main__":
    unittest.main(verbosity=2)
