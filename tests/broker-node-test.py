"""Runtime/installer boundary contracts with captured system and API transports."""
import json
import unittest
from unittest import mock
import broker_test as base

broker, p = base.broker, base.p


class NodeBrokerTests(unittest.TestCase):
    setUp = base.BrokerTests.setUp
    tearDown = base.BrokerTests.tearDown
    save_json = base.BrokerTests.save_json
    persist = base.BrokerTests.persist
    make = base.BrokerTests.make

    def system(self, argv, **kwargs):
        self.assertNotIn('long-fixture-password', json.dumps([str(x) for x in argv]))
        return b'0' if '-NBe' in argv else b''

    def selected_app(self, telegram, max_enabled):
        app = self.make()
        app.private['settings'] = broker.settings(base.valid_settings(telegram, max_enabled))
        with mock.patch.object(p, 'run', side_effect=self.system):
            app.install_step('database')
        app.private['config']['bot_username'] = 'fixture_bot' if telegram else ''
        app.private['config']['max_bot_username'] = 'fixture_max' if max_enabled else ''
        return app

    def capture_config(self, app):
        with mock.patch.object(p, 'atomic') as output:
            app.write_config(app.private['config'])
        path, content, mode, uid, gid = output.call_args.args
        self.assertEqual((path, mode, uid, gid), (p.CONFIG, 0o600, 1001, 1001))
        flat = json.loads(content)
        self.assertTrue(all(isinstance(k, str) and isinstance(v, str) for k, v in flat.items()))
        self.assertNotIn('long-fixture-password', content.decode())
        return flat

    def test_four_platform_modes_accept_webhooks_before_workers_are_enabled(self):
        for telegram, max_enabled in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(telegram=telegram, max=max_enabled):
                app = self.selected_app(telegram, max_enabled)
                flat = self.capture_config(app)
                self.assertEqual((flat['TELEGRAM_ENABLED'], flat['MAX_ENABLED']), (str(int(telegram)), str(int(max_enabled))))
                self.assertEqual(flat['GITREPOSTED_WORKERS_ENABLED'], '0')
                self.assertEqual((flat['PUBLIC_TELEGRAM_ENABLED'], flat['PUBLIC_MAX_ENABLED']), ('0', '0'))
                self.assertEqual(flat['TELEGRAM_BOT_URL'], 'https://t.me/fixture_bot' if telegram else '')
                self.assertEqual(flat['MAX_BOT_URL'], 'https://max.ru/fixture_max' if max_enabled else '')
                self.assertEqual(flat['HCAPTCHA_ENABLED'], '0')
                self.assertNotEqual(flat['ADMIN_API_KEY'], flat['ADMIN_PASSWORD_HASH'])
                self.assertEqual(len(flat['ADMIN_API_KEY']), 64)
                self.assertEqual(len(flat['TELEGRAM_WEBHOOK_SECRET']), 64)
                self.assertEqual(len(flat['MAX_WEBHOOK_SECRET']), 64)

    def test_initialize_is_followed_by_bridge_start_and_activate_restarts_after_config_commit(self):
        app = self.selected_app(True, False)
        events = []
        original = app.write_config
        app.write_config = lambda config: events.append(('write', config['workers_enabled']))
        def system(argv, **kwargs):
            events.append(('system', tuple(str(x) for x in argv)))
            return b''
        with mock.patch.object(p, 'run', side_effect=system), mock.patch.object(broker, 'helper', side_effect=lambda request, **kwargs: events.append(('schema', request['action'])) or {}):
            app.install_step('schema')
            self.assertEqual(events[0], ('schema', 'initialize'))
            self.assertEqual(events[1], ('system', ('systemctl', 'enable', '--now', 'gitreposted-bridge.service')))
            events.clear()
            app.install_step('activate')
        self.assertEqual(events[0], ('write', True))
        self.assertEqual(events[1], ('system', ('systemctl', 'restart', 'gitreposted-bridge.service')))
        app.write_config = original
        flat = self.capture_config(app)
        self.assertEqual((flat['PUBLIC_TELEGRAM_ENABLED'], flat['PUBLIC_MAX_ENABLED'], flat['GITREPOSTED_WORKERS_ENABLED']), ('1', '0', '1'))

    def test_unsupported_session_setup_cannot_be_enabled_by_forged_settings(self):
        settings = base.valid_settings(True, False)
        settings['mtproto'] = {'enabled': True, 'api_id': 123, 'api_hash': 'a' * 32}
        with self.assertRaises(p.Failure):
            broker.settings(settings)

    def test_separate_admin_secret_is_stable_when_schema_or_webhook_steps_retry(self):
        app = self.selected_app(True, True)
        before = app.private['config'].copy()
        with mock.patch.object(p, 'run', side_effect=self.system):
            app.install_step('database')
        for name in ('admin_api_key', 'webhook_secret', 'max_webhook_secret', 'database'):
            self.assertEqual(app.private['config'][name], before[name])


if __name__ == '__main__':
    unittest.main(verbosity=2)
