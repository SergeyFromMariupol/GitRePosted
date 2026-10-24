'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ui = require('../web/assets/wizard.js');

function values(overrides = {}) {
    return {
        adminUsername: 'admin', adminPassword: 'fixture-password-only', adminPasswordConfirm: 'fixture-password-only',
        telegramEnabled: false, telegramToken: 'unused-telegram-secret', telegramTakeover: true,
        maxEnabled: false, maxToken: 'unused-max-secret', maxTakeover: true,
        timezone: 'Europe/Moscow', supportUsername: '',
        hcaptchaEnabled: false, hcaptchaSitekey: 'unused-sitekey', hcaptchaSecret: 'unused-captcha-secret',
        mtprotoEnabled: false, mtprotoApiId: '12345', mtprotoApiHash: 'unused-api-secret', ...overrides
    };
}

function checks(platform, token, foreignUrls = []) {
    return { [platform]: { token, identity: { id: '123', username: 'fixture_bot' }, foreignUrls } };
}

test('admin-only installation omits every disabled platform and optional secret', () => {
    const settings = ui.buildSettings(values());
    assert.deepEqual(settings.telegram, { enabled: false });
    assert.deepEqual(settings.max, { enabled: false });
    assert.deepEqual(settings.hcaptcha, { enabled: false });
    assert.equal(Object.hasOwn(settings, 'mtproto'), false);
    assert.equal(JSON.stringify(settings).includes('unused-'), false);
    assert.deepEqual(ui.validateSettings(settings, {}), []);
});

test('MAX can be configured independently without Telegram', () => {
    const settings = ui.buildSettings(values({ maxEnabled: true, maxToken: 'max-fixture-token', maxTakeover: false }));
    assert.deepEqual(ui.validateSettings(settings, checks('max', 'max-fixture-token')), []);
    assert.deepEqual(settings.telegram, { enabled: false });
});

test('Telegram can be configured independently without MAX', () => {
    const settings = ui.buildSettings(values({ telegramEnabled: true, telegramToken: 'telegram-fixture-token', telegramTakeover: false }));
    assert.deepEqual(ui.validateSettings(settings, checks('telegram', 'telegram-fixture-token')), []);
    assert.deepEqual(settings.max, { enabled: false });
});

test('enabled bot requires a successful check of the current token', () => {
    const settings = ui.buildSettings(values({ maxEnabled: true, maxToken: 'new-fixture-token' }));
    assert.equal(ui.validateSettings(settings, {}).some((error) => error.field === 'max-token'), true);
    assert.equal(ui.validateSettings(settings, checks('max', 'older-fixture-token')).some((error) => error.field === 'max-token'), true);
});

test('foreign webhook requires separate explicit takeover permission', () => {
    const settings = ui.buildSettings(values({ maxEnabled: true, maxToken: 'fixture-token', maxTakeover: false }));
    const checked = checks('max', 'fixture-token', ['https://legacy.example/hook']);
    assert.equal(ui.validateSettings(settings, checked).some((error) => error.field === 'max-takeover'), true);
    settings.max.takeover = true;
    assert.deepEqual(ui.validateSettings(settings, checked), []);
});

test('only exact own webhook is excluded from takeover detection', () => {
    const own = 'https://posts.example/webhooks/telegram';
    assert.deepEqual(ui.foreignWebhookUrls([own, own], 'telegram', 'https://posts.example'), []);
    assert.deepEqual(ui.foreignWebhookUrls([own + '?changed=1', 'https://other.example/webhooks/telegram'], 'telegram', 'https://posts.example'), [own + '?changed=1', 'https://other.example/webhooks/telegram']);
});

test('webhook display hides userinfo, query and fragments', () => {
    assert.equal(ui.visibleWebhookUrl('https://user:fixture@legacy.example/hook?token=fixture#fragment'), 'https://legacy.example/hook [параметры скрыты]');
    assert.equal(ui.visibleWebhookUrl('javascript:alert(1)'), 'Адрес другого подключения');
});

test('navigation accepts only HTTPS destinations without credentials or query', () => {
    assert.equal(ui.safeHttpsUrl('https://posts.example', 'control/'), 'https://posts.example/control/');
    assert.equal(ui.safeHttpsUrl('https://posts.example/GitRePosted', 'control/'), 'https://posts.example/GitRePosted/control/');
    assert.equal(ui.safeHttpsUrl('https://posts.example/GitRePosted', 'install/'), 'https://posts.example/GitRePosted/install/');
    assert.deepEqual(ui.foreignWebhookUrls(['https://posts.example/GitRePosted/webhooks/telegram'], 'telegram', 'https://posts.example/GitRePosted'), []);
    for (const value of ['http://posts.example', 'javascript:alert(1)', '//posts.example', 'https://user:fixture@posts.example', 'https://posts.example?code=fixture', 'https://posts.example/#code']) assert.equal(ui.safeHttpsUrl(value, 'install/'), null);
});

test('setup fragment accepts only one bounded base64url token', () => {
    assert.equal(ui.setupCodeFromFragment('#setup=' + 'a'.repeat(32)), 'a'.repeat(32));
    assert.equal(ui.setupCodeFromFragment('#setup=' + 'a'.repeat(160)), 'a'.repeat(160));
    for (const value of ['', '#setup=short', '#setup=' + 'a'.repeat(161), '#setup=' + 'a'.repeat(32) + '&x=1', '#setup=' + 'a'.repeat(31) + '%61', '?setup=' + 'a'.repeat(32)]) assert.equal(ui.setupCodeFromFragment(value), null);
});

test('password validation matches character minimum and UTF-8 byte maximum', () => {
    const valid = 'ж'.repeat(36);
    assert.deepEqual(ui.validateSettings(ui.buildSettings(values({ adminPassword: valid, adminPasswordConfirm: valid })), {}), []);
    const tooLong = 'ж'.repeat(37);
    assert.equal(ui.validateSettings(ui.buildSettings(values({ adminPassword: tooLong, adminPasswordConfirm: tooLong })), {}).some((error) => error.field === 'admin-password'), true);
    const tooShort = 'я'.repeat(11);
    assert.equal(ui.validateSettings(ui.buildSettings(values({ adminPassword: tooShort, adminPasswordConfirm: tooShort })), {}).some((error) => error.field === 'admin-password'), true);
});

test('invalid username, timezone and password confirmation have field-specific errors', () => {
    const errors = ui.validateSettings(ui.buildSettings(values({ adminUsername: '<admin>', timezone: 'Not/AZone', adminPasswordConfirm: 'different-fixture' })), {});
    for (const field of ['admin-username', 'timezone', 'admin-password-confirm']) assert.equal(errors.some((error) => error.field === field), true);
});

test('MTProto options are not exposed or collected by the installer', () => {
    const config = ui.buildSettings(values({ mtprotoEnabled: true, mtprotoApiId: '12345', mtprotoApiHash: 'a'.repeat(32) }));
    assert.equal(Object.hasOwn(config, 'mtproto'), false);
});


test('hCaptcha requires complete correctly shaped credentials only when enabled', () => {
    const settings = ui.buildSettings(values({ hcaptchaEnabled: true }));
    assert.equal(ui.validateSettings(settings, {}).length, 2);
    settings.hcaptcha = { enabled: true, sitekey: '00000000-0000-0000-0000-000000000000', secret: 'ES_' + 'x'.repeat(20) };
    assert.deepEqual(ui.validateSettings(settings, {}), []);
});

test('job normalization preserves host/install types and bounds enum-driven CSS classes', () => {
    assert.deepEqual(ui.normalizedJob(null), { id: '', type: 'install', status: 'idle', canRevise: false, steps: [], error: '' });
    const host = ui.normalizedJob({ id: 'host_1', type: 'host', status: 'complete', steps: [{ id: 'tls', title: 'HTTPS', status: 'done' }, { status: 'bad" onclick="x' }], error: { message: 'fixture error' } });
    assert.equal(host.type, 'host'); assert.equal(host.status, 'complete'); assert.equal(host.steps[1].status, 'pending'); assert.equal(host.error, 'fixture error');
});

test('UI assets are self-contained and do not use browser persistence, URL secrets or HTML interpolation', () => {
    const js = fs.readFileSync(path.join(__dirname, '../web/assets/wizard.js'), 'utf8');
    const html = fs.readFileSync(path.join(__dirname, '../web/index.php'), 'utf8');
    const css = fs.readFileSync(path.join(__dirname, '../web/assets/wizard.css'), 'utf8');
    assert.doesNotMatch(js, /(?:localStorage|sessionStorage|indexedDB|\.innerHTML|console\.)/);
    assert.doesNotMatch(html, /(?:src|href)="https?:\/\//);
    assert.doesNotMatch(css, /@import|url\(\s*https?:\/\//);
    assert.doesNotMatch(html, /id="(?:login-form|access-code)"/);
    assert.doesNotMatch(html, /id="(?:mtproto-enabled|mtproto-api-id|mtproto-api-hash|support-username)"/);
    for (const id of ['admin-password', 'admin-password-confirm', 'telegram-token', 'max-token', 'hcaptcha-secret']) assert.match(html, new RegExp('id="' + id + '" type="password"'));
});
