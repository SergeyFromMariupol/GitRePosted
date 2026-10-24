'use strict';

// All browser requests are intercepted. No PHP server, bot API or network is used.
// Set PLAYWRIGHT_MODULE and, if needed, UI_BROWSER_EXECUTABLE for your local runtime.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const web = path.resolve(__dirname, '../web');
const assets = {
    '/install/': ['text/html; charset=utf-8', fs.readFileSync(path.join(web, 'index.php'))],
    '/install/assets/wizard.js': ['text/javascript; charset=utf-8', fs.readFileSync(path.join(web, 'assets/wizard.js'))],
    '/install/assets/wizard.css': ['text/css; charset=utf-8', fs.readFileSync(path.join(web, 'assets/wizard.css'))]
};
let browser;
test.before(async () => { browser = await chromium.launch({ headless: true, ...(process.env.UI_BROWSER_EXECUTABLE ? { executablePath: process.env.UI_BROWSER_EXECUTABLE } : {}) }); });
test.after(async () => { if (browser) await browser.close(); });

async function fixture(options = {}) {
    const prefix = options.prefix || '';
    const context = await browser.newContext({ viewport: options.viewport || { width: 1365, height: 1000 } });
    const page = await context.newPage();
    const calls = [];
    const errors = [];
    const status = {
        authenticated: false, secure: options.http !== true, installed: false,
        base_url: 'https://installer.example' + prefix, host: 'installer.example', public_ip: 'Server IP',
        site_url: 'https://installer.example' + prefix, site_host: 'installer.example', path_prefix: prefix, csrf: 'a'.repeat(64),
        job: { id: '', type: 'install', status: 'idle', steps: [] }, ...options.status
    };
    page.on('pageerror', (error) => errors.push(error.message));
    await context.route('**/*', async (route) => {
        const request = route.request(); const url = new URL(request.url());
        if (url.pathname === prefix + '/install/api.php') {
            const action = url.searchParams.get('action');
            const body = request.method() === 'POST' ? request.postDataJSON() : null;
            calls.push({ action, body, method: request.method(), url: request.url(), csrf: request.headers()['x-csrf-token'], addressHadFragment: Boolean(new URL(page.url()).hash) });
            let result;
            if (options.onApi) result = await options.onApi({ action, body, status, calls, route });
            if (result === 'abort') { await route.abort('connectionreset'); return; }
            if (result && result.fixtureError) { await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ ok: false, error: result.fixtureError }) }); return; }
            if (result === undefined) {
                if (action === 'status') result = { ...status, csrf: status.authenticated ? status.csrf : undefined };
                else if (action === 'login') { status.authenticated = true; result = { authenticated: true, csrf: status.csrf }; }
                else if (action === 'check_bot') result = { identity: { id: '321', username: 'fixture_' + body.platform, name: 'Fixture bot' }, existing_urls: [] };
                else if (action === 'start') { status.job = { id: 'install_fixture', type: 'install', status: 'running', steps: [{ id: 'config', title: 'Настройки приложения', status: 'running' }, { id: 'schema', title: 'База данных', status: 'pending' }] }; result = { job: status.job }; }
                else if (action === 'host') { status.job = { id: 'host_fixture', type: 'host', status: 'running', steps: [{ id: 'dns', title: 'Проверка DNS', status: 'done' }, { id: 'tls', title: 'Сертификат', status: 'running' }] }; result = { job: status.job }; }
                else if (action === 'retry') { status.job.status = 'running'; result = { job: status.job }; }
                else if (action === 'logout') { status.authenticated = false; result = { authenticated: false }; }
                else throw new Error('Unexpected fixture action');
            }
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, result }) });
            return;
        }
        const asset = url.pathname.startsWith(prefix + '/install/') ? assets[url.pathname.slice(prefix.length)] : null;
        if (asset) { await route.fulfill({ status: 200, contentType: asset[0], body: asset[1] }); return; }
        await route.abort('blockedbyclient');
    });
    const fragment = options.fragment !== undefined ? options.fragment : (options.autoLogin === false ? '' : '#setup=' + 'x'.repeat(32));
    await page.goto((options.http ? 'http' : 'https') + '://installer.example' + prefix + '/install/' + fragment);
    return { page, context, calls, status, errors, close: async () => { assert.deepEqual(errors, []); await context.close(); } };
}

async function login(f) {
    await f.page.locator('#wizard-screen').waitFor({ state: 'visible' });
}

async function settleFragment(page) {
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function adminAndBots(f, options = {}) {
    await f.page.locator('#next-step').click();
    if (options.username) await f.page.locator('#admin-username').fill(options.username);
    if (options.timezone) await f.page.locator('#timezone').fill(options.timezone);
    await f.page.locator('#admin-password').fill('fixture-password-only');
    await f.page.locator('#admin-password-confirm').fill('fixture-password-only');
    await f.page.locator('#next-step').click();
    await f.page.locator('#bots-title').waitFor({ state: 'visible' });
}

async function review(f) {
    await f.page.locator('#next-step').click();
    await f.page.locator('#options-title').waitFor({ state: 'visible' });
    await f.page.locator('#next-step').click();
    await f.page.locator('#review-title').waitFor({ state: 'visible' });
}

test('HTTP screen removes fragment and never submits the setup secret', async () => {
    const f = await fixture({ http: true });
    try {
        await f.page.locator('#http-screen').waitFor({ state: 'visible' });
        assert.equal(await f.page.locator('#login-screen').isVisible(), false);
        assert.equal(await f.page.locator('#https-link').getAttribute('href'), 'https://installer.example/install/');
        assert.equal(await f.page.locator('#access-code').count(), 0);
        assert.equal(f.page.url(), 'http://installer.example/install/');
        assert.equal(f.calls.some((call) => call.method === 'POST'), false);
    } finally { await f.close(); }
});

test('setup link logs in automatically after removing fragment from the address', async () => {
    const f = await fixture();
    try {
        await login(f);
        assert.equal(f.page.url(), 'https://installer.example/install/');
        const request = f.calls.find((call) => call.action === 'login');
        assert.deepEqual(request.body, { code: 'x'.repeat(32) });
        assert.equal(request.addressHadFragment, false);
        assert.equal(f.calls.some((call) => call.url.includes('setup=') || call.url.includes('x'.repeat(32))), false);
        assert.equal(await f.page.locator('#login-form').count(), 0);
    } finally { await f.close(); }
});

test('mounted setup enrollment, API and completion keep their project path on a shared host', async () => {
    const prefix = '/GitRePosted';
    const f = await fixture({ prefix });
    try {
        await login(f);
        assert.equal(f.page.url(), 'https://installer.example' + prefix + '/install/');
        assert.deepEqual(f.calls.find(call => call.action === 'login').body, { code: 'x'.repeat(32) });
        assert.equal(f.calls.every(call => new URL(call.url).pathname === prefix + '/install/api.php'), true);
        assert.equal(f.calls.every(call => !call.addressHadFragment), true);
        f.status.installed = true; f.status.authenticated = false;
        f.status.admin_url = 'https://installer.example' + prefix + '/control/';
        await f.page.reload();
        await f.page.locator('#complete-screen').waitFor({ state: 'visible' });
        assert.equal(await f.page.locator('#control-link').getAttribute('href'), f.status.admin_url);
    } finally { await f.close(); }
    const http = await fixture({ prefix, http: true });
    try {
        await http.page.locator('#http-screen').waitFor({ state: 'visible' });
        assert.equal(http.page.url(), 'http://installer.example' + prefix + '/install/');
        assert.equal(await http.page.locator('#https-link').getAttribute('href'), 'https://installer.example' + prefix + '/install/');
        assert.equal(http.calls.some(call => call.method === 'POST'), false);
    } finally { await http.close(); }
});

test('setup link pasted into an open login page enrolls once without reloading the document', async () => {
    const f = await fixture({ autoLogin: false });
    const code = 's'.repeat(40);
    try {
        await f.page.locator('#login-screen').waitFor({ state: 'visible' });
        await f.page.evaluate(() => { window.fixtureDocument = 'same-document'; });
        await f.page.goto('https://installer.example/install/#setup=' + code);
        await login(f);
        assert.equal(await f.page.evaluate(() => window.fixtureDocument), 'same-document');
        assert.equal(f.page.url(), 'https://installer.example/install/');
        assert.deepEqual(f.calls.filter((call) => call.action === 'login').map((call) => call.body), [{ code }]);
        assert.equal(f.calls.find((call) => call.action === 'login').addressHadFragment, false);
        assert.equal(f.calls.some((call) => call.action === 'start'), false);
        assert.equal(f.calls.some((call) => call.url.includes('setup=') || call.url.includes(code)), false);
    } finally { await f.close(); }
});

test('another setup fragment during pending enrollment is removed without a second login', async () => {
    let release;
    const pending = new Promise((resolve) => { release = resolve; });
    const f = await fixture({ autoLogin: false, onApi: async ({ action }) => { if (action === 'login') await pending; } });
    const first = 'p'.repeat(40); const second = 'q'.repeat(40);
    try {
        await f.page.locator('#login-screen').waitFor({ state: 'visible' });
        const enrollment = f.page.waitForRequest((request) => new URL(request.url()).searchParams.get('action') === 'login', { timeout: 4000 });
        await f.page.goto('https://installer.example/install/#setup=' + first);
        await enrollment;
        await f.page.goto('https://installer.example/install/#setup=' + second);
        await settleFragment(f.page);
        assert.equal(f.page.url(), 'https://installer.example/install/');
        assert.deepEqual(f.calls.filter((call) => call.action === 'login').map((call) => call.body), [{ code: first }]);
        assert.equal(f.calls.find((call) => call.action === 'login').addressHadFragment, false);
        assert.equal(f.calls.filter((call) => call.method === 'POST').length, 1);
        release(); await login(f);
        assert.equal(f.calls.filter((call) => call.action === 'login').length, 1);
        assert.equal(f.calls.some((call) => call.url.includes(first) || call.url.includes(second)), false);
    } finally { release(); await f.close(); }
});

test('setup fragment after authentication preserves the current step and entered settings', async () => {
    const f = await fixture();
    try {
        await login(f); await f.page.locator('#next-step').click();
        await f.page.locator('#admin-username').fill('keep_operator');
        await f.page.locator('#admin-password').fill('keep-fixture-password');
        await f.page.locator('#admin-password-confirm').fill('keep-fixture-password');
        const calls = f.calls.length;
        await f.page.goto('https://installer.example/install/#setup=' + 'a'.repeat(40));
        await settleFragment(f.page);
        assert.equal(f.page.url(), 'https://installer.example/install/');
        assert.equal(await f.page.locator('#admin-title').isVisible(), true);
        assert.equal(await f.page.locator('#admin-username').inputValue(), 'keep_operator');
        assert.equal(await f.page.locator('#admin-password').inputValue(), 'keep-fixture-password');
        assert.equal(await f.page.locator('#admin-password-confirm').inputValue(), 'keep-fixture-password');
        assert.deepEqual(f.calls.slice(calls).map((call) => [call.action, call.method]), [['status', 'GET']]);
        assert.equal(f.calls.filter((call) => call.action === 'login').length, 1);
    } finally { await f.close(); }
});

test('fresh setup link recovers an expired idle session after confirming backend status', async () => {
    const f = await fixture();
    const code = 'e'.repeat(40);
    try {
        await login(f);
        f.status.authenticated = false;
        const calls = f.calls.length;
        const enrollment = f.page.waitForRequest((request) => request.method() === 'POST' && new URL(request.url()).searchParams.get('action') === 'login', { timeout: 4000 });
        await f.page.goto('https://installer.example/install/#setup=' + code);
        await enrollment;
        await login(f);
        assert.equal(f.page.url(), 'https://installer.example/install/');
        assert.deepEqual(f.calls.slice(calls).map((call) => [call.action, call.method]), [['status', 'GET'], ['login', 'POST'], ['status', 'GET']]);
        assert.deepEqual(f.calls.filter((call) => call.action === 'login').map((call) => call.body), [{ code: 'x'.repeat(32) }, { code }]);
        assert.equal(f.calls.some((call) => call.action === 'start'), false);
    } finally { await f.close(); }
});

test('setup fragment during a running install leaves its job and polling intact without restarting', async () => {
    const f = await fixture();
    try {
        await login(f); await adminAndBots(f); await review(f);
        await f.page.locator('#next-step').click(); await f.page.locator('#job-screen').waitFor({ state: 'visible' });
        await f.page.waitForFunction(() => document.getElementById('settings-form').getAttribute('aria-busy') === 'false');
        await f.page.goto('https://installer.example/install/#setup=' + 'r'.repeat(40));
        await settleFragment(f.page);
        assert.equal(f.page.url(), 'https://installer.example/install/');
        assert.equal(await f.page.locator('#job-screen').isVisible(), true);
        assert.equal(f.status.job.id, 'install_fixture');
        assert.match(await f.page.locator('#job-steps').innerText(), /Настройки приложения/);
        assert.equal(f.calls.filter((call) => call.action === 'login').length, 1);
        assert.equal(f.calls.filter((call) => call.action === 'start').length, 1);
        const statuses = f.calls.filter((call) => call.action === 'status').length;
        await f.page.locator('#job-refresh').click();
        await f.page.waitForFunction(() => !document.getElementById('job-refresh').disabled);
        assert.ok(f.calls.filter((call) => call.action === 'status').length > statuses);
        assert.equal(await f.page.locator('#job-screen').isVisible(), true);
    } finally { await f.close(); }
});

test('malformed setup fragment in an open login page is removed and never submitted', async () => {
    const f = await fixture({ autoLogin: false });
    try {
        await f.page.locator('#login-screen').waitFor({ state: 'visible' });
        for (const fragment of ['#setup=short&other=value', '#setup']) {
            await f.page.goto('https://installer.example/install/' + fragment);
            await f.page.locator('#login-error').waitFor({ state: 'visible' });
            await settleFragment(f.page);
            assert.match(await f.page.locator('#login-error').innerText(), /Ссылка недействительна/);
            assert.equal(f.page.url(), 'https://installer.example/install/');
        }
        assert.equal(f.calls.some((call) => call.method === 'POST'), false);
    } finally { await f.close(); }
});

test('setup fragment added to an open HTTP page is scrubbed without sending credentials', async () => {
    const f = await fixture({ autoLogin: false, http: true });
    try {
        await f.page.locator('#http-screen').waitFor({ state: 'visible' });
        const statuses = f.calls.filter((call) => call.action === 'status').length;
        await f.page.goto('http://installer.example/install/#setup=' + 'h'.repeat(40));
        await settleFragment(f.page);
        assert.equal(f.page.url(), 'http://installer.example/install/');
        assert.equal(await f.page.locator('#http-screen').isVisible(), true);
        assert.ok(f.calls.filter((call) => call.action === 'status').length > statuses);
        assert.equal(f.calls.some((call) => call.method === 'POST'), false);
    } finally { await f.close(); }
});

test('ordinary main anchor navigation is preserved and does not trigger setup API calls', async () => {
    const f = await fixture({ autoLogin: false });
    try {
        await f.page.locator('#login-screen').waitFor({ state: 'visible' });
        const calls = f.calls.length;
        await f.page.goto('https://installer.example/install/#main');
        await settleFragment(f.page);
        assert.equal(f.page.url(), 'https://installer.example/install/#main');
        assert.equal(await f.page.locator('#login-screen').isVisible(), true);
        assert.equal(f.calls.length, calls);
    } finally { await f.close(); }
});

test('setup fragment on a completed installation is scrubbed without reopening enrollment', async () => {
    const f = await fixture({ autoLogin: false, status: { installed: true } });
    try {
        await f.page.locator('#complete-screen').waitFor({ state: 'visible' });
        const calls = f.calls.length;
        await f.page.goto('https://installer.example/install/#setup=' + 'i'.repeat(40));
        await settleFragment(f.page);
        assert.equal(f.page.url(), 'https://installer.example/install/');
        assert.equal(await f.page.locator('#complete-screen').isVisible(), true);
        assert.equal(f.calls.length, calls);
        assert.equal(f.calls.some((call) => call.method === 'POST'), false);
    } finally { await f.close(); }
});

test('failure to remove a new setup fragment refuses enrollment and gives safe recovery guidance', async () => {
    const f = await fixture({ autoLogin: false });
    try {
        await f.page.locator('#login-screen').waitFor({ state: 'visible' });
        const calls = f.calls.length;
        await f.page.evaluate(() => { history.replaceState = () => { throw new Error('fixture raw history failure'); }; });
        await f.page.goto('https://installer.example/install/#setup=' + 'f'.repeat(40));
        await f.page.locator('#login-error').waitFor({ state: 'visible' });
        assert.match(await f.page.locator('#login-error').innerText(), /Откройте её в новой вкладке/);
        assert.doesNotMatch(await f.page.locator('body').innerText(), /fixture raw history failure/);
        assert.equal(f.calls.length, calls);
        await f.page.locator('#login-refresh').click();
        await f.page.waitForFunction(() => !document.getElementById('job-refresh').disabled);
        assert.equal(f.calls.some((call) => call.method === 'POST'), false);
    } finally { await f.close(); }
});

test('missing or malformed setup link shows SSH resume guidance without a manual code form', async () => {
    for (const fragment of ['', '#setup=short&other=value']) {
        const f = await fixture({ fragment });
        try {
            await f.page.locator('#login-screen').waitFor({ state: 'visible' });
            assert.match(await f.page.locator('#login-title').innerText(), /ссылку из SSH/);
            assert.match(await f.page.locator('.resume-command').innerText(), /bootstrap\.sh --resume/);
            assert.equal(await f.page.locator('#access-code').count(), 0);
            assert.equal(f.calls.some((call) => call.action === 'login'), false);
            assert.equal(f.page.url(), 'https://installer.example/install/');
        } finally { await f.close(); }
    }
});

test('used or expired setup link is not replayed and gives a clear recovery path', async () => {
    const f = await fixture({ onApi: async ({ action }) => action === 'login' ? { fixtureError: { code: 'INVALID_CODE', message: 'Fixture invalid code' } } : undefined });
    try {
        await f.page.locator('#login-error').waitFor({ state: 'visible' });
        assert.match(await f.page.locator('#login-error').innerText(), /Ссылка уже использована или срок/);
        await f.page.locator('#login-refresh').click();
        assert.equal(f.calls.filter((call) => call.action === 'login').length, 1);
        assert.equal(f.page.url(), 'https://installer.example/install/');
    } finally { await f.close(); }
});

test('admin-only install has no platform secrets and completes at the final site URL', async () => {
    const f = await fixture();
    try {
        await login(f); await adminAndBots(f); await review(f);
        assert.match(await f.page.locator('#review-facts').innerText(), /Пропущен/);
        await f.page.locator('#next-step').click(); await f.page.locator('#job-screen').waitFor({ state: 'visible' });
        const start = f.calls.find((call) => call.action === 'start');
        assert.deepEqual(start.body.settings.telegram, { enabled: false });
        assert.deepEqual(start.body.settings.max, { enabled: false });
        assert.equal(Object.hasOwn(start.body.settings, 'mtproto'), false);
        assert.equal(start.csrf, 'a'.repeat(64));
        assert.equal(f.calls.some((call) => /fixture-(?:code|password)/.test(call.url)), false);
        f.status.installed = true; f.status.site_url = 'https://posts.example';
        await f.page.locator('#job-refresh').click(); await f.page.locator('#complete-screen').waitFor({ state: 'visible' });
        assert.equal(await f.page.locator('#control-link').getAttribute('href'), 'https://posts.example/control/');
        assert.equal(await f.page.locator('#admin-password').inputValue(), '');
    } finally { await f.close(); }
});

for (const [name, telegram, max] of [['none', false, false], ['telegram', true, false], ['max', false, true], ['both', true, true]]) {
    test('platform matrix ' + name + ': checks only selected bots, preserves settings and closes after commit', async () => {
        const f = await fixture();
        try {
            await login(f); await adminAndBots(f, { username: 'matrix_operator', timezone: 'UTC' });
            const selected = { telegram, max };
            const tokens = { telegram: '123456:' + 'a'.repeat(32), max: 'fixture-max-matrix-token' };
            for (const platform of ['telegram', 'max']) {
                if (!selected[platform]) {
                    assert.equal(await f.page.locator('#' + platform + '-fields').isVisible(), false);
                    continue;
                }
                await f.page.locator('#' + platform + '-enabled').check();
                await f.page.locator('#' + platform + '-token').fill(tokens[platform]);
                await f.page.locator('[data-check-platform="' + platform + '"]').click();
                await f.page.locator('#' + platform + '-identity').waitFor({ state: 'visible' });
            }
            await review(f); await f.page.locator('#next-step').click();
            await f.page.locator('#job-screen').waitFor({ state: 'visible' });
            const start = f.calls.find(call => call.action === 'start');
            assert.ok(start);
            assert.equal(start.body.settings.admin.username, 'matrix_operator');
            assert.equal(start.body.settings.timezone, 'UTC');
            assert.equal(start.csrf, 'a'.repeat(64));
            assert.equal(Object.hasOwn(start.body.settings, 'mtproto'), false);
            for (const platform of ['telegram', 'max']) {
                const settings = start.body.settings[platform];
                assert.equal(settings.enabled, selected[platform]);
                assert.equal(f.calls.filter(call => call.action === 'check_bot' && call.body.platform === platform).length, selected[platform] ? 1 : 0);
                if (selected[platform]) assert.equal(settings.token, tokens[platform]);
                else assert.deepEqual(settings, { enabled: false });
                assert.equal(await f.page.locator('#' + platform + '-token').inputValue(), '');
            }
            f.status.installed = true; f.status.authenticated = false;
            f.status.admin_url = 'https://installer.example/control/';
            await f.page.locator('#job-refresh').click();
            await f.page.locator('#complete-screen').waitFor({ state: 'visible' });
            assert.equal(await f.page.locator('#control-link').getAttribute('href'), f.status.admin_url);
            assert.equal(await f.page.locator('#wizard-screen').isVisible(), false);
            assert.equal(await f.page.locator('#job-retry').isVisible(), false);
            assert.equal(f.calls.filter(call => call.action === 'start').length, 1);
            assert.equal(await f.page.locator('#admin-password').inputValue(), '');
            assert.equal(f.calls.some(call => call.url.includes('fixture-password') || call.url.includes(tokens.telegram) || call.url.includes(tokens.max)), false);
        } finally { await f.close(); }
    });
}

test('MAX-only flow escapes identity, hides URL query and requires fresh takeover consent', async () => {
    const f = await fixture({ onApi: async ({ action }) => action === 'check_bot' ? { identity: { id: '321', username: '<img src=x onerror=alert(1)>', name: 'Fixture' }, existing_urls: ['https://legacy.example/hook?token=fixture-hidden-value'] } : undefined });
    try {
        await login(f); await adminAndBots(f);
        await f.page.locator('#max-enabled').check(); await f.page.locator('#max-token').fill('fixture-max-only');
        await f.page.locator('[data-check-platform="max"]').click(); await f.page.locator('#max-identity').waitFor({ state: 'visible' });
        assert.equal(await f.page.locator('#max-identity img').count(), 0);
        assert.equal(await f.page.locator('#max-existing-urls').innerText(), 'https://legacy.example/hook [параметры скрыты]');
        await f.page.locator('#next-step').click(); assert.match(await f.page.locator('#settings-error').innerText(), /Подтвердите/);
        await f.page.locator('#max-takeover').check(); await f.page.locator('#next-step').click();
        await f.page.locator('#options-title').waitFor({ state: 'visible' });
        await f.page.locator('#previous-step').click(); await f.page.locator('#max-token').fill('fixture-changed-token');
        assert.equal(await f.page.locator('#max-identity').isVisible(), false);
        assert.equal(await f.page.locator('#max-takeover').isChecked(), false);
        await f.page.locator('#next-step').click(); assert.match(await f.page.locator('#settings-error').innerText(), /проверьте текущий токен/);
        assert.equal(f.calls.some((call) => call.action === 'start'), false);
    } finally { await f.close(); }
});

test('late token-check response cannot verify a replaced token', async () => {
    const f = await fixture({ onApi: async ({ action }) => {
        if (action !== 'check_bot') return;
        await new Promise((resolve) => setTimeout(resolve, 350));
        return { identity: { id: '321', username: 'fixture_bot', name: 'Fixture' }, existing_urls: [] };
    } });
    try {
        await login(f); await adminAndBots(f); await f.page.locator('#telegram-enabled').check();
        await f.page.locator('#telegram-token').fill('fixture-original-token'); await f.page.locator('[data-check-platform="telegram"]').click();
        await f.page.locator('#telegram-token').fill('fixture-new-token');
        await f.page.waitForTimeout(500);
        assert.equal(await f.page.locator('#telegram-identity').isVisible(), false);
        await f.page.locator('#next-step').click(); assert.match(await f.page.locator('#settings-error').innerText(), /проверьте текущий токен/);
    } finally { await f.close(); }
});

test('host job keeps initial authenticated origin and returns to settings after TLS is ready', async () => {
    const f = await fixture();
    try {
        await login(f); await f.page.locator('#domain-details').evaluate((element) => { element.open = true; });
        await f.page.locator('#domain-host').fill('posts.example'); await f.page.locator('#host-submit').click();
        await f.page.locator('#job-screen').waitFor({ state: 'visible' });
        assert.match(await f.page.locator('#job-title').innerText(), /домен/);
        f.status.site_url = 'https://posts.example'; f.status.site_host = 'posts.example'; f.status.job.status = 'complete';
        await f.page.locator('#job-refresh').click(); await f.page.locator('#wizard-screen').waitFor({ state: 'visible' });
        assert.equal(await f.page.locator('#server-base-url').innerText(), 'https://posts.example');
        assert.equal(await f.page.locator('#host-ready').isVisible(), true);
        assert.equal(f.page.url(), 'https://installer.example/install/');
        assert.equal(f.calls.filter((call) => call.action === 'login').length, 1);
        assert.equal(await f.page.locator('#complete-screen').isVisible(), false);
    } finally { await f.close(); }
});

test('lost start response polls existing job and retry uses its ID without a second start', async () => {
    const f = await fixture({ onApi: async ({ action, status }) => {
        if (action !== 'start') return;
        status.job = { id: 'install_existing', type: 'install', status: 'running', steps: [{ id: 'config', title: 'Настройки', status: 'running' }] };
        return 'abort';
    } });
    try {
        await login(f); await adminAndBots(f); await review(f); await f.page.locator('#next-step').click();
        await f.page.locator('#job-screen').waitFor({ state: 'visible' });
        await f.page.locator('#job-refresh').click();
        assert.equal(f.calls.filter((call) => call.action === 'start').length, 1);
        assert.equal(await f.page.locator('#job-retry').isVisible(), false);
        f.status.job.status = 'failed'; f.status.job.error = 'Fixture stage failure'; f.status.job.steps[0].status = 'failed';
        await f.page.locator('#job-refresh').click(); await f.page.locator('#job-retry').waitFor({ state: 'visible' });
        await f.page.locator('#job-retry').click();
        await f.page.waitForFunction(() => document.getElementById('job-retry').hidden);
        assert.equal(f.calls.filter((call) => call.action === 'start').length, 1);
        assert.deepEqual(f.calls.find((call) => call.action === 'retry').body, { job_id: 'install_existing' });
    } finally { await f.close(); }
});

test('responsive pages fit a mobile viewport and optional credentials stay disabled by default', async () => {
    const f = await fixture({ viewport: { width: 390, height: 844 } });
    try {
        await login(f); await adminAndBots(f);
        assert.equal(await f.page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
        await f.page.locator('#next-step').click(); await f.page.locator('#options-title').waitFor({ state: 'visible' });
        assert.equal(await f.page.locator('#hcaptcha-enabled').isChecked(), false);
        assert.equal(await f.page.locator('#mtproto-enabled').count(), 0);
        assert.equal(await f.page.locator('#hcaptcha-fields').isVisible(), false);
        assert.equal(await f.page.locator('#mtproto-fields').count(), 0);
        assert.equal(await f.page.locator('#support-username').count(), 0);
        assert.equal(await f.page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
        if (process.env.UI_SCREENSHOT_DIR) {
            fs.mkdirSync(process.env.UI_SCREENSHOT_DIR, { recursive: true });
            await f.page.screenshot({ path: path.join(process.env.UI_SCREENSHOT_DIR, 'ui-mobile.png'), fullPage: true });
            await f.page.setViewportSize({ width: 1365, height: 1000 });
            await f.page.locator('#previous-step').click();
            await f.page.screenshot({ path: path.join(process.env.UI_SCREENSHOT_DIR, 'ui-desktop.png'), fullPage: true });
        }
    } finally { await f.close(); }
});
