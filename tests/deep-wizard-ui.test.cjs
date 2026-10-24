'use strict';
// HTTP/browser fixture only. All requests are captured; no external APIs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const web = path.resolve(__dirname, '../web');
let browser;
test.before(async () => { browser = await chromium.launch({ headless: true, ...(process.env.UI_BROWSER_EXECUTABLE ? { executablePath: process.env.UI_BROWSER_EXECUTABLE } : {}) }); });
test.after(async () => { if (browser) await browser.close(); });

async function fixture(mode) {
    const context = await browser.newContext();
    const page = await context.newPage(), calls = [], errors = [];
    const state = { authenticated: true, secure: true, installed: false, csrf: 'a'.repeat(64),
        base_url: 'https://fixture.example', host: 'fixture.example', site_url: 'https://fixture.example',
        site_host: 'fixture.example', public_ip: '8.8.8.8', job: { status: 'idle', type: 'install', steps: [] } };
    page.on('pageerror', e => errors.push(e.message));
    await context.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url());
        if (url.pathname === '/install/api.php') {
            const action = url.searchParams.get('action');calls.push(action);
            if (action === 'start') {
                if (mode === 'absent' && calls.filter(x => x === 'start').length === 1) { await route.abort('connectionreset');return; }
                state.job = { id: 'original-job', type: 'install', status: 'running', steps: [{ id: 'schema', title: 'Schema', status: 'running' }] };
                if (mode !== 'absent') {
                    await route.fulfill({ status: mode === 'busy' ? 409 : 503, contentType: 'application/json',
                        body: JSON.stringify({ ok: false, error: { code: mode === 'busy' ? 'BUSY' : 'UNAVAILABLE', message: 'Captured reply failure' } }) });return;
                }
                await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, result: { job: state.job } }) });return;
            }
            assert.equal(action, 'status');
            await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, result: state }) });return;
        }
        const relative = url.pathname === '/install/' ? 'index.php' : url.pathname.slice('/install/'.length);
        if (!['index.php', 'assets/wizard.js', 'assets/wizard.css'].includes(relative)) { await route.abort();return; }
        const filename = relative === 'assets/wizard.js' && process.env.DEEP_WIZARD_SCRIPT ? process.env.DEEP_WIZARD_SCRIPT : path.join(web, relative);
        await route.fulfill({ contentType: relative.endsWith('.js') ? 'text/javascript' : relative.endsWith('.css') ? 'text/css' : 'text/html', body: fs.readFileSync(filename) });
    });
    await page.goto('https://fixture.example/install/');
    await page.locator('#wizard-screen').waitFor({ state: 'visible' });
    await page.locator('#next-step').click();
    await page.locator('#admin-username').fill('operator');
    await page.locator('#admin-password').fill('fixture-new-password');
    await page.locator('#admin-password-confirm').fill('fixture-new-password');
    await page.locator('#next-step').click();await page.locator('#next-step').click();await page.locator('#next-step').click();
    return { page, calls, state, close: async () => { assert.deepEqual(errors, []);await context.close(); } };
}

for (const mode of ['server-error', 'busy']) test(mode + ' after accepted start reconciles the existing job instead of trapping the form', async () => {
    const f = await fixture(mode);
    try {
        await f.page.locator('#next-step').click();
        await f.page.locator('#job-screen').waitFor({ state: 'visible', timeout: 4000 });
        await f.page.waitForFunction(() => document.getElementById('job-caption').textContent === 'Schema', { timeout: 4000 });
        assert.equal(f.calls.filter(x => x === 'start').length, 1);
        assert.equal(await f.page.locator('#wizard-screen').isVisible(), false);
    } finally { await f.close(); }
});

test('lost request before acceptance restores explicit manual retry without automatically starting twice', async () => {
    const f = await fixture('absent');
    try {
        await f.page.locator('#next-step').click();
        await f.page.locator('#settings-error').waitFor({ state: 'visible', timeout: 4000 });
        assert.match(await f.page.locator('#settings-error').innerText(), /повторите запуск вручную/);
        assert.equal(f.calls.filter(x => x === 'start').length, 1);
        assert.equal(await f.page.locator('#admin-password').inputValue(), 'fixture-new-password');
        await f.page.locator('#next-step').click();
        await f.page.waitForFunction(() => document.getElementById('job-caption').textContent === 'Schema', { timeout: 4000 });
        assert.equal(f.calls.filter(x => x === 'start').length, 2);
        assert.equal(await f.page.locator('#admin-password').inputValue(), '');
    } finally { await f.close(); }
});
