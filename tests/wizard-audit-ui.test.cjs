'use strict';
// Isolated HTTP fixtures: browser requests never reach a server or platform API.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const web = path.resolve(__dirname, '../web');
let browser;
test.before(async () => { browser = await chromium.launch({ headless: true, ...(process.env.UI_BROWSER_EXECUTABLE ? { executablePath: process.env.UI_BROWSER_EXECUTABLE } : {}) }); });
test.after(async () => { if (browser) await browser.close(); });

async function fixture(job, onStatus) {
    const context = await browser.newContext();
    const page = await context.newPage();
    const calls = [], errors = [];
    const status = { authenticated: true, secure: true, installed: false, csrf: 'a'.repeat(64),
        base_url: 'https://setup.example', host: 'setup.example', site_url: 'https://setup.example',
        site_host: 'setup.example', public_ip: '8.8.8.8', job };
    page.on('pageerror', error => errors.push(error.message));
    await context.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url());
        if (url.pathname === '/install/api.php') {
            const action = url.searchParams.get('action'), body = request.method() === 'POST' ? request.postDataJSON() : null;
            calls.push({ action, body });
            let result;
            if (action === 'status') { if (onStatus) onStatus(status, calls.filter(x => x.action === 'status').length); result = status; }
            else if (action === 'check_bot') result = { identity: { id: '321', username: 'fixture_bot' }, existing_urls: [] };
            else if (action === 'revise' || action === 'start' || action === 'host') {
                status.job = { id: action === 'revise' ? body.job_id : 'new-job', type: action === 'host' ? 'host' : 'install', status: 'running', steps: [] };
                result = { job: status.job };
            } else throw new Error('Unexpected action ' + action);
            await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, result }) }); return;
        }
        const file = url.pathname === '/install/' ? 'index.php' : url.pathname.startsWith('/install/assets/') ? url.pathname.slice('/install/'.length) : null;
        if (!file || !['index.php', 'assets/wizard.js', 'assets/wizard.css'].includes(file)) { await route.abort(); return; }
        await route.fulfill({ contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html', body: fs.readFileSync(path.join(web, file)) });
    });
    await page.goto('https://setup.example/install/');
    return { page, calls, status, close: async () => { assert.deepEqual(errors, []); await context.close(); } };
}

test('install completion keeps polling until committed installed metadata is visible', async () => {
    const f = await fixture({ id: 'completed', type: 'install', status: 'complete', steps: [] }, (status, count) => {
        if (count > 1) { status.installed = true; status.authenticated = false; status.admin_url = 'https://setup.example/control/'; }
    });
    try {
        await f.page.locator('#complete-screen').waitFor({ state: 'visible', timeout: 8000 });
        assert.ok(f.calls.filter(call => call.action === 'status').length >= 2);
        assert.equal(await f.page.locator('#wizard-screen').isVisible(), false);
    } finally { await f.close(); }
});

test('failed domain can be edited or bypassed while preserving the failed job', async () => {
    const f = await fixture({ id: 'host-failed', type: 'host', status: 'failed', steps: [], error: 'DNS mismatch' });
    try {
        await f.page.locator('#job-edit').click();
        await f.page.locator('#wizard-screen').waitFor({ state: 'visible' });
        await f.page.locator('#next-step').click();
        await f.page.locator('#admin-title').waitFor({ state: 'visible' });
        assert.equal(f.calls.some(call => call.action !== 'status'), false);
        await f.page.locator('#previous-step').click();
        await f.page.locator('#domain-details summary').click();
        await f.page.locator('#domain-host').fill('correct.example');
        await f.page.locator('#host-submit').click();
        await f.page.locator('#job-screen').waitFor({ state: 'visible' });
        assert.equal(f.calls.find(call => call.action === 'host').body.host, 'correct.example');
    } finally { await f.close(); }
});

test('repair re-enters secrets, checks new token and resumes the same install job', async () => {
    const f = await fixture({ id: 'original-job', type: 'install', status: 'failed', can_revise: true, steps: [], error: 'Revoked token' });
    try {
        await f.page.locator('#job-edit').click();
        await f.page.locator('#admin-title').waitFor({ state: 'visible' });
        assert.equal(await f.page.locator('#admin-password').inputValue(), '');
        assert.equal(await f.page.locator('#telegram-token').inputValue(), '');
        assert.equal(await f.page.locator('#domain-details').isVisible(), false);
        await f.page.locator('#admin-password').fill('fixture-new-password');
        await f.page.locator('#admin-password-confirm').fill('fixture-new-password');
        await f.page.locator('#next-step').click();
        await f.page.locator('#telegram-enabled').check();
        await f.page.locator('#telegram-token').fill('123456:' + 'a'.repeat(32));
        await f.page.locator('[data-check-platform="telegram"]').click();
        await f.page.locator('#telegram-identity').waitFor({ state: 'visible' });
        await f.page.locator('#next-step').click();
        await f.page.locator('#next-step').click();
        await f.page.locator('#next-step').click();
        await f.page.locator('#job-screen').waitFor({ state: 'visible' });
        const revised = f.calls.find(call => call.action === 'revise');
        assert.equal(revised.body.job_id, 'original-job');
        assert.equal(revised.body.settings.telegram.enabled, true);
        assert.equal(f.calls.some(call => call.action === 'start'), false);
        assert.equal(await f.page.locator('#admin-password').inputValue(), '');
    } finally { await f.close(); }
});

test('failed activated installation offers retry without settings replacement', async () => {
    const f = await fixture({ id: 'activated-job', type: 'install', status: 'failed', can_revise: false, steps: [], error: 'Finish failed' });
    try {
        await f.page.locator('#job-screen').waitFor({ state: 'visible' });
        assert.equal(await f.page.locator('#job-edit').isVisible(), false);
        assert.equal(await f.page.locator('#job-retry').isVisible(), true);
    } finally { await f.close(); }
});
