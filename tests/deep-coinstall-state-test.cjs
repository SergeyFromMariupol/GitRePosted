'use strict';
// Captured browser regressions. Every request is fulfilled/aborted locally.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const web = process.env.COINSTALL_WEB_ROOT || path.resolve(__dirname, '../web');
let browser;
test.before(async () => {
    browser = await chromium.launch({ headless: true,
        ...(process.env.UI_BROWSER_EXECUTABLE ? { executablePath: process.env.UI_BROWSER_EXECUTABLE } : {}) });
});
test.after(async () => { if (browser) await browser.close(); });

async function fixture(mode) {
    const context = await browser.newContext();
    const page = await context.newPage(), actions = [], errors = [];
    const state = { authenticated: true, secure: true, installed: false, csrf: 'a'.repeat(64),
        base_url: 'https://fixture.example', host: 'fixture.example',
        site_url: 'https://old.example.org', site_host: 'old.example.org', public_ip: '8.8.8.8',
        job: mode === 'initial-same-host' ? { type: 'install', status: 'idle', steps: [] } :
            { id: 'previous-domain-job', type: 'host', status: 'complete', steps: [] } };
    if (mode === 'initial-same-host') {
        state.site_url = state.base_url; state.site_host = state.host;
    }
    page.on('pageerror', error => errors.push(error.message));
    await context.route('**/*', async route => {
        const url = new URL(route.request().url());
        if (url.pathname === '/install/api.php') {
            const action = url.searchParams.get('action'); actions.push(action);
            if (action === 'host') {
                const wanted = route.request().postDataJSON().host;
                if (mode === 'shared-busy') {
                    await route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ ok: false,
                        error: { code: 'SHARED_INSTALL_BUSY', message: 'Another installer is busy. Retry manually.' } }) }); return;
                }
                if (['lost-fast-complete', 'lost-running', 'lost-wrong-host', 'initial-same-host', 'accepted-response'].includes(mode)) {
                    state.job = { id: 'accepted-new-domain-job', type: 'host',
                        status: mode === 'lost-running' ? 'running' : 'complete',
                        steps: [{ id: 'certificate', title: 'New domain certificate', status: mode === 'lost-running' ? 'running' : 'done' }] };
                    if (mode !== 'lost-running') {
                        state.site_host = mode === 'lost-wrong-host' ? 'different.example.org' : wanted;
                        state.site_url = 'https://' + state.site_host;
                    }
                    if (mode === 'accepted-response') {
                        await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, result: { job: state.job } }) }); return;
                    }
                }
                await route.abort('connectionreset'); return;
            }
            assert.equal(action, 'status', 'No automatic mutation is allowed');
            await route.fulfill({ contentType: 'application/json',
                body: JSON.stringify({ ok: true, result: state }) }); return;
        }
        const relative = url.pathname === '/install/' ? 'index.php' : url.pathname.slice('/install/'.length);
        if (!['index.php', 'assets/wizard.js', 'assets/wizard.css'].includes(relative)) {
            await route.abort(); return;
        }
        const filename = relative === 'assets/wizard.js' && process.env.COINSTALL_WIZARD_SCRIPT
            ? process.env.COINSTALL_WIZARD_SCRIPT : path.join(web, relative);
        await route.fulfill({ contentType: relative.endsWith('.js') ? 'text/javascript' :
            relative.endsWith('.css') ? 'text/css' : 'text/html', body: fs.readFileSync(filename) });
    });
    await page.goto('https://fixture.example/install/');
    await page.locator('#wizard-screen').waitFor({ state: 'visible' });
    await page.locator('#domain-details summary').click();
    const wanted = mode === 'repeat-same-host' ? 'old.example.org' :
        mode === 'initial-same-host' ? 'fixture.example' : 'new.example.org';
    await page.locator('#domain-host').fill(wanted);
    await page.locator('#domain-email').fill('operator@new.example.org');
    return { page, actions, state, wanted,
        close: async () => { assert.deepEqual(errors, []); await context.close(); } };
}

for (const mode of ['lost-before-accept', 'repeat-same-host', 'lost-wrong-host']) {
    test(mode + ': a completed unrelated domain job does not confirm the pending hostname', async () => {
        const f = await fixture(mode), { page, actions } = f;
        try {
        await page.locator('#host-submit').click();
        await page.locator('#job-screen').waitFor({ state: 'visible', timeout: 4000 });
        await page.locator('#wizard-screen').waitFor({ state: 'visible', timeout: 4000 });
        assert.equal(actions.filter(action => action === 'host').length, 1);
        assert.equal(await page.locator('#domain-host').inputValue(), f.wanted);
        assert.equal(await page.locator('#domain-email').inputValue(), 'operator@new.example.org');
        assert.equal(await page.locator('#host-error').isVisible(), true,
            'The old completed job must not silently confirm the unaccepted new hostname');
        assert.match(await page.locator('#host-error').textContent(), /не подтвержд|повторите.*вручную|не сообщает/i);
        const polls = actions.filter(action => action === 'status').length;
        await page.waitForTimeout(1200);
        assert.equal(actions.filter(action => action === 'status').length, polls, 'Terminal stale status must stop automatic polling');
        assert.equal(actions.filter(action => action === 'host').length, 1, 'Manual retry must not replay the request');
        } finally { await f.close(); }
    });
}

for (const mode of ['lost-fast-complete', 'initial-same-host', 'accepted-response']) {
    test(mode + ': the accepted new completed domain job is confirmed', async () => {
        const f = await fixture(mode), { page, actions } = f;
        try {
            await page.locator('#host-submit').click();
            if (mode !== 'accepted-response') await page.locator('#job-screen').waitFor({ state: 'visible', timeout: 4000 });
            await page.waitForFunction(wanted => !document.getElementById('wizard-screen').hidden &&
                document.getElementById('host-ready-url').textContent === 'https://' + wanted, f.wanted, { timeout: 4000 });
            assert.equal(await page.locator('#host-error').isVisible(), false);
            assert.equal(actions.filter(action => action === 'host').length, 1);
            assert.equal(await page.locator('#domain-host').inputValue(), f.wanted);
        } finally { await f.close(); }
    });
}

test('an accepted running new job remains visible and reconciles its eventual completion', async () => {
    const f = await fixture('lost-running'), { page, actions, state } = f;
    try {
        await page.locator('#host-submit').click();
        await page.waitForFunction(() => document.getElementById('job-caption').textContent === 'New domain certificate',
            undefined, { timeout: 4000 });
        assert.equal(await page.locator('#job-screen').isVisible(), true);
        assert.equal(await page.locator('#job-retry').isVisible(), false);
        assert.equal(actions.filter(action => action === 'host').length, 1);
        state.job = { ...state.job, status: 'complete', steps: [{ id: 'certificate', title: 'New domain certificate', status: 'done' }] };
        state.site_host = f.wanted; state.site_url = 'https://' + f.wanted;
        await page.locator('#job-refresh').click();
        await page.waitForFunction(wanted => !document.getElementById('wizard-screen').hidden &&
            document.getElementById('host-ready-url').textContent === 'https://' + wanted, f.wanted, { timeout: 4000 });
        assert.equal(await page.locator('#host-error').isVisible(), false);
        assert.equal(actions.filter(action => action === 'host').length, 1);
    } finally { await f.close(); }
});

test('a definitive shared-installer busy response preserves the form and allows manual retry', async () => {
    const f = await fixture('shared-busy'), { page, actions } = f;
    try {
        await page.locator('#host-submit').click();
        await page.locator('#host-error').waitFor({ state: 'visible', timeout: 4000 });
        assert.match(await page.locator('#host-error').textContent(), /Another installer is busy/);
        assert.equal(await page.locator('#wizard-screen').isVisible(), true);
        assert.equal(await page.locator('#domain-host').inputValue(), f.wanted);
        assert.equal(await page.locator('#host-submit').isEnabled(), true);
        assert.equal(actions.filter(action => action === 'host').length, 1);
    } finally { await f.close(); }
});
