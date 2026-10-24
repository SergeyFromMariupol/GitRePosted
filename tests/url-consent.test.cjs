'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {foreignWebhookUrls} = require('../web/assets/wizard.js');
const base = 'https://selfhost.example';
for (const platform of ['telegram','max']) {
    test(platform + ': only the exact configured endpoint bypasses consent', () => {
        const endpoint = platform==='telegram' ? '/webhooks/telegram' : '/webhooks/max';
        assert.deepEqual(foreignWebhookUrls([base+endpoint],platform,base),[]);
        for (const url of ['https://selfhost.example:443'+endpoint,'https://SELFHOST.EXAMPLE'+endpoint,base+'/folder/../'+endpoint.slice(1),base+endpoint+'?']) {
            assert.deepEqual(foreignWebhookUrls([url],platform,base),[url], 'UI consent must agree with the root helper exact URL comparison');
        }
    });
    test(platform + ': redacted foreign endpoint stays distinguishable from own endpoint', () => {
        const safe = base+'/[configured-webhook]';
        assert.deepEqual(foreignWebhookUrls([safe,safe],platform,base),[safe]);
    });
}
