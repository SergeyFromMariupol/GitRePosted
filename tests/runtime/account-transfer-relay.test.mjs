import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";

const server = fs.readFileSync(new URL("../../payload/src/server.js", import.meta.url), "utf8");
const plain = (value) => JSON.parse(JSON.stringify(value));

function extract(name) {
  const start = server.search(new RegExp(`^(?:async )?function ${name}\\(`, "m"));
  assert.ok(start >= 0, `missing ${name}`);
  const rest = server.slice(start);
  const next = rest.slice(1).search(/\n(?:(?:async )?function |const server = )/);
  assert.ok(next >= 0, `missing end of ${name}`);
  return rest.slice(0, next + 1);
}

for (const sourcePlatform of ["telegram", "max"]) {
  test(`${sourcePlatform}: queued relay continues after ownership transfer using unchanged route and target IDs`, async () => {
    const targetPlatform = sourcePlatform === "telegram" ? "max" : "telegram";
    const sourceChatId = sourcePlatform === "telegram" ? "-1001001" : "-2001";
    const targetChatId = targetPlatform === "telegram" ? "-1002002" : "-3002";
    const state = {
      route: { id: "stable-route", account_id: 1, source_platform: sourcePlatform, source_chat_id: sourceChatId, enabled: 1 },
      target: { id: 17, route_id: "stable-route", platform: targetPlatform, chat_id: targetChatId },
      accounts: new Map([[1, { is_blocked: 0, telegram_blocked: 0, max_blocked: 0 }], [2, { is_blocked: 0, telegram_blocked: 0, max_blocked: 0 }]]),
      channels: [
        { account_id: 1, platform: sourcePlatform, chat_id: sourceChatId, is_blocked: 0 },
        { account_id: 1, platform: targetPlatform, chat_id: targetChatId, is_blocked: 0 }
      ],
      providerCalls: [], botCanPublish: true
    };
    const db = async (sql, params) => {
      const normalized = sql.replace(/\s+/g, " ").trim();
      if (/^UPDATE (?:telegram|max)_channels/.test(normalized)) return { affectedRows: 1 };
      assert.match(normalized, /JOIN linked_accounts a ON a\.id = r\.account_id/);
      assert.match(normalized, /JOIN account_channels src ON src\.account_id = r\.account_id/);
      assert.match(normalized, /JOIN account_channels dst ON dst\.account_id = r\.account_id/);
      const account = state.accounts.get(state.route.account_id);
      const allowed = state.route.enabled && account && !account.is_blocked && !account[`${sourcePlatform}_blocked`]
        && state.channels.every((channel) => channel.account_id === state.route.account_id && !channel.is_blocked);
      if (!allowed) return [];
      if (/^SELECT r\.id AS route_id/.test(normalized)) {
        assert.equal(params[0], sourcePlatform);
        assert.ok(params.includes(sourceChatId));
        return [{ route_id: state.route.id, account_id: state.route.account_id, source_chat_id: sourceChatId,
          target_id: state.target.id, platform: targetPlatform, chat_id: targetChatId }];
      }
      assert.equal(params[0], targetPlatform);
      assert.ok(params.includes(state.route.id));
      const expectedTargetId = params.at(-1);
      if (expectedTargetId !== null && expectedTargetId !== state.target.id) return [];
      return [{ source_chat_id: sourceChatId, target_chat_id: targetChatId }];
    };
    const context = vm.createContext({
      db, normalizeTelegramChatId: String, legacyTelegramChatId: String,
      channelPublishingAccessCache: new Map(), CHANNEL_ACCESS_CACHE_MS: 30000,
      getTelegramBotIdentity: async () => ({ id: "publishing-bot" }),
      tgApi: async (method, payload) => {
        assert.equal(method, "getChatMember");
        assert.equal(payload.user_id, "publishing-bot", "relay must check the bot, not the new human owner's channel membership");
        state.providerCalls.push({ platform: "telegram", payload: plain(payload) });
        return { status: "administrator", can_post_messages: state.botCanPublish };
      },
      maxApi: async (url) => {
        assert.match(url, /^\/chats\/-\d+\/members\/me$/);
        state.providerCalls.push({ platform: "max", url });
        return { is_admin: true, permissions: state.botCanPublish ? ["write"] : [] };
      }
    });
    vm.runInContext(["channelHasPublishingAccess", "relayRoutesSnapshot", "relayTargetIsActive"].map(extract).join("\n"), context);
    const queuedSnapshot = plain(await context.relayRoutesSnapshot(sourcePlatform, sourceChatId));
    assert.deepEqual(queuedSnapshot, [{ route_id: "stable-route", target_id: 17, platform: targetPlatform, chat_id: targetChatId }]);

    // Account transfer changes only the owner foreign keys. The captured queue
    // still holds the same route/target IDs and no human-admin metadata exists.
    state.route.account_id = 2;
    for (const channel of state.channels) channel.account_id = 2;
    assert.deepEqual(plain(await context.relayRoutesSnapshot(sourcePlatform, sourceChatId)), queuedSnapshot);
    const queued = queuedSnapshot[0];
    assert.deepEqual(plain(await context.relayTargetIsActive(queued.route_id, sourcePlatform, sourceChatId, queued.platform, queued.chat_id, queued.target_id)), {
      sourceChatId, targetChatId
    });
    assert.deepEqual(new Set(state.providerCalls.map((call) => call.platform)), new Set(["telegram", "max"]));

    state.accounts.get(2).is_blocked = 1;
    assert.equal(await context.relayTargetIsActive(queued.route_id, sourcePlatform, sourceChatId, queued.platform, queued.chat_id, queued.target_id), null);
    state.accounts.get(2).is_blocked = 0;
    state.target.id = 18;
    assert.equal(await context.relayTargetIsActive(queued.route_id, sourcePlatform, sourceChatId, queued.platform, queued.chat_id, queued.target_id), null, "a replaced destination cannot reuse a queued target ID");
    state.target.id = 17;
    state.botCanPublish = false;
    context.channelPublishingAccessCache.clear();
    assert.equal(await context.relayTargetIsActive(queued.route_id, sourcePlatform, sourceChatId, queued.platform, queued.chat_id, queued.target_id), null, "transfer cannot bypass a bot's lost publishing permission");
  });
}
