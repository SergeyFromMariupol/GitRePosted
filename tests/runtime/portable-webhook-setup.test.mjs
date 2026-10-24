import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";

const server = fs.readFileSync(new URL("../../payload/src/server.js", import.meta.url), "utf8");
const source = server.slice(server.indexOf("function assertWebhookSettingsApplied()"), server.indexOf("\nasync function handleTelegramMyChatMember("));
const foreignUrl = "https://foreign.example/private-secret-path?token=foreign-sentinel";
const targetMax = "https://fixture.example/webhooks/max";
const targetTelegram = "https://fixture.example/webhooks/telegram";
const maxEvents = ["message_created", "message_callback", "bot_added", "bot_removed", "bot_started"];
const telegramEvents = ["message", "edited_message", "channel_post", "edited_channel_post", "callback_query", "my_chat_member"];

function fixture() {
  const state = { calls: [], max: [{ url: foreignUrl, update_types: maxEvents }], telegram: { url: foreignUrl, allowed_updates: telegramEvents }, loseMaxPostResponse: false, loseTelegramPostResponse: false, omitMaxConfirmation: false };
  const context = vm.createContext({
    env: { TELEGRAM_WEBHOOK_SECRET: "fixture-secret", MAX_WEBHOOK_SECRET: "fixture-secret" },
    assertPlatformEnabled: () => {}, platformEnabled: () => true,
    editableConfigState: () => ({ restart_required: false }), requestPublicBaseUrl: () => "https://fixture.example",
    tgApi: async (method, payload) => {
      state.calls.push(`telegram:${method}`);
      if (method === "getWebhookInfo") return structuredClone(state.telegram);
      assert.equal(method, "setWebhook");
      assert.equal(payload.drop_pending_updates, false);
      state.telegram = { url: payload.url, allowed_updates: [...payload.allowed_updates] };
      if (state.loseTelegramPostResponse) { state.loseTelegramPostResponse = false; throw new Error(foreignUrl); }
      return true;
    },
    maxApi: async (path, options = {}) => {
      const method = options.method || "GET";
      state.calls.push(`max:${method}`);
      if (method === "GET") return { subscriptions: structuredClone(state.max).map((row) => state.omitMaxConfirmation && row.url === targetMax ? { url: row.url } : row) };
      if (method === "POST") {
        const payload = JSON.parse(options.body);
        state.max = [...state.max.filter((row) => row.url !== payload.url), { url: payload.url, update_types: payload.update_types }];
        if (state.loseMaxPostResponse) { state.loseMaxPostResponse = false; throw new Error(foreignUrl); }
        return { success: true };
      }
      assert.equal(method, "DELETE");
      const oldUrl = new URL(path, "https://fixture.invalid").searchParams.get("url");
      assert.equal(oldUrl, foreignUrl);
      state.max = state.max.filter((row) => row.url !== oldUrl);
      return { success: true };
    }
  });
  vm.runInContext(source, context);
  return { state, context };
}

test("declined Telegram and MAX takeover perform reads only and never expose foreign webhook secrets", async () => {
  for (const platform of ["telegram", "max"]) {
    const { state, context } = fixture();
    const work = platform === "telegram" ? context.replaceTelegramWebhookSubscription(targetTelegram) : context.replaceMaxWebhookSubscription(targetMax);
    await assert.rejects(work, (error) => error.statusCode === 409 && error.code === "TAKEOVER_REQUIRED"
      && !error.message.includes("foreign-sentinel") && !error.message.includes("private-secret-path"));
    assert.deepEqual(state.calls, [platform === "telegram" ? "telegram:getWebhookInfo" : "max:GET"]);
  }
});

test("MAX confirms the new endpoint and exact events before deleting an approved foreign webhook", async () => {
  const { state, context } = fixture();
  await context.replaceMaxWebhookSubscription(targetMax, true);
  assert.deepEqual(state.calls, ["max:GET", "max:POST", "max:GET", "max:DELETE", "max:GET"]);
  assert.equal(state.max.length, 1);
  assert.equal(state.max[0].url, targetMax);
  await context.replaceMaxWebhookSubscription(targetMax);
  assert.equal(state.calls.filter((call) => call === "max:DELETE").length, 1);
  assert.equal(state.max.length, 1);
});

test("lost MAX registration response and failed readback preserve the old subscription until a verified retry", async () => {
  for (const failure of ["loseMaxPostResponse", "omitMaxConfirmation"]) {
    const { state, context } = fixture();
    state[failure] = true;
    await assert.rejects(context.replaceMaxWebhookSubscription(targetMax, true), (error) => error.statusCode === 502 && !error.message.includes("foreign-sentinel"));
    assert.equal(state.calls.includes("max:DELETE"), false);
    assert.ok(state.max.some((row) => row.url === foreignUrl));
    state[failure] = false;
    await context.replaceMaxWebhookSubscription(targetMax, true);
    assert.equal(state.max.length, 1);
    assert.equal(state.max[0].url, targetMax);
    assert.equal(state.calls.filter((call) => call === "max:DELETE").length, 1);
  }
});

test("Telegram takeover is explicit and retry after an ambiguous control response remains idempotent", async () => {
  const { state, context } = fixture();
  state.loseTelegramPostResponse = true;
  await assert.rejects(context.replaceTelegramWebhookSubscription(targetTelegram, true), (error) => error.statusCode === 502 && !error.message.includes("foreign-sentinel"));
  assert.equal(state.telegram.url, targetTelegram);
  await context.replaceTelegramWebhookSubscription(targetTelegram);
  assert.deepEqual(state.telegram.allowed_updates.sort(), [...telegramEvents].sort());
  assert.equal(state.calls.filter((call) => call === "telegram:setWebhook").length, 2);
  assert.equal(state.calls.at(-1), "telegram:getWebhookInfo");
});
