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
  const state = {
    calls: [], menuWrites: [], menuReadOverrides: {}, max: [{ url: foreignUrl, update_types: maxEvents }],
    telegram: { url: foreignUrl, allowed_updates: telegramEvents },
    telegramCommands: { default: [], ru: [] }, telegramMenu: { type: "default" }, maxCommands: [],
    loseMaxPostResponse: false, loseTelegramPostResponse: false, omitMaxConfirmation: false,
    omitTelegramConfirmation: false, loseMenuResponse: "", failMenuReadAfterWrite: "", ignoreMenuWrite: ""
  };
  const menuRead = (key, value) => {
    if (state.failMenuReadAfterWrite === key && state.menuWrites.some((write) => write.key === key)) {
      state.failMenuReadAfterWrite = "";
      throw new Error(foreignUrl);
    }
    return structuredClone(Object.hasOwn(state.menuReadOverrides, key) ? state.menuReadOverrides[key] : value);
  };
  const menuWrite = (key, payload, apply) => {
    state.menuWrites.push({ key, payload: structuredClone(payload) });
    if (state.ignoreMenuWrite !== key) apply();
    if (state.loseMenuResponse === key) {
      state.loseMenuResponse = "";
      throw new Error(foreignUrl);
    }
    return state.ignoreMenuWrite !== key;
  };
  const context = vm.createContext({
    env: { TELEGRAM_ENABLED: "1", MAX_ENABLED: "1", TELEGRAM_WEBHOOK_SECRET: "fixture-secret", MAX_WEBHOOK_SECRET: "fixture-secret" },
    assertPlatformEnabled: (platform) => {
      if (context.env[`${platform.toUpperCase()}_ENABLED`] === "0") {
        const error = new Error("Platform disabled"); error.code = "PLATFORM_DISABLED"; error.statusCode = 503; throw error;
      }
    },
    platformEnabled: (env, platform) => env[`${platform.toUpperCase()}_ENABLED`] !== "0",
    editableConfigState: () => ({ restart_required: false }), requestPublicBaseUrl: () => "https://fixture.example",
    tgApi: async (method, payload) => {
      state.calls.push(`telegram:${method}`);
      const locale = payload.language_code || "default";
      if (method === "getMyCommands") return menuRead(`telegram:commands:${locale}`, state.telegramCommands[locale]);
      if (method === "setMyCommands") return menuWrite(`telegram:commands:${locale}`, payload, () => {
        state.telegramCommands[locale] = structuredClone(payload.commands);
      });
      if (method === "getChatMenuButton") return menuRead("telegram:button", state.telegramMenu);
      if (method === "setChatMenuButton") return menuWrite("telegram:button", payload, () => {
        state.telegramMenu = structuredClone(payload.menu_button);
      });
      if (method === "getWebhookInfo") return state.omitTelegramConfirmation && state.telegram.url === targetTelegram
        ? { url: targetTelegram } : structuredClone(state.telegram);
      assert.equal(method, "setWebhook");
      assert.equal(payload.drop_pending_updates, false);
      state.telegram = { url: payload.url, allowed_updates: [...payload.allowed_updates] };
      if (state.loseTelegramPostResponse) { state.loseTelegramPostResponse = false; throw new Error(foreignUrl); }
      return true;
    },
    maxApi: async (path, options = {}) => {
      const method = options.method || "GET";
      if (path === "/me") {
        assert.equal(method, "GET"); state.calls.push("max:getMe");
        return { commands: menuRead("max:commands", state.maxCommands) };
      }
      if (path === "/me/commands") {
        assert.equal(method, "PATCH"); state.calls.push("max:commands");
        const payload = JSON.parse(options.body);
        menuWrite("max:commands", payload, () => { state.maxCommands = structuredClone(payload.commands); });
        return { commands: structuredClone(state.maxCommands) };
      }
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
    assert.deepEqual(state.menuWrites, []);
  }
});

test("MAX confirms the new endpoint and exact events before deleting an approved foreign webhook", async () => {
  const { state, context } = fixture();
  await context.replaceMaxWebhookSubscription(targetMax, true);
  assert.deepEqual(state.calls, ["max:GET", "max:POST", "max:GET", "max:getMe", "max:commands", "max:getMe", "max:DELETE", "max:GET"]);
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
    assert.deepEqual(state.menuWrites, []);
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
  assert.equal(state.calls.at(-1), "telegram:getChatMenuButton");
});

test("none, Telegram-only, MAX-only and both configure menus only for selected platforms", async () => {
  for (const [telegram, max] of [[false, false], [true, false], [false, true], [true, true]]) {
    const { state, context } = fixture();
    context.env.TELEGRAM_ENABLED = telegram ? "1" : "0";
    context.env.MAX_ENABLED = max ? "1" : "0";
    await context.setWebhooks(true);
    assert.equal(state.calls.some((call) => call.startsWith("telegram:")), telegram);
    assert.equal(state.calls.some((call) => call.startsWith("max:")), max);
    assert.deepEqual(state.menuWrites.map((write) => write.key), [
      ...(telegram ? ["telegram:commands:default", "telegram:commands:ru", "telegram:button"] : []),
      ...(max ? ["max:commands"] : [])
    ]);
    if (telegram) {
      const expected = [{ command: "start", description: "Открыть главное меню" }];
      assert.deepEqual(state.telegramCommands, { default: expected, ru: expected });
      assert.deepEqual(state.telegramMenu, { type: "commands" });
      assert.deepEqual(state.menuWrites[0].payload, { commands: expected });
      assert.deepEqual(state.menuWrites[1].payload, { language_code: "ru", commands: expected });
      assert.deepEqual(state.menuWrites[2].payload, { menu_button: { type: "commands" } });
      assert.ok(state.calls.indexOf("telegram:getWebhookInfo", 1) < state.calls.indexOf("telegram:setMyCommands"));
    }
    if (max) assert.deepEqual(state.maxCommands, [{ name: "start", description: "Открыть главное меню" }]);
    const writes = state.menuWrites.length;
    await context.setWebhooks();
    assert.equal(state.menuWrites.length, writes, "verified menu settings must not be rewritten on retry");
  }
});

test("unconfirmed Telegram or MAX webhook never changes command menus", async () => {
  for (const platform of ["telegram", "max"]) {
    const { state, context } = fixture();
    state[platform === "telegram" ? "omitTelegramConfirmation" : "omitMaxConfirmation"] = true;
    await assert.rejects(platform === "telegram"
      ? context.replaceTelegramWebhookSubscription(targetTelegram, true)
      : context.replaceMaxWebhookSubscription(targetMax, true), (error) => error.statusCode === 502);
    assert.deepEqual(state.menuWrites, []);
  }
});

test("lost command or menu write responses are reconciled without repeating confirmed settings", async () => {
  for (const key of ["telegram:commands:default", "telegram:commands:ru", "telegram:button", "max:commands"]) {
    const { state, context } = fixture();
    state.loseMenuResponse = key;
    const setup = (takeover) => key.startsWith("telegram:")
      ? context.replaceTelegramWebhookSubscription(targetTelegram, takeover)
      : context.replaceMaxWebhookSubscription(targetMax, takeover);
    await setup(true);
    assert.equal(state.menuWrites.filter((write) => write.key === key).length, 1);
    const writes = state.menuWrites.length;
    await setup(false);
    assert.equal(state.menuWrites.length, writes);
  }
});

test("retry after lost command readback checks applied state and preserves old MAX webhook until verified", async () => {
  for (const key of ["telegram:commands:default", "telegram:commands:ru", "telegram:button", "max:commands"]) {
    const { state, context } = fixture();
    state.failMenuReadAfterWrite = key;
    const setup = () => key.startsWith("telegram:")
      ? context.replaceTelegramWebhookSubscription(targetTelegram, true)
      : context.replaceMaxWebhookSubscription(targetMax, true);
    await assert.rejects(setup(), (error) => error.statusCode === 502 && !error.message.includes("foreign-sentinel"));
    if (key.startsWith("max:")) {
      assert.equal(state.calls.includes("max:DELETE"), false);
      assert.ok(state.max.some((row) => row.url === foreignUrl));
    }
    await setup();
    assert.equal(state.menuWrites.filter((write) => write.key === key).length, 1);
  }
});

test("rejected or incorrect command menus cannot report successful setup", async () => {
  for (const key of ["telegram:commands:default", "telegram:commands:ru", "telegram:button", "max:commands"]) {
    const { state, context } = fixture();
    state.ignoreMenuWrite = key;
    await assert.rejects(key.startsWith("telegram:")
      ? context.replaceTelegramWebhookSubscription(targetTelegram, true)
      : context.replaceMaxWebhookSubscription(targetMax, true), (error) => error.statusCode === 502);
    if (key.startsWith("max:")) assert.equal(state.calls.includes("max:DELETE"), false);
  }
});

test("malformed, duplicate or incorrect provider menu readbacks cannot confirm setup", async () => {
  for (const platform of ["telegram", "max"]) {
    const field = platform === "telegram" ? "command" : "name";
    const expected = { [field]: "start", description: "Открыть главное меню" };
    for (const value of [null, {}, [{}], [expected, expected], [{ ...expected, description: "Old service menu" }], [{ ...expected, [field]: "other" }]]) {
      const { state, context } = fixture();
      state.menuReadOverrides[platform === "telegram" ? "telegram:commands:default" : "max:commands"] = value;
      await assert.rejects(platform === "telegram"
        ? context.replaceTelegramWebhookSubscription(targetTelegram, true)
        : context.replaceMaxWebhookSubscription(targetMax, true), (error) => error.statusCode === 502);
      if (platform === "max") assert.equal(state.calls.includes("max:DELETE"), false);
    }
  }
  for (const value of [null, {}, { type: "default" }, { type: "web_app" }]) {
    const { state, context } = fixture();
    state.menuReadOverrides["telegram:button"] = value;
    await assert.rejects(context.replaceTelegramWebhookSubscription(targetTelegram, true), (error) => error.statusCode === 502);
  }
});
