import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";

const server = fs.readFileSync(new URL("../../payload/src/server.js", import.meta.url), "utf8");
const plain = (value) => JSON.parse(JSON.stringify(value));
const TOKEN = "a1".repeat(12);
const RECEIVER_TOKEN = "b2".repeat(12);
const invalid = (message) => Object.assign(new Error(message), { code: "ACCOUNT_TRANSFER_INVALID" });

function extract(name) {
  const start = server.search(new RegExp(`^(?:async )?function ${name}\\(`, "m"));
  assert.ok(start >= 0, `missing ${name}`);
  const rest = server.slice(start);
  const next = rest.slice(1).search(/\n(?:(?:async )?function |const server = )/);
  assert.ok(next >= 0, `missing end of ${name}`);
  return rest.slice(0, next + 1);
}

const names = [
  "accountTransferRows", "accountTransferChoice", "performAccountTransferAction", "accountTransferTextAction",
  "redactedTransferText", "sendTelegramLinkStatus", "maxMainButtons", "handleTelegramCallback",
  "handleMaxEventOnce", "replayTelegramBotAction", "maxCallbackIsAlreadyClosed", "replayMaxBotAction"
];

function fixture() {
  const state = {
    users: { "100": { state: null, state_payload: null, chat_id: "private-100" }, "200": { state: null, state_payload: null, chat_id: "private-200" } },
    results: [], writes: [], responses: [], backend: [], transactions: [],
    persistFailure: false, prepareError: null, confirmError: null, answerError: null, blocked: false
  };
  let activeQuery = null;
  let sequence = 0;
  const query = async (sql, params) => {
    assert.equal(activeQuery, query, "state mutation must use the active transaction connection");
    state.writes.push({ sql, params: plain(params) });
    if (/state = 'account_transfer_input'/.test(sql)) Object.assign(state.users[String(params[0])], { state: "account_transfer_input", state_payload: null });
    return { affectedRows: 1 };
  };
  const backend = (name, connection, args) => {
    assert.equal(connection, activeQuery, `${name} must share the receipt transaction`);
    state.backend.push({ name, args: plain(args) });
  };
  const context = vm.createContext({
    env: { PUBLIC_TELEGRAM_ENABLED: "1", PUBLIC_MAX_ENABLED: "1" },
    crypto: { randomBytes: () => ({ toString: () => sequence++ ? TOKEN : RECEIVER_TOKEN }) },
    withDbTransaction: async (work) => {
      assert.equal(activeQuery, null, "no nested transaction");
      const before = plain({ users: state.users, results: state.results });
      activeQuery = query;
      state.transactions.push("begin");
      try { const result = await work(query); state.transactions.push("commit"); return result; }
      catch (error) { state.users = before.users; state.results = before.results; state.transactions.push("rollback"); throw error; }
      finally { activeQuery = null; }
    },
    persistBotEventResult: async (connection, receipt, result) => {
      assert.equal(connection, activeQuery);
      assert.equal(receipt?.key, "receipt");
      if (state.persistFailure) throw Object.assign(new Error("receipt lease lost"), { code: "BOT_EVENT_LEASE_LOST" });
      state.results.push(plain(result));
    },
    allowAccountTransferReceipt: async (connection, platform, userId, { token }) => {
      backend("allow", connection, { platform, userId, token });
      state.users[String(userId)].state = "account_transfer_receive";
      state.users[String(userId)].state_payload = { token };
      return { token };
    },
    resolveTransferRecipient: async (connection, platform, input) => {
      backend("resolve", connection, { platform, input });
      if (input !== "200" && input !== "@NewOwner") throw invalid("Получатель не найден");
      return { user_id: "200" };
    },
    prepareAccountTransfer: async (connection, platform, userId, targetUserId, options) => {
      backend("prepare", connection, { platform, userId, targetUserId, options });
      if (state.prepareError) throw state.prepareError;
      const recipient = state.users[targetUserId];
      if (recipient.state !== "account_transfer_receive" || recipient.state_payload?.token !== options.receiverToken) throw invalid("Получите код на новом аккаунте");
      Object.assign(state.users[String(userId)], { state: "account_transfer_confirm", state_payload: { token: options.token } });
      return { token: options.token, targetUserId, targetLabel: "Новый <владелец>", channels: 4, routes: 2, bridges: 1, counterpartPlatform: "max", counterpartUserId: "300" };
    },
    confirmAccountTransfer: async (connection, platform, userId, token) => {
      backend("confirm", connection, { platform, userId, token });
      if (state.confirmError) throw state.confirmError;
      if (state.users[String(userId)].state_payload?.token !== token) throw invalid("Подтверждение устарело");
      state.users[String(userId)] = { ...state.users[String(userId)], state: null, state_payload: null };
      state.users["200"] = { ...state.users["200"], state: null, state_payload: null };
      return { targetLabel: "Новый <владелец>", targetUserId: "200", channels: 4, routes: 2, bridges: 1 };
    },
    getTelegramUser: async (userId) => state.users[String(userId)],
    getMaxUser: async (userId) => state.users[String(userId)],
    linkedAccountStatus: async () => ({ max_user_id: "300", telegram_user_id: "100" }),
    accountLinkStatusText: () => "Связанные аккаунты",
    accountAccess: async () => ({ blocked: state.blocked, reason: "Доступ заблокирован" }),
    maxCallbackButton: (text, payload) => ({ type: "callback", text, payload }),
    tgInline: (rows) => ({ inline_keyboard: rows }),
    maxKeyboard: (buttons) => [{ type: "inline_keyboard", payload: { buttons } }],
    tgApi: async (method, payload) => { state.responses.push({ provider: "telegram", method, payload: plain(payload) }); },
    editTelegramMenu: async (...args) => { state.responses.push({ provider: "telegram", method: "edit", args: plain(args) }); },
    answerMaxCallback: async (...args) => {
      state.responses.push({ provider: "max", method: "answer", args: plain(args) });
      if (state.answerError) throw state.answerError;
    },
    sendMaxChat: async (...args) => { state.responses.push({ provider: "max", method: "send", args: plain(args) }); },
    setTelegramState: async (userId, stateValue, payload) => { Object.assign(state.users[String(userId)], { state: stateValue, state_payload: payload }); },
    setMaxState: async (userId, stateValue, payload) => { Object.assign(state.users[String(userId)], { state: stateValue, state_payload: payload }); },
    sendTelegramMenu: async () => {},
    debugLog: () => {}, rememberInboundEvent: async () => {}, answerTelegramCallback: async () => {},
    extractMaxUser: (body) => body.user || {}, extractMaxChat: (body) => body.chat || {},
    extractMaxMessage: (body) => body.message || {}, extractMaxCallback: (body) => body.callback || {},
    maxEventChatId: (body) => body.chat_id || body.message?.chat_id || null,
    relayFailureCode: (error) => error.code || "unknown"
  });
  vm.runInContext(names.map(extract).join("\n"), context);
  const receipt = { key: "receipt" };
  return { state, context, receipt };
}

for (const platform of ["telegram", "max"]) {
  test(`${platform}: receiver and sender flows persist actionable results in the mutation transaction`, async () => {
    const { state, context, receipt } = fixture();
    const receive = await context.performAccountTransferAction(platform, "200", "receive", {}, receipt);
    assert.match(receive.message, new RegExp(`200 ${RECEIVER_TOKEN}`));
    assert.equal(receive.stage, "receive");
    assert.deepEqual(state.results.at(-1), plain(receive));
    await context.performAccountTransferAction(platform, "100", "send", {}, receipt);
    const preview = await context.accountTransferTextAction(platform, "100", `@NewOwner ${RECEIVER_TOKEN.toUpperCase()}`, receipt);
    assert.equal(preview.stage, "confirm");
    assert.match(preview.message, /ID 200/);
    assert.match(preview.message, /Каналов: 4/);
    assert.match(preview.message, /Пересылок: 2/);
    assert.match(preview.message, /МАКС: 300/);
    const complete = await context.performAccountTransferAction(platform, "100", "confirm", { token: preview.token }, receipt);
    assert.equal(complete.stage, "complete");
    assert.match(complete.message, /У старого аккаунта эти данные и права сняты/);
    assert.deepEqual(state.results.map(({ stage }) => stage), ["receive", "input", "confirm", "complete"]);
    assert.equal(state.backend.filter(({ name }) => name === "confirm").length, 1);
    assert.equal(state.transactions.filter((entry) => entry === "commit").length, 4);
  });

  test(`${platform}: an invalid new recipient clears the previous confirmation and persists the error`, async () => {
    const { state, context, receipt } = fixture();
    state.users["100"] = { state: "account_transfer_confirm", state_payload: { token: TOKEN } };
    const result = await context.performAccountTransferAction(platform, "100", "prepare", { input: `999 ${RECEIVER_TOKEN}` }, receipt);
    assert.equal(result.stage, "error");
    assert.equal(state.users["100"].state, "account_transfer_input");
    assert.equal(state.users["100"].state_payload, null);
    assert.equal(state.transactions[1], "rollback");
    assert.deepEqual(state.results.at(-1), plain(result));
    assert.equal(state.backend.some(({ name }) => name === "confirm"), false);
  });

  test(`${platform}: receipt lease failure prevents a response result and rolls back the action`, async () => {
    const { state, context, receipt } = fixture();
    state.persistFailure = true;
    await assert.rejects(context.performAccountTransferAction(platform, "200", "receive", {}, receipt), { code: "BOT_EVENT_LEASE_LOST" });
    assert.equal(state.users["200"].state, null);
    assert.deepEqual(state.results, []);
    assert.deepEqual(state.transactions, ["begin", "rollback"]);
  });

  test(`${platform}: confirmation and its receipt either commit together or both roll back`, async () => {
    const { state, context, receipt } = fixture();
    await context.performAccountTransferAction(platform, "200", "receive", {}, receipt);
    await context.performAccountTransferAction(platform, "100", "send", {}, receipt);
    await context.accountTransferTextAction(platform, "100", `200 ${RECEIVER_TOKEN}`, receipt);
    const before = plain({ users: state.users, results: state.results });
    state.persistFailure = true;
    await assert.rejects(context.performAccountTransferAction(platform, "100", "confirm", { token: TOKEN }, receipt), { code: "BOT_EVENT_LEASE_LOST" });
    assert.deepEqual(state.users, before.users);
    assert.deepEqual(state.results, before.results);
    assert.equal(state.transactions.at(-1), "rollback");
  });

  test(`${platform}: malformed selection and stale confirmation become durable error results`, async () => {
    const { state, context, receipt } = fixture();
    await context.performAccountTransferAction(platform, "100", "send", {}, receipt);
    const malformed = await context.accountTransferTextAction(platform, "100", `200 ${RECEIVER_TOKEN} extra`, receipt);
    assert.equal(malformed.stage, "error");
    assert.deepEqual(state.backend, [], "malformed recipient must not reach account mutations");
    const stale = await context.performAccountTransferAction(platform, "100", "confirm", { token: TOKEN }, receipt);
    assert.equal(stale.stage, "error");
    assert.match(stale.message, /устарело/);
    assert.deepEqual(state.results.at(-1), plain(stale));
    assert.equal(state.users["100"].state, "account_transfer_input");
  });

  test(`${platform}: transfer text mode allows menu commands to escape and rejects unrelated text`, async () => {
    const { state, context, receipt } = fixture();
    assert.equal(await context.accountTransferTextAction(platform, "100", "unrelated", receipt), null);
    const choice = await context.accountTransferTextAction(platform, "100", "/transfer", receipt);
    assert.equal(choice.stage, "choice");
    state.users["100"].state = "account_transfer_confirm";
    for (const command of ["/start", "/menu", "/link", "Меню"]) {
      assert.equal(await context.accountTransferTextAction(platform, "100", command, receipt), null);
    }
    assert.deepEqual(state.backend, []);
  });
}

test("Telegram account screen and MAX menu expose transfer with confirmation and cancellation", async () => {
  const { state, context } = fixture();
  await context.sendTelegramLinkStatus("100", "100");
  const telegramButtons = state.responses[0].payload.reply_markup.inline_keyboard.flat();
  assert.ok(telegramButtons.some((button) => button.callback_data === "tg:transfer"));
  assert.ok(plain(context.maxMainButtons()).flat().some((button) => button.payload === "max:transfer"));
  for (const platform of ["telegram", "max"]) {
    const field = platform === "telegram" ? "callback_data" : "payload";
    const prefix = platform === "telegram" ? "tg" : "max";
    const choice = plain(context.accountTransferRows(platform, context.accountTransferChoice())).flat();
    assert.deepEqual(choice.map((button) => button[field]), [`${prefix}:transfer:send`, `${prefix}:transfer:receive`, `${prefix}:menu`]);
    const confirmation = plain(context.accountTransferRows(platform, { stage: "confirm", token: TOKEN })).flat();
    assert.deepEqual(confirmation.map((button) => button[field]), [`${prefix}:transfer:confirm:${TOKEN}`, `${prefix}:menu`]);
    assert.ok(Buffer.byteLength(confirmation[0][field]) <= 64);
  }
});

test("Telegram transfer callbacks require the actor's own private chat and render plain text", async () => {
  const { state, context, receipt } = fixture();
  const callback = { id: "cb", from: { id: "100" }, data: "tg:transfer:send", message: { message_id: 1, chat: { id: "100", type: "group" } } };
  await context.handleTelegramCallback(callback, receipt);
  callback.message.chat = { id: "200", type: "private" };
  await context.handleTelegramCallback(callback, receipt);
  assert.deepEqual(state.backend, []);
  assert.deepEqual(state.writes, []);
  callback.message.chat = { id: "100", type: "private" };
  await context.handleTelegramCallback(callback, receipt);
  assert.equal(state.users["100"].state, "account_transfer_input");
  assert.equal(state.responses.at(-1).method, "edit");
  assert.equal(state.responses.at(-1).args[4], null, "account names must not be parsed as HTML");
});

test("MAX transfer callbacks require the saved private chat", async () => {
  const { state, context, receipt } = fixture();
  const body = { update_type: "message_callback", chat_id: "group-chat", callback: { id: "cb", user_id: "100", payload: "max:transfer:send" } };
  await context.handleMaxEventOnce(body, receipt);
  assert.deepEqual(state.writes, []);
  body.chat_id = "private-100";
  await context.handleMaxEventOnce(body, receipt);
  assert.equal(state.users["100"].state, "account_transfer_input");
  assert.equal(state.responses.at(-1).method, "answer");
});

test("both bot transfer callbacks honor blocked and disabled public access", async () => {
  for (const restriction of ["blocked", "disabled"]) {
    const { state, context, receipt } = fixture();
    if (restriction === "blocked") state.blocked = true;
    else {
      context.env.PUBLIC_TELEGRAM_ENABLED = "0";
      context.env.PUBLIC_MAX_ENABLED = "0";
    }
    await context.handleTelegramCallback({ id: "cb", from: { id: "100" }, data: "tg:transfer:receive", message: { message_id: 1, chat: { id: "100", type: "private" } } }, receipt);
    await context.handleMaxEventOnce({ update_type: "message_callback", chat_id: "private-100", callback: { id: "cb", user_id: "100", payload: "max:transfer:receive" } }, receipt);
    assert.deepEqual(state.backend, []);
    assert.deepEqual(state.writes, []);
    assert.deepEqual(state.results, []);
  }
});

test("Telegram replay edits a callback and resends a message only after a guaranteed rate limit", async () => {
  const { state, context } = fixture();
  const result = { action: "account_transfer", stage: "complete", message: "Перенос завершён" };
  const update = { message: { chat: { id: "100" }, from: { id: "100" } } };
  for (const lastError of [null, "TELEGRAM_TIMEOUT", "TELEGRAM_AMBIGUOUS_RESPONSE"]) {
    assert.equal(await context.replayTelegramBotAction(update, { result, lastError }), true);
  }
  assert.deepEqual(state.responses, []);
  await context.replayTelegramBotAction(update, { result, lastError: "TELEGRAM_RATE_LIMIT" });
  assert.equal(state.responses.length, 1);
  assert.equal(state.responses[0].method, "sendMessage");
  await context.replayTelegramBotAction({ callback_query: { message: { chat: { id: "100" }, message_id: 6 } } }, { result });
  assert.equal(state.responses.at(-1).method, "edit");
  assert.equal(state.responses.at(-1).args[4], null);
  assert.deepEqual(state.backend, []);
  assert.deepEqual(state.writes, []);
});

test("MAX replay avoids duplicate sends and tolerates only callbacks that are already closed", async () => {
  const { state, context } = fixture();
  const result = { action: "account_transfer", stage: "complete", message: "Перенос завершён" };
  const body = { chat_id: "private-100" };
  for (const lastError of [null, "MAX_TIMEOUT", "MAX_AMBIGUOUS_RESPONSE"]) await context.replayMaxBotAction(body, { result, lastError });
  assert.deepEqual(state.responses, []);
  await context.replayMaxBotAction(body, { result, lastError: "MAX_RATE_LIMIT" });
  assert.equal(state.responses.length, 1);
  assert.equal(state.responses[0].method, "send");
  state.answerError = Object.assign(new Error("callback already answered"), { httpStatus: 400 });
  await context.replayMaxBotAction({ callback: { id: "cb" } }, { result });
  state.answerError = Object.assign(new Error("private provider failure"), { httpStatus: 500 });
  await assert.rejects(context.replayMaxBotAction({ callback: { id: "cb" } }, { result }), /private provider failure/);
  assert.deepEqual(state.backend, []);
  assert.deepEqual(state.writes, []);
});

test("transfer codes are redacted from bot text and callback diagnostics", () => {
  const { context } = fixture();
  assert.equal(context.redactedTransferText(`200 ${RECEIVER_TOKEN}`), "200 [transfer-code]");
  assert.equal(context.redactedTransferText(`tg:transfer:confirm:${TOKEN}`), "tg:transfer:confirm:[transfer-code]");
});
