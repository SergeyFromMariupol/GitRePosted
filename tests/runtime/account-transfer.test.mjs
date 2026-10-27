import assert from "node:assert/strict";
import test from "node:test";
import {
  allowAccountTransferReceipt,
  resolveTransferRecipient,
  prepareAccountTransfer,
  confirmAccountTransfer
} from "../../payload/src/src/account-transfer.js";

const NOW = Date.UTC(2026, 9, 28, 10);
const TOKEN = "a1".repeat(12);
const RECEIVER_TOKEN = "c3".repeat(12);
const copy = (value) => structuredClone(value);

function fixture(platform = "telegram") {
  const id = platform === "telegram" ? "telegram_user_id" : "max_user_id";
  const other = platform === "telegram" ? "max_user_id" : "telegram_user_id";
  const sourceUserId = platform === "telegram" ? "100" : "300";
  const targetUserId = platform === "telegram" ? "200" : "400";
  const counterpartUserId = platform === "telegram" ? "300" : "100";
  const users = (userId, username, extra = {}) => ({
    [id]: userId, username, first_name: username,
    chat_id: platform === "max" ? `chat-${userId}` : undefined,
    is_admin: 0, permissions: [], state: null, state_payload: null, ...extra
  });
  const state = {
    linked_accounts: [
      { id: 1, [id]: sourceUserId, [other]: counterpartUserId, is_blocked: 0, telegram_blocked: 0, max_blocked: 0 },
      { id: 2, [id]: targetUserId, [other]: null, is_blocked: 0, telegram_blocked: 0, max_blocked: 0 }
    ],
    [`${platform}_users`]: [
      users(sourceUserId, "OldOwner", { is_admin: 1, permissions: '["channels","routes"]' }),
      users(targetUserId, "NewOwner", {
        permissions: '["routes","logs"]',
        state: "account_transfer_receive",
        state_payload: JSON.stringify({ token: RECEIVER_TOKEN, expiresAt: NOW + 600000 })
      })
    ],
    [`${platform === "telegram" ? "max" : "telegram"}_users`]: [
      { [other]: counterpartUserId, chat_id: "counterpart-chat", username: "Counterpart", is_admin: 0, permissions: [], state: "route_targets", state_payload: '{"targets":["max:old"]}' }
    ],
    account_channels: [
      { account_id: 1, platform: "telegram", chat_id: "-1001", is_blocked: 0, created_at: "before" },
      { account_id: 1, platform: "max", chat_id: "-2001", is_blocked: 1, block_reason: "channel moderation", created_at: "before" },
      { account_id: 2, platform: "max", chat_id: "-2002", is_blocked: 0, created_at: "target-before" }
    ],
    repost_routes: [
      { id: "route-old", account_id: 1, source_platform: "telegram", source_chat_id: "-1001", enabled: 1 },
      { id: "route-target", account_id: 2, source_platform: "max", source_chat_id: "-2002", enabled: 0 }
    ],
    repost_route_targets: [
      { id: 10, route_id: "route-old", platform: "max", chat_id: "-2001" },
      { id: 20, route_id: "route-target", platform: "telegram", chat_id: "-3002" }
    ],
    bridges: [{ id: "legacy-old", account_id: 1, enabled: 0, direction: "both", telegram_chat_id: "-1001", max_chat_id: "-2001" }],
    account_link_codes: [{ code: "111111", account_id: 1 }, { code: "222222", account_id: 2 }, { code: "333333", account_id: 3 }],
    relay_source_events: [{ id: 55, state: "failed", routing_json: [{ routeId: "route-old", targetId: 10 }] }],
    relay_outbound_operations: [{ id: "pending-operation", state: "uncertain", attempt_count: 2 }],
    relay_outbound_messages: [{ operation_id: "pending-operation", message_id: "stable-id" }]
  };
  const calls = [];
  let failOn = null;

  // A stateful SQL seam: mutations affect records and rollback restores the
  // entire model. Unexpected statements fail instead of silently succeeding.
  const query = async (statement, params = []) => {
    const sql = statement.replace(/\s+/g, " ").trim();
    calls.push({ sql, params: copy(params) });
    if (failOn?.(sql)) throw new Error("injected database failure");
    if (/^(?:UPDATE|DELETE|INSERT).*\b(?:relay_|repost_route_targets)/i.test(sql)) {
      assert.fail(`transfer changed durable delivery records: ${sql}`);
    }
    if (/^SELECT/i.test(sql)) {
      if (/\bCOUNT\(\*\)/i.test(sql)) {
        const ownerId = params[0];
        return [{
          channels: state.account_channels.filter((row) => String(row.account_id) === String(ownerId)).length,
          routes: state.repost_routes.filter((row) => String(row.account_id) === String(ownerId)).length,
          bridges: state.bridges.filter((row) => String(row.account_id) === String(ownerId)).length
        }];
      }
      if (/FROM repost_routes (?:\w+) JOIN repost_routes/i.test(sql)) {
        const sources = state.repost_routes.filter((row) => String(row.account_id) === String(params[0]));
        const targets = state.repost_routes.filter((row) => String(row.account_id) === String(params[1]));
        return copy(sources.filter((source) => targets.some((target) => target.source_platform === source.source_platform && target.source_chat_id === source.source_chat_id)));
      }
      const table = sql.match(/\bFROM (\w+)/i)?.[1];
      assert.ok(state[table], `unknown SELECT table: ${sql}`);
      let rows = state[table];
      if (/LOWER\((?:\w+\.)?username\)/i.test(sql)) {
        rows = rows.filter((row) => String(row.username || "").toLowerCase() === String(params[0]).toLowerCase());
      } else {
        const condition = sql.match(/\bWHERE (?:\w+\.)?(\w+) (IN \([^)]*\)|= \?)/i);
        if (condition) {
          const [, column, expression] = condition;
          const values = expression.startsWith("IN") ? params : [params[0]];
          rows = rows.filter((row) => values.some((value) => String(value) === String(row[column])));
        }
      }
      if (/ORDER BY (?:\w+\.)?id\b/i.test(sql)) rows = [...rows].sort((a, b) => Number(a.id) - Number(b.id));
      if (/LIMIT 1\b/i.test(sql)) rows = rows.slice(0, 1);
      if (/LIMIT 2\b/i.test(sql)) rows = rows.slice(0, 2);
      const alias = sql.match(/SELECT (\w+) AS user_id/i)?.[1];
      if (alias) rows = rows.map((row) => ({ ...row, user_id: row[alias] }));
      return copy(rows);
    }
    if (/^UPDATE/i.test(sql)) {
      const [, table, assignments, where] = sql.match(/^UPDATE (\w+) SET (.+?) WHERE (.+)$/i) || [];
      assert.ok(state[table], `unknown UPDATE: ${sql}`);
      let parameter = 0;
      const changes = {};
      for (const assignment of assignments.split(/,\s*(?=\w+\s*=)/)) {
        const [, column, expression] = assignment.match(/^(\w+)\s*=\s*(.+)$/) || [];
        assert.ok(column, `unknown assignment: ${assignment}`);
        if (expression === "?") changes[column] = copy(params[parameter++]);
        else if (/^NULL$/i.test(expression)) changes[column] = null;
        else if (/^JSON_ARRAY\(\)$/i.test(expression)) changes[column] = "[]";
        else if (/^[01]$/.test(expression)) changes[column] = Number(expression);
        else if (/^'[^']*'$/.test(expression)) changes[column] = expression.slice(1, -1);
        else if (!/(?:NOW|CURRENT_TIMESTAMP|UTC_TIMESTAMP)/i.test(expression)) assert.fail(`unknown assignment expression: ${expression}`);
      }
      const condition = where.match(/^(\w+) (IN \([^)]*\)|= \?)/i);
      assert.ok(condition, `unknown UPDATE condition: ${sql}`);
      const [, column, expression] = condition;
      const values = expression.startsWith("IN") ? params.slice(parameter) : [params[parameter]];
      let affectedRows = 0;
      for (const row of state[table]) {
        if (!values.some((value) => String(value) === String(row[column]))) continue;
        Object.assign(row, copy(changes));
        affectedRows += 1;
      }
      return { affectedRows };
    }
    if (/^DELETE FROM account_link_codes/i.test(sql)) {
      const before = state.account_link_codes.length;
      state.account_link_codes = state.account_link_codes.filter((row) => !params.some((value) => String(row.account_id) === String(value)));
      return { affectedRows: before - state.account_link_codes.length };
    }
    assert.fail(`unexpected SQL: ${sql}`);
  };
  const transaction = async (work) => {
    const before = copy(state);
    try { return await work(query); }
    catch (error) {
      for (const key of Object.keys(state)) state[key] = before[key];
      throw error;
    }
  };
  const prepare = () => transaction((connection) => prepareAccountTransfer(connection, platform, sourceUserId, targetUserId, { token: TOKEN, receiverToken: RECEIVER_TOKEN, now: NOW }));
  const confirm = (token = TOKEN, now = NOW + 1000, actor = sourceUserId) => transaction((connection) => confirmAccountTransfer(connection, platform, actor, token, { now }));
  return { platform, id, other, sourceUserId, targetUserId, counterpartUserId, state, calls, query, transaction, prepare, confirm, failWhen: (predicate) => { failOn = predicate; } };
}

function invalid(promise) {
  return assert.rejects(promise, (error) => error.code === "ACCOUNT_TRANSFER_INVALID");
}

for (const platform of ["telegram", "max"]) {
  test(`${platform}: transfer moves all owned records, merges receiver data and revokes the old account`, async () => {
    const f = fixture(platform);
    const before = copy(f.state);
    const proposal = await f.prepare();
    assert.equal(proposal.targetUserId, f.targetUserId);
    assert.equal(proposal.channels, 2);
    assert.equal(proposal.routes, 1);
    assert.equal(proposal.bridges, 1);
    assert.equal(proposal.counterpartUserId, f.counterpartUserId);
    assert.deepEqual(f.state.account_channels, before.account_channels, "preview must not move ownership");

    const result = await f.confirm();
    assert.equal(result.status, "transferred");
    assert.equal(result.channels, 2);
    assert.equal(f.state.account_channels.filter((row) => row.account_id === 1).length, 0);
    assert.equal(f.state.repost_routes.filter((row) => row.account_id === 1).length, 0);
    assert.equal(f.state.bridges.filter((row) => row.account_id === 1).length, 0);
    for (const table of ["account_channels", "repost_routes", "bridges"]) {
      assert.deepEqual(f.state[table], before[table].map((row) => row.account_id === 1 ? { ...row, account_id: 2 } : row));
    }
    for (const table of ["repost_route_targets", "relay_source_events", "relay_outbound_operations", "relay_outbound_messages"]) {
      assert.deepEqual(f.state[table], before[table], `${table} must preserve stable IDs and delivery state`);
    }
    assert.equal(f.state.linked_accounts[0][f.id], f.sourceUserId, "the old identity gets an empty account");
    assert.equal(f.state.linked_accounts[0][f.other], null);
    assert.equal(f.state.linked_accounts[1][f.other], f.counterpartUserId);
    const [source, recipient] = f.state[`${platform}_users`];
    assert.equal(source.is_admin, 0);
    assert.deepEqual(JSON.parse(source.permissions), []);
    assert.equal(recipient.is_admin, 1);
    assert.deepEqual(new Set(JSON.parse(recipient.permissions)), new Set(["channels", "routes", "logs"]));
    assert.equal(source.state, null);
    assert.equal(recipient.state, null);
    assert.equal(f.state[`${platform === "telegram" ? "max" : "telegram"}_users`][0].state, null);
    assert.deepEqual(f.state.account_link_codes, [{ code: "333333", account_id: 3 }]);
    assert.ok(f.calls.some(({ sql }) => /FROM linked_accounts/.test(sql) && /ORDER BY id FOR UPDATE/.test(sql)), "ownership accounts must lock in stable order");
  });

  test(`${platform}: a consumed confirmation cannot transfer new data later`, async () => {
    const f = fixture(platform);
    await f.prepare();
    await f.confirm();
    f.state.account_channels.push({ account_id: 1, platform, chat_id: "new-old-channel", is_blocked: 0 });
    const before = copy(f.state);
    await invalid(f.confirm());
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: wrong actor, nonce and expired proposal cannot move any data`, async () => {
    const f = fixture(platform);
    await f.prepare();
    const before = copy(f.state);
    await invalid(f.confirm("b2".repeat(12)));
    await invalid(f.confirm(TOKEN, NOW + 1000, f.targetUserId));
    await invalid(f.confirm(TOKEN, NOW + 10 * 60 * 1000));
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: different occupied counterparts cause no data loss`, async () => {
    const f = fixture(platform);
    f.state.linked_accounts[1][f.other] = "other-owner";
    const before = copy(f.state);
    await invalid(f.prepare());
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: changing a counterpart after preview invalidates confirmation`, async () => {
    const f = fixture(platform);
    await f.prepare();
    f.state.linked_accounts[0][f.other] = "replacement";
    const before = copy(f.state);
    await invalid(f.confirm());
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: deleting or replacing the recipient account invalidates confirmation`, async () => {
    const f = fixture(platform);
    await f.prepare();
    f.state.linked_accounts[1].id = 99;
    const before = copy(f.state);
    await invalid(f.confirm());
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: a database failure rolls back identities, rights and ownership together`, async () => {
    const f = fixture(platform);
    await f.prepare();
    const before = copy(f.state);
    f.failWhen((sql) => /^UPDATE bridges SET account_id/.test(sql));
    await assert.rejects(f.confirm(), /injected database failure/);
    assert.deepEqual(f.state, before);
    f.failWhen(null);
    await f.confirm();
    assert.equal(f.state.repost_routes[0].account_id, 2);
  });

  test(`${platform}: the recipient's own counterpart survives when the source has none`, async () => {
    const f = fixture(platform);
    f.state.linked_accounts[0][f.other] = null;
    f.state.linked_accounts[1][f.other] = "recipient-counterpart";
    await f.prepare();
    await f.confirm();
    assert.equal(f.state.linked_accounts[0][f.other], null);
    assert.equal(f.state.linked_accounts[1][f.other], "recipient-counterpart");
  });

  test(`${platform}: a route-source conflict refuses the complete operation`, async () => {
    const f = fixture(platform);
    f.state.repost_routes[1].source_platform = f.state.repost_routes[0].source_platform;
    f.state.repost_routes[1].source_chat_id = f.state.repost_routes[0].source_chat_id;
    await f.prepare();
    const before = copy(f.state);
    await invalid(f.confirm());
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: newly added source records are included at confirmation`, async () => {
    const f = fixture(platform);
    const preview = await f.prepare();
    f.state.account_channels.push({ account_id: 1, platform, chat_id: "late-added-channel", is_blocked: 0 });
    const result = await f.confirm();
    assert.equal(preview.channels, 2);
    assert.equal(result.channels, 3);
    assert.equal(f.state.account_channels.at(-1).account_id, 2);
  });

  test(`${platform}: losing the bot receipt lease rolls the transfer back`, async () => {
    const f = fixture(platform);
    await f.prepare();
    const before = copy(f.state);
    await assert.rejects(f.transaction(async (query) => {
      await confirmAccountTransfer(query, platform, f.sourceUserId, TOKEN, { now: NOW + 1000 });
      throw Object.assign(new Error("receipt fencing rejected commit"), { code: "BOT_EVENT_LEASE_LOST" });
    }), { code: "BOT_EVENT_LEASE_LOST" });
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: an operator block applied after preview is rechecked`, async () => {
    const f = fixture(platform);
    await f.prepare();
    f.state.linked_accounts[1].is_blocked = 1;
    const before = copy(f.state);
    await invalid(f.confirm());
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: a recipient must authorize receiving before preview`, async () => {
    const f = fixture(platform);
    f.state[`${platform}_users`][1].state = null;
    f.state[`${platform}_users`][1].state_payload = null;
    const before = copy(f.state);
    await invalid(f.prepare());
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: receiving authorization cannot be guessed or omitted`, async () => {
    const f = fixture(platform);
    const before = copy(f.state);
    for (const receiverToken of [undefined, "f0".repeat(12)]) {
      await invalid(f.transaction((query) => prepareAccountTransfer(query, platform, f.sourceUserId, f.targetUserId, {
        token: TOKEN, receiverToken, now: NOW
      })));
    }
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: recipient cancellation or replacement invalidates a prepared transfer`, async () => {
    const f = fixture(platform);
    await f.prepare();
    f.state[`${platform}_users`][1].state_payload = JSON.stringify({ token: "d4".repeat(12), expiresAt: NOW + 600000 });
    const before = copy(f.state);
    await invalid(f.confirm());
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: expired receiving authorization cannot create a proposal`, async () => {
    const f = fixture(platform);
    f.state[`${platform}_users`][1].state_payload = JSON.stringify({ token: RECEIVER_TOKEN, expiresAt: NOW });
    const before = copy(f.state);
    await invalid(f.prepare());
    assert.deepEqual(f.state, before);
  });

  test(`${platform}: recipient authorization is durable, short lived and replaced by a new code`, async () => {
    const f = fixture(platform);
    const replacement = "e5".repeat(12);
    const consent = await f.transaction((query) => allowAccountTransferReceipt(query, platform, f.targetUserId, {
      token: replacement, now: NOW + 100
    }));
    assert.deepEqual(consent, { token: replacement, expiresAt: NOW + 600100 });
    const recipient = f.state[`${platform}_users`][1];
    assert.equal(recipient.state, "account_transfer_receive");
    assert.deepEqual(JSON.parse(recipient.state_payload), consent);
    await invalid(f.prepare());
    const proposal = await f.transaction((query) => prepareAccountTransfer(query, platform, f.sourceUserId, f.targetUserId, {
      token: TOKEN, receiverToken: replacement, now: NOW + 200
    }));
    assert.equal(proposal.receiverToken, replacement);
    await f.confirm();
    assert.equal(f.state[`${platform}_users`][1].state, null, "successful transfer consumes authorization");
  });

  test(`${platform}: receiving cannot be authorized by a blocked identity`, async () => {
    const f = fixture(platform);
    f.state.linked_accounts[1][platform === "telegram" ? "max_blocked" : "telegram_blocked"] = 1;
    const before = copy(f.state);
    await invalid(f.transaction((query) => allowAccountTransferReceipt(query, platform, f.targetUserId, { token: RECEIVER_TOKEN, now: NOW })));
    assert.deepEqual(f.state, before);
  });

  for (const owner of [0, 1]) {
    for (const flag of ["is_blocked", "telegram_blocked", "max_blocked"]) {
      test(`${platform}: ${flag} on ${owner ? "recipient" : "source"} blocks transfer`, async () => {
        const f = fixture(platform);
        f.state.linked_accounts[owner][flag] = 1;
        const before = copy(f.state);
        await invalid(f.prepare());
        assert.deepEqual(f.state, before);
      });
    }
  }
}

test("recipient resolution requires an existing exact identity and rejects ambiguous usernames", async () => {
  const f = fixture();
  const numeric = await resolveTransferRecipient(f.query, "telegram", f.targetUserId);
  const username = await resolveTransferRecipient(f.query, "telegram", "@nEwOwNeR");
  assert.deepEqual(username, numeric);
  await invalid(resolveTransferRecipient(f.query, "telegram", "999999"));
  await invalid(resolveTransferRecipient(f.query, "telegram", "@New"));
  await invalid(resolveTransferRecipient(f.query, "telegram", "200 OR 1=1"));
  f.state.telegram_users.push({ ...f.state.telegram_users[1], telegram_user_id: "999" });
  await invalid(resolveTransferRecipient(f.query, "telegram", "@NewOwner"));
});

test("MAX recipient must have a known private bot chat", async () => {
  const f = fixture("max");
  f.state.max_users[1].chat_id = null;
  await invalid(resolveTransferRecipient(f.query, "max", f.targetUserId));
});

test("self-transfer is rejected before ownership changes", async () => {
  const f = fixture();
  await invalid(f.transaction((query) => prepareAccountTransfer(query, "telegram", f.sourceUserId, f.sourceUserId, { token: TOKEN, now: NOW })));
  assert.equal(f.state.account_channels[0].account_id, 1);
});
