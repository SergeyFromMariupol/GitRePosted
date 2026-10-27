import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import {
  assertLinkedAccountIdentity,
  mutateOwnedRouteEnabled
} from "../../payload/src/src/account-routing.js";

function toggleStore({ accountId = 1, routeOwner = 1, blocked = false } = {}) {
  const account = {
    id: accountId,
    telegram_user_id: "old-user",
    max_user_id: "max-user",
    is_blocked: blocked ? 1 : 0,
    telegram_blocked: 0,
    max_blocked: 0
  };
  let locked = false;
  let enabled = 0;
  let writes = 0;
  return {
    get writes() { return writes; },
    get enabled() { return enabled; },
    query: async (sql, params) => {
      if (sql.includes("FROM linked_accounts")) {
        assert.match(sql, /FOR UPDATE/);
        locked = true;
        return [account];
      }
      assert.equal(locked, true, "authorization must hold the account lock");
      if (sql.startsWith("SELECT id FROM repost_routes")) {
        assert.match(sql, /FOR UPDATE/);
        return params[1] === routeOwner ? [{ id: params[0] }] : [];
      }
      if (sql.startsWith("UPDATE repost_routes")) {
        assert.match(sql, /WHERE id = \? AND account_id = \?/);
        assert.equal(params[2], routeOwner);
        enabled = params[0];
        writes += 1;
        return { affectedRows: 1 };
      }
      throw new Error(`Unexpected query: ${sql}`);
    }
  };
}

test("old route action cannot change a route transferred after earlier authorization", async () => {
  // A handler may already have rendered or checked this route under account 1.
  // At mutation time ownership has moved to account 2.
  const store = toggleStore({ routeOwner: 2 });
  await assert.rejects(
    mutateOwnedRouteEnabled(store.query, "telegram", "old-user", "route-1", true),
    /Пересылка не найдена/
  );
  assert.equal(store.writes, 0);
});

test("route state setter uses current ownership and repeated callbacks preserve the desired state", async () => {
  const store = toggleStore({ accountId: 2, routeOwner: 2 });
  await mutateOwnedRouteEnabled(store.query, "telegram", "old-user", "route-1", true);
  await mutateOwnedRouteEnabled(store.query, "telegram", "old-user", "route-1", true);
  assert.equal(store.enabled, 1);
  await mutateOwnedRouteEnabled(store.query, "max", "max-user", "route-1", false);
  assert.equal(store.enabled, 0);
});

test("blocked accounts and changed identities cannot mutate routes", async () => {
  const blocked = toggleStore({ blocked: true });
  await assert.rejects(
    mutateOwnedRouteEnabled(blocked.query, "telegram", "old-user", "route-1", true),
    /Доступ заблокирован/
  );
  assert.equal(blocked.writes, 0);
  const changed = toggleStore();
  await assert.rejects(
    mutateOwnedRouteEnabled(changed.query, "max", "other-max-user", "route-1", true),
    /Привязка аккаунта изменилась/
  );
  assert.equal(changed.writes, 0);
  assert.throws(() => assertLinkedAccountIdentity({ max_user_id: null }, "max", "max-user"), /Привязка/);
});

async function legacyBridgeHarness({ channelOwner = 1, detached = false } = {}) {
  const source = await fs.readFile(new URL("../../payload/src/server.js", import.meta.url), "utf8");
  const extract = (start, end) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));
  const accountLock = extract("async function lockLinkedAccountForRouting(", "async function saveUniversalRouteForUser(");
  const saveBridge = extract("async function saveBridge(", "async function updateBridgeChannels(");
  assert.ok(accountLock && saveBridge);
  let active = false;
  let locked = false;
  let writes = 0;
  let reconciliations = 0;
  const query = async (sql, params) => {
    assert.equal(active, true, "all bridge operations must share the transaction");
    if (sql.includes("FROM linked_accounts")) {
      assert.match(sql, /FOR UPDATE/);
      locked = true;
      return [{ id: 1, telegram_user_id: "old-user", max_user_id: detached ? null : "max-user" }];
    }
    assert.equal(locked, true, "account lock must precede configuration reads");
    if (sql.includes("FROM account_channels")) {
      assert.match(sql, /FOR UPDATE/);
      return params[0] === channelOwner ? [{ 1: 1 }] : [];
    }
    if (sql.startsWith("SELECT title")) return [{ title: "Channel" }];
    if (sql.startsWith("SELECT id FROM bridges") || sql.startsWith("SELECT account_id FROM bridges")) return [];
    if (sql.startsWith("INSERT INTO bridges")) {
      writes += 1;
      return { affectedRows: 1 };
    }
    throw new Error(`Unexpected query: ${sql}`);
  };
  const build = new Function(
    "db", "linkedAccount", "withDbTransaction", "assertLinkedAccountIdentity", "hashKey", "reconcileLegacyBridgeRoute",
    `${accountLock}\n${saveBridge}\nreturn saveBridge;`
  );
  const save = build(
    async () => { throw new Error("Bridge configuration cannot use an unlocked connection"); },
    async () => ({ id: 1 }),
    async (work) => {
      assert.equal(active, false, "nested transaction is forbidden");
      active = true;
      try { return await work(query); } finally { active = false; }
    },
    assertLinkedAccountIdentity,
    () => "bridge-hash",
    async (currentQuery) => {
      assert.equal(active, true);
      assert.equal(currentQuery, query);
      reconciliations += 1;
    }
  );
  return { save, get writes() { return writes; }, get reconciliations() { return reconciliations; } };
}

test("legacy bridge save rejects channels transferred after the account was resolved", async () => {
  const state = await legacyBridgeHarness({ channelOwner: 2 });
  await assert.rejects(state.save("telegram", "old-user", "tg-channel", "max-channel", "both"), /Канал не принадлежит/);
  assert.equal(state.writes, 0);
  assert.equal(state.reconciliations, 0);
});

test("legacy bridge save rejects a counterpart moved to another linked account", async () => {
  const state = await legacyBridgeHarness({ detached: true });
  await assert.rejects(state.save("max", "max-user", "tg-channel", "max-channel", "both"), /Привязка аккаунта изменилась/);
  assert.equal(state.writes, 0);
});

test("legacy bridge save holds ownership through the bridge and both route reconciliations", async () => {
  const state = await legacyBridgeHarness();
  await state.save("telegram", "old-user", "tg-channel", "max-channel", "both");
  assert.equal(state.writes, 1);
  assert.equal(state.reconciliations, 2);
});
