import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import test from "node:test";

const executeFile = promisify(execFile);
const application = fileURLToPath(new URL("../../payload/src/", import.meta.url));
const passwordHash = "scrypt$16384$8$1$00000000000000000000000000000000$1004ee38ce027a2729879b60928c49d36fd9a7f9ecec9a6158419822c30b160a";

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gitreposted-server-"));
  // Copy explicit reviewed runtime targets, never arbitrary installed state.
  for (const file of ["server.js", "src/account-routing.js", "src/bot-ui.js", "src/config.js", "src/link-format.js", "src/multipart-stream.js", "src/portable-runtime.js", "src/relay-idempotency.js", "src/relay-media.js", "src/relay-retry.js", "src/relay-temp-file.js", "src/request-ip.js", "src/runtime-secrets.js", "src/security-state.js", "public/index.html", "public/app.js", "public/app.css", "public/landing.html", "public/landing.css", "public/landing-strict.css", "public/assets/telegram.png", "public/assets/reposted-logo.png", "public/assets/max.png"]) {
    const target = path.join(directory, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(application, file), target);
  }
  fs.writeFileSync(path.join(directory, "package.json"), '{"type":"module"}');
  const driver = path.join(directory, "node_modules", "mysql2");
  fs.mkdirSync(driver, { recursive: true });
  fs.writeFileSync(path.join(driver, "package.json"), '{"type":"module","exports":{"./promise":"./promise.js"}}');
  fs.writeFileSync(path.join(driver, "promise.js"), `
import fs from 'node:fs';
const tables = ['account_channels','account_link_codes','admin_passkeys','app_schema_migrations','bot_event_receipts','bot_ingress_events','bridges','delivery_log','inbound_events','linked_accounts','max_channels','max_users','relay_outbound_messages','relay_outbound_operations','relay_source_events','repost_route_targets','repost_routes','telegram_channels','telegram_users'];
const required = {bot_ingress_events:['ingress_id','actor_key','payload_json','lease_token','lease_until','state'],relay_source_events:['queue_id','job_key','payload_json','routing_json','lease_token','lease_until','terminal_at'],relay_outbound_operations:['operation_key','lease_token','lease_until','state'],linked_accounts:['is_blocked','telegram_blocked','max_blocked','block_reason'],account_channels:['is_blocked','block_reason']};
const columns=Object.entries(required).flatMap(([table_name,names])=>names.map(column_name=>({table_name,column_name,is_nullable:'NO'})));
const indexes=[['bot_ingress_events','idx_bot_ingress_actor_order','platform,actor_key,ingress_id,state',1],['relay_source_events','uq_relay_source_job','platform,chat_id,job_key',0],['relay_outbound_operations','uq_relay_outbound_target','source_platform,source_chat_id,source_event_id,target_platform,target_chat_id,operation_key',0],['account_channels','uq_account_channel_platform_chat','platform,chat_id',0]].flatMap(([table_name,index_name,names,non_unique])=>names.split(',').map((column_name,i)=>({table_name,index_name,column_name,sequence_number:i+1,non_unique})));
function ledger(value){fs.appendFileSync(process.env.TEST_LEDGER,value+'\\n');}
async function execute(sql,params=[]){
 const normalized=sql.replace(/\\s+/g,' ').trim(); ledger(normalized);
 if(process.env.TEST_READ_ONLY==='1'&&!/^SELECT /i.test(normalized))throw new Error('MUTATION_FORBIDDEN');
 if(/^SELECT TABLE_NAME AS table_name, TABLE_TYPE/.test(normalized))return [tables.filter(t=>!(process.env.TEST_BAD_SCHEMA==='missing'&&t==='bot_ingress_events')).map(table_name=>({table_name,table_type:'BASE TABLE'}))];
 if(/^SELECT TABLE_NAME AS table_name, COLUMN_NAME/.test(normalized))return [columns.filter(c=>!(process.env.TEST_BAD_SCHEMA==='nullable'&&c.column_name==='routing_json'))];
 if(/^SELECT TABLE_NAME AS table_name, INDEX_NAME/.test(normalized))return [indexes.filter(i=>!(process.env.TEST_BAD_SCHEMA==='index'&&i.index_name==='uq_relay_outbound_target'))];
 if(/information_schema.COLUMNS/.test(normalized))return [[{COLUMN_TYPE:"enum('queued','processing','completed','failed','terminal','pending','sending','uncertain')",IS_NULLABLE:'NO',1:1}]];
 if(/information_schema.STATISTICS/.test(normalized))return [/SELECT COLUMN_NAME/.test(normalized)?indexes.filter(i=>i.table_name===params[0]&&i.index_name===params[1]).map(i=>({COLUMN_NAME:i.column_name})):[{1:1}]];
 if(/GET_LOCK/.test(normalized))return [[{acquired:1}]];
 if(/RELEASE_LOCK/.test(normalized))return [[{released:1}]];
 if(/^SELECT COUNT/.test(normalized))return [[{total:0}]];
 if(/^SELECT /i.test(normalized))return [[]];
 return [{affectedRows:/^INSERT/i.test(normalized)?1:0}];
}

const connection={execute,async beginTransaction(){ledger('BEGIN');},async commit(){ledger('COMMIT');},async rollback(){ledger('ROLLBACK');},release(){}};
export default {createPool(){return {execute,async getConnection(){return connection;},async end(){ledger('POOL_END');}};}};
`);
  fs.writeFileSync(path.join(directory, "guard.mjs"), `
import fs from 'node:fs'; import http from 'node:http';
globalThis.fetch=async()=>{fs.appendFileSync(process.env.TEST_LEDGER,'PROVIDER_FORBIDDEN\\n');throw new Error('PROVIDER_FORBIDDEN');};
globalThis.setInterval=()=>{throw new Error('WORKER_TIMER_FORBIDDEN');};
const original=http.Server.prototype.listen;
http.Server.prototype.listen=function(...args){if(process.env.TEST_FORBID_LISTEN==='1')throw new Error('HTTP_FORBIDDEN');this.once('listening',()=>console.log('READY:'+this.address().port));return original.apply(this,args);};
`);
  const config = {
    HOST: "127.0.0.1", PORT: "0", PUBLIC_BASE_URL: "https://example.test",
    ADMIN_USERNAME: "operator", ADMIN_PASSWORD_HASH: passwordHash, ADMIN_API_KEY: "11".repeat(32),
    HCAPTCHA_ENABLED: "0", GITREPOSTED_WORKERS_ENABLED: "0", TELEGRAM_ENABLED: "1", MAX_ENABLED: "0",
    TELEGRAM_WEBHOOK_SECRET: "test_webhook_secret_for_captured_runtime", TELEGRAM_BOT_TOKEN: "test-only-no-provider",
    TELEGRAM_API_BASE_URL: "https://api.telegram.org", TELEGRAM_LOCAL_FILE_MODE: "0",
    PUBLIC_TELEGRAM_ENABLED: "1", TELEGRAM_BOT_URL: "https://t.me/fixture_bot", PUBLIC_MAX_ENABLED: "0",
    MAX_API_BASE_URL: "https://platform-api2.max.ru", DB_HOST: "invalid.test", DB_NAME: "captured_fixture"
  };
  const configPath = path.join(directory, "config.json");
  fs.writeFileSync(configPath, JSON.stringify(config));
  const ledgerPath = path.join(directory, "ledger.txt");
  const environment = { ...process.env, GITREPOSTED_ENV_FILE: configPath, TEST_LEDGER: ledgerPath };
  return { directory, config, configPath, ledgerPath, environment };
}

async function startCapturedServer(data) {
  const child = spawn(process.execPath, ["--import", "./guard.mjs", "server.js"], { cwd: data.directory, env: data.environment, stdio: ["ignore", "pipe", "pipe"] });
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error("Captured server startup timed out")); }, 10000);
    let stdout = "";
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      const match = /READY:(\d+)/.exec(stdout);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
    child.once("exit", (code) => { clearTimeout(timer); reject(new Error(`Captured server exited ${code}: ${stderr}`)); });
  });
  const base = `http://127.0.0.1:${port}`;
  return { child, request: (route, body, headers = {}) => fetch(base + route, {
    method: body === undefined ? "GET" : "POST", headers: { "content-type": "application/json", ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  }) };
}

async function stopCapturedServer(child) {
  if (child && child.exitCode === null) await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
}

test("CLI verify is read-only, validates current tables/columns/indexes and never starts HTTP/workers/providers", async () => {
  const data = fixture();
  try {
    const options = { cwd: data.directory, env: { ...data.environment, TEST_READ_ONLY: "1", TEST_FORBID_LISTEN: "1" } };
    const result = await executeFile(process.execPath, ["--import", "./guard.mjs", "server.js", "--verify-schema"], options);
    assert.deepEqual(JSON.parse(result.stdout), { ok: true, result: { tables: 19 } });
    assert.equal(result.stderr, "");
    const ledger = fs.readFileSync(data.ledgerPath, "utf8").trim().split("\n");
    assert.equal(ledger.pop(), "POOL_END");
    assert.equal(ledger.length, 3);
    assert.ok(ledger.every((sql) => /^SELECT .* information_schema\./.test(sql)));
    for (const failure of ["missing", "nullable", "index"]) {
      await assert.rejects(executeFile(process.execPath, ["--import", "./guard.mjs", "server.js", "--verify-schema"], {
        ...options, env: { ...options.env, TEST_BAD_SCHEMA: failure }
      }), (error) => error.code === 1 && JSON.parse(error.stderr).ok === false && !error.stdout);
    }
  } finally { fs.rmSync(data.directory, { recursive: true }); }
});

test("CLI initialize runs the real schema initializer without HTTP, worker timers or providers", async () => {
  const data = fixture();
  try {
    const result = await executeFile(process.execPath, ["--import", "./guard.mjs", "server.js", "--initialize"], {
      cwd: data.directory, env: { ...data.environment, TEST_FORBID_LISTEN: "1" }
    });
    assert.deepEqual(JSON.parse(result.stdout), { ok: true, result: { tables: 19 } });
    const ledger = fs.readFileSync(data.ledgerPath, "utf8");
    assert.equal((ledger.match(/CREATE TABLE IF NOT EXISTS/g) || []).length, 19);
    assert.match(ledger, /INSERT INTO app_schema_migrations/);
    assert.doesNotMatch(ledger, /PROVIDER_FORBIDDEN|claimNext|SET state = 'processing'/);
    assert.match(ledger, /POOL_END\n$/);
  } finally { fs.rmSync(data.directory, { recursive: true }); }
});

test("JSON startup rejects missing password hash, invalid switches and enabled platform without a secret", async () => {
  const data = fixture();
  try {
    for (const values of [
      { ...data.config, ADMIN_PASSWORD_HASH: "" },
      { ...data.config, ADMIN_API_KEY: "plaintext password must not become a JSON bearer key" },
      { ...data.config, GITREPOSTED_WORKERS_ENABLED: "false" },
      { ...data.config, TZ: "Unknown/Zone" },
      { ...data.config, MAX_ENABLED: "1", MAX_WEBHOOK_SECRET: "" }
    ]) {
      fs.writeFileSync(data.configPath, JSON.stringify(values));
      await assert.rejects(executeFile(process.execPath, ["--import", "./guard.mjs", "server.js", "--verify-schema"], {
        cwd: data.directory, env: { ...data.environment, TEST_READ_ONLY: "1", TEST_FORBID_LISTEN: "1" }
      }), (error) => error.code === 1 && JSON.parse(error.stderr).ok === false && !error.stdout);
    }
    assert.equal(fs.readFileSync(data.ledgerPath, "utf8"), "POOL_END\n".repeat(5));
  } finally { fs.rmSync(data.directory, { recursive: true }); }
});

test("captured real HTTP handlers authenticate, rotate credentials atomically, and durably enqueue with workers paused", async () => {
  const data = fixture();
  let child;
  try {
    const server = await startCapturedServer(data);
    child = server.child;
    const { request } = server;
    assert.equal((await request("/health")).status, 200);
    assert.equal((await (await request("/api/auth-config")).json()).hcaptcha_enabled, false);
    assert.equal((await request("/api/login", { username: "wrong", password: "correct horse battery staple" })).status, 401);
    assert.equal((await request("/api/login", { username: "operator", password: data.config.ADMIN_API_KEY })).status, 401);
    const login = await request("/api/login", { username: "operator", password: "correct horse battery staple" });
    assert.equal(login.status, 200);
    const cookie = login.headers.get("set-cookie").split(";")[0];
    assert.equal((await request("/api/session", undefined, { cookie })).status, 200);
    const bearer = { authorization: `Bearer ${data.config.ADMIN_API_KEY}` };
    assert.equal((await request("/api/session", undefined, bearer)).status, 200);
    assert.equal((await request("/webhooks/max", {})).status, 503);
    assert.equal((await request("/api/setup/max-webhook", {}, bearer)).status, 503);
    const event = await request("/webhooks/telegram", { update_id: 123, message: { message_id: 1, from: { id: 5 }, chat: { id: 5, type: "private" }, text: "/start" } }, { "x-telegram-bot-api-secret-token": data.config.TELEGRAM_WEBHOOK_SECRET });
    assert.equal(event.status, 200);
    assert.equal((await event.json()).queued, true);
    const ledger = fs.readFileSync(data.ledgerPath, "utf8");
    assert.match(ledger, /INSERT IGNORE INTO bot_ingress_events/);
    assert.doesNotMatch(ledger, /PROVIDER_FORBIDDEN|SET state = 'processing'/);
    // Invalid edit must preserve both persisted and in-memory settings.
    assert.equal((await request("/api/config", { public_base_url: "javascript:bad" }, bearer)).status, 400);
    assert.equal((await (await request("/api/config", undefined, bearer)).json()).config.public_base_url, "https://example.test");
    const change = await request("/api/change-password", { current_password: "correct horse battery staple", new_password: "a different secure password", confirm_password: "a different secure password" }, { cookie });
    assert.equal(change.status, 200);
    const updated = JSON.parse(fs.readFileSync(data.configPath, "utf8"));
    assert.match(updated.ADMIN_API_KEY, /^[a-f0-9]{64}$/);
    assert.notEqual(updated.ADMIN_API_KEY, data.config.ADMIN_API_KEY);
    assert.notEqual(updated.ADMIN_PASSWORD_HASH, data.config.ADMIN_PASSWORD_HASH);
    assert.equal((await request("/api/session", undefined, { cookie })).status, 401);
    assert.equal((await request("/api/session", undefined, bearer)).status, 401);
    assert.equal((await request("/api/login", { username: "operator", password: "a different secure password" })).status, 200);
    assert.ok(!fs.readdirSync(data.directory).some((name) => name.includes(".tmp-")));
  } finally {
    await stopCapturedServer(child);
    fs.rmSync(data.directory, { recursive: true });
  }
});

test("bots can be enabled later from none, Telegram-only and MAX-only without activating transport before restart", async () => {
  for (const [telegram, max, additions] of [[false, false, ["telegram", "max"]], [true, false, ["max"]], [false, true, ["telegram"]]]) {
    const data = fixture();
    let child;
    try {
      const validTelegramToken = "123456789" + ":" + "abcdefghijklmnopqrstuvwxyzABCDE123456789";
      data.config.TELEGRAM_ENABLED = telegram ? "1" : "0";
      data.config.MAX_ENABLED = max ? "1" : "0";
      data.config.TELEGRAM_BOT_TOKEN = telegram ? validTelegramToken : "";
      data.config.MAX_BOT_TOKEN = max ? "fixture-valid-opaque-max-token" : "";
      data.config.MAX_WEBHOOK_SECRET = "fixture_generated_secret_for_max_webhooks";
      fs.writeFileSync(data.configPath, JSON.stringify(data.config));
      let running = await startCapturedServer(data);
      child = running.child;
      const authorization = { authorization: `Bearer ${data.config.ADMIN_API_KEY}` };
      const platform = additions[0];
      assert.equal((await running.request("/api/config", { [platform]: { enabled: "1" } }, authorization)).status, 400);
      assert.equal((await running.request("/api/config", { [platform]: { enabled: true, bot_token: "REPLACE_TOKEN" } }, authorization)).status, 400);
      assert.equal((await running.request("/api/config", { [platform]: { enabled: true } }, authorization)).status, 400);
      assert.equal(JSON.parse(fs.readFileSync(data.configPath, "utf8"))[`${platform.toUpperCase()}_ENABLED`], "0");
      const update = Object.fromEntries(additions.map((name) => [name, { enabled: true,
        bot_token: name === "telegram" ? validTelegramToken : "fixture-valid-opaque-max-token" }]));
      const save = await running.request("/api/config", update, authorization);
      assert.equal(save.status, 200);
      const pending = (await save.json()).config;
      assert.equal(pending.restart_required, true);
      const alreadyEnabled = telegram ? "telegram" : max ? "max" : null;
      if (alreadyEnabled) {
        const blockedSetup = await running.request(`/api/setup/${alreadyEnabled}-webhook`, {}, authorization);
        assert.equal(blockedSetup.status, 409);
        assert.equal((await blockedSetup.json()).error, "restart_required");
      }
      for (const name of additions) {
        assert.equal(pending[name].enabled, true);
        assert.equal(pending[name].active_enabled, false);
        assert.equal((await running.request(`/webhooks/${name}`, {})).status, 503);
      }
      await stopCapturedServer(child);
      running = await startCapturedServer(data);
      child = running.child;
      const active = (await (await running.request("/api/config", undefined, authorization)).json()).config;
      assert.equal(active.restart_required, false);
      for (const name of additions) {
        assert.equal(active[name].enabled, true);
        assert.equal(active[name].active_enabled, true);
        const headers = name === "telegram"
          ? { "x-telegram-bot-api-secret-token": data.config.TELEGRAM_WEBHOOK_SECRET }
          : { "x-max-bot-api-secret": data.config.MAX_WEBHOOK_SECRET };
        const response = await running.request(`/webhooks/${name}`, name === "telegram" ? { update_id: 1001, message: { message_id: 1, from: { id: 5 }, chat: { id: 5, type: "private" }, text: "/start" } } : { update_type: "bot_started", timestamp: 1, chat_id: 5, user: { user_id: 5 } }, headers);
        assert.equal(response.status, 200);
        assert.equal((await response.json()).queued, true);
      }
      assert.doesNotMatch(fs.readFileSync(data.ledgerPath, "utf8"), /PROVIDER_FORBIDDEN|SET state = 'processing'/);
    } finally {
      await stopCapturedServer(child);
      fs.rmSync(data.directory, { recursive: true });
    }
  }
});
