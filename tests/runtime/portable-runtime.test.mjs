import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import {
  applyRuntimeTimezone, createAdminPasswordHash, platformEnabled, readRuntimeEnvironment, validateRuntimeUrls,
  verifyAdminCredentials, verifyAdminPassword, workersEnabled, writeRuntimeEnvironment
} from "../../payload/src/src/portable-runtime.js";

test("JSON configuration preserves strings and replaces atomically without exposing malformed content", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gitreposted-json-"));
  const file = path.join(directory, "config.json");
  try {
    fs.writeFileSync(file, JSON.stringify({ ADMIN_USERNAME: "admin", VALUE: "line1\nline2=\"quoted\"" }));
    const previous = readRuntimeEnvironment(file);
    writeRuntimeEnvironment(file, { ...previous, VALUE: "changed", EMPTY: "" });
    assert.deepEqual(readRuntimeEnvironment(file), { ADMIN_USERNAME: "admin", VALUE: "changed", EMPTY: "" });
    if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(fs.readdirSync(directory), ["config.json"]);
    assert.throws(() => writeRuntimeEnvironment(file, { BAD: { nested: true } }), /flat JSON/);
    assert.equal(readRuntimeEnvironment(file).VALUE, "changed");
    fs.writeFileSync(file, '{"PRIVATE_VALUE":"sentinel-secret", bad}');
    assert.throws(() => readRuntimeEnvironment(file), (error) => error.message === "Configuration contains invalid JSON.");
    for (const invalid of [[], { VALUE: 1 }, { VALUE: null }, { lower_case: "x" }]) {
      fs.writeFileSync(file, JSON.stringify(invalid));
      assert.throws(() => readRuntimeEnvironment(file), /flat JSON/);
    }
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test("legacy env parser and writer preserve the password installation interface", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gitreposted-env-"));
  const file = path.join(directory, "application.env");
  try {
    fs.writeFileSync(file, '# comment\nADMIN_API_KEY="legacy private password"\nVALUE=a=b\n');
    const values = readRuntimeEnvironment(file);
    assert.equal(values.VALUE, "a=b");
    assert.equal(verifyAdminCredentials(values, undefined, "legacy private password"), true);
    assert.equal(verifyAdminPassword(values, ""), false);
    writeRuntimeEnvironment(file, { ...values, VALUE: "updated" });
    assert.equal(readRuntimeEnvironment(file).VALUE, "updated");
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test("POSIX configuration replacement persists its directory before success and reports ambiguous fsync failure", () => {
  const module = fs.readFileSync(new URL("../../payload/src/src/portable-runtime.js", import.meta.url), "utf8");
  const writer = module.slice(module.indexOf("export function writeRuntimeEnvironment("), module.indexOf("\nexport function platformEnabled("))
    .replace(/^export /, "");
  const filename = "/private/config.json";
  const oldValue = '{"VALUE":"old"}\n';
  for (const failDirectorySync of [false, true]) {
    // Model persisted file bytes and persisted directory entries separately.
    // A file fsync alone must not make rename survive a simulated power loss.
    const namespace = new Map([[filename, { bytes: oldValue, durable: oldValue }]]);
    let stableNamespace = new Map(namespace);
    const opened = new Map();
    const events = [];
    let nextDescriptor = 10;
    const fakeFs = {
      constants: { O_RDONLY: 0, O_DIRECTORY: 0x10000, O_NOFOLLOW: 0x20000 },
      statSync() { return { uid: 1000, gid: 1000 }; },
      openSync(name, flags) {
        const descriptor = nextDescriptor++;
        if (name === "/private") {
          assert.equal(flags, 0x30000);
          opened.set(descriptor, { directory: true });
        } else {
          assert.equal(flags, "wx");
          assert.ok(!namespace.has(name));
          const value = { bytes: "", durable: null };
          namespace.set(name, value);
          opened.set(descriptor, { name, value });
        }
        return descriptor;
      },
      writeFileSync(descriptor, source) { opened.get(descriptor).value.bytes = source; },
      fchmodSync() {},
      fsyncSync(descriptor) {
        const target = opened.get(descriptor);
        if (target.directory) {
          events.push("directory-fsync");
          if (failDirectorySync) throw new Error("private disk fault details");
          stableNamespace = new Map(namespace);
        } else { events.push("file-fsync"); target.value.durable = target.value.bytes; }
      },
      closeSync(descriptor) { assert.ok(opened.delete(descriptor)); },
      renameSync(from, to) { events.push("rename"); namespace.set(to, namespace.get(from)); namespace.delete(from); },
      unlinkSync(name) { namespace.delete(name); }
    };
    const context = vm.createContext({ fs: fakeFs, path: path.posix,
      crypto: { randomBytes: () => Buffer.alloc(8) }, process: { pid: 123, platform: "linux", getuid: () => 1000 },
      jsonConfiguration: () => true, validateEnvironmentMap: value => value });
    vm.runInContext(writer, context);
    if (failDirectorySync) {
      assert.throws(() => context.writeRuntimeEnvironment(filename, { VALUE: "new" }), error =>
        error.code === "CONFIG_DURABILITY_UNCONFIRMED" && error.statusCode === 503 && error.configurationReplaced === true
        && /replaced/.test(error.message) && !/private disk/.test(error.message));
      assert.equal(JSON.parse(namespace.get(filename).bytes).VALUE, "new");
      assert.equal(JSON.parse(stableNamespace.get(filename).durable).VALUE, "old");
    } else {
      context.writeRuntimeEnvironment(filename, { VALUE: "new" });
      assert.equal(JSON.parse(stableNamespace.get(filename).durable).VALUE, "new");
    }
    assert.deepEqual(events, ["file-fsync", "rename", "directory-fsync"]);
    assert.equal(opened.size, 0);
    assert.deepEqual([...namespace.keys()], [filename]);
  }
});

test("scrypt matches Python hashlib.scrypt, requires username, and rejects malformed costs without fallback", () => {
  // Python 3 hashlib.scrypt(b'correct horse battery staple', salt=bytes.fromhex('00'*16), n=16384,r=8,p=1,dklen=32).
  const hash = createAdminPasswordHash("correct horse battery staple", Buffer.alloc(16));
  assert.equal(hash, "scrypt$16384$8$1$00000000000000000000000000000000$1004ee38ce027a2729879b60928c49d36fd9a7f9ecec9a6158419822c30b160a");
  const values = { ADMIN_USERNAME: "operator", ADMIN_PASSWORD_HASH: hash, ADMIN_API_KEY: "separate bearer secret" };
  assert.equal(verifyAdminCredentials(values, "operator", "correct horse battery staple"), true);
  assert.equal(verifyAdminCredentials(values, "admin", "correct horse battery staple"), false);
  assert.equal(verifyAdminCredentials(values, "operator", values.ADMIN_API_KEY), false);
  assert.equal(verifyAdminPassword({ ...values, ADMIN_PASSWORD_HASH: "scrypt$999999999$8$1$bad$bad" }, values.ADMIN_API_KEY), false);
  assert.equal(verifyAdminPassword(values, "x".repeat(4097)), false);
});

test("optional flags preserve legacy enabled workers and disable only explicit zero", () => {
  assert.equal(platformEnabled({}, "telegram"), true);
  assert.equal(platformEnabled({ PUBLIC_TELEGRAM_ENABLED: "0" }, "telegram"), true);
  assert.equal(platformEnabled({ TELEGRAM_ENABLED: "0" }, "telegram"), false);
  assert.equal(platformEnabled({ MAX_ENABLED: "0" }, "max"), false);
  assert.equal(workersEnabled({}), true);
  assert.equal(workersEnabled({ GITREPOSTED_WORKERS_ENABLED: "0" }), false);
});

test("portable URLs reject credentials, fragments, wrong bot hosts and remote cleartext API roots", () => {
  validateRuntimeUrls({ PUBLIC_BASE_URL: "http://192.0.2.1", TELEGRAM_API_BASE_URL: "http://127.0.0.1:8081", MAX_API_BASE_URL: "https://platform-api2.max.ru", TELEGRAM_BOT_URL: "https://t.me/test_bot", MAX_BOT_URL: "https://max.ru/id123_bot" });
  for (const values of [{ PUBLIC_BASE_URL: "https://user:secret@example.com" }, { MAX_API_BASE_URL: "http://remote.example" }, { TELEGRAM_BOT_URL: "javascript:alert(1)" }, { MAX_BOT_URL: "https://example.com/bot" }, { PUBLIC_BASE_URL: "https://example.com/#fragment" }]) {
    assert.throws(() => validateRuntimeUrls(values), /URL/);
  }
});

test("configured IANA timezone is validated and applied to the actual Node process", () => {
  const previous = process.env.TZ;
  try {
    applyRuntimeTimezone({ TZ: "Europe/Moscow" });
    assert.equal(process.env.TZ, "Europe/Moscow");
    assert.equal(new Date("2026-10-24T00:00:00Z").getTimezoneOffset(), -180);
    assert.equal(new Intl.DateTimeFormat("en").resolvedOptions().timeZone, "Europe/Moscow");
    applyRuntimeTimezone({});
    assert.equal(process.env.TZ, "Europe/Moscow");
    assert.throws(() => applyRuntimeTimezone({ TZ: "Unknown/Zone" }), /valid IANA/);
    assert.throws(() => applyRuntimeTimezone({ TZ: "" }), /valid IANA/);
    assert.equal(process.env.TZ, "Europe/Moscow");
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
});

test("hCaptcha is skipped only for explicit zero and otherwise fails closed without provider credentials", async () => {
  const server = fs.readFileSync(new URL("../../payload/src/server.js", import.meta.url), "utf8");
  const source = server.slice(server.indexOf("async function verifyHcaptcha("), server.indexOf("\nfunction changeAdminPassword("));
  for (const [env, expected] of [[{ HCAPTCHA_ENABLED: "0" }, true], [{}, false], [{ HCAPTCHA_ENABLED: "1" }, false]]) {
    const context = vm.createContext({ env, fetch: () => { throw new Error("Provider must not be contacted"); } });
    vm.runInContext(source, context);
    assert.equal(await context.verifyHcaptcha({}, ""), expected);
  }
});

test("landing uses configured safe bot URLs and leaves disabled or malicious links inactive", async () => {
  const html = fs.readFileSync(new URL("../../payload/src/public/landing.html", import.meta.url), "utf8");
  assert.doesNotMatch(html, /href=["\']https:\/\/(?:t\.me|max\.ru)\//);
  const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const links = ["telegram", "max"].map((platform) => ({
    dataset: { platformLink: platform }, attributes: { "aria-disabled": "true" },
    setAttribute(name, value) { this.attributes[name] = value; },
    removeAttribute(name) { delete this.attributes[name]; if (name === "href") delete this.href; }
  }));
  for (const [data, expected] of [
    [{ telegram: { public: true, url: "https://t.me/portable_bot" }, max: { public: true, url: "https://max.ru/portable_bot" } }, ["https://t.me/portable_bot", "https://max.ru/portable_bot"]],
    [{ telegram: { public: false, url: "https://t.me/portable_bot" }, max: { public: true, url: "javascript:alert(1)" } }, [undefined, undefined]],
    [{ telegram: { public: true, url: "https://t.me.evil.example/portable_bot" }, max: { public: true, url: "https://max.ru/portable_bot#bad" } }, [undefined, undefined]]
  ]) {
    const context = vm.createContext({ URL, fetch: async () => ({ json: async () => data }), document: { querySelectorAll: (selector) => selector === "[data-platform-link]" ? links : [] } });
    await vm.runInContext(source, context);
    assert.deepEqual(links.map((link) => link.href), expected);
  }
});
