import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { publicBaseInfo } from "./public-base.js";

export function jsonConfiguration(filePath) {
  return path.extname(filePath).toLowerCase() === ".json";
}

export function validateEnvironmentMap(values) {
  if (!values || typeof values !== "object" || Array.isArray(values)
    || Object.entries(values).some(([key, value]) => !/^[A-Z][A-Z0-9_]*$/.test(key)
      || typeof value !== "string" || value.includes("\0"))) {
    throw new Error("Configuration must be a flat JSON object of environment names and string values.");
  }
  return values;
}

export function readRuntimeEnvironment(filePath) {
  const source = fs.readFileSync(filePath, "utf8");
  if (jsonConfiguration(filePath)) {
    let parsed;
    try { parsed = JSON.parse(source.replace(/^\uFEFF/, "")); }
    catch { throw new Error("Configuration contains invalid JSON."); }
    return validateEnvironmentMap(parsed);
  }
  const values = {};
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separatorIndex = line.indexOf("=");
    if (separatorIndex <= 0) continue;
    const key = line.slice(0, separatorIndex).trim();
    let value = line.slice(separatorIndex + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    values[key] = value;
  }
  return values;
}

export function writeRuntimeEnvironment(filePath, nextEnv) {
  const source = jsonConfiguration(filePath)
    ? `${JSON.stringify(validateEnvironmentMap(nextEnv), null, 2)}\n`
    : `${Object.entries(nextEnv).map(([key, value]) => `${key}=${value ?? ""}`).join("\n")}\n`;
  const currentStat = fs.statSync(filePath);
  const temporaryPath = `${filePath}.tmp-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
  let descriptor;
  let directoryDescriptor;
  try {
    // Ubuntu needs the directory entry persisted as well as the new file's
    // bytes. Windows does not support opening/fsyncing a directory this way.
    if (process.platform !== "win32") {
      directoryDescriptor = fs.openSync(path.dirname(path.resolve(filePath)),
        fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    }
    descriptor = fs.openSync(temporaryPath, "wx", 0o600);
    fs.writeFileSync(descriptor, source, { encoding: "utf8" });
    if (typeof process.getuid === "function" && process.getuid() === 0) {
      fs.fchownSync(descriptor, currentStat.uid, currentStat.gid);
    }
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporaryPath, filePath);
    if (directoryDescriptor !== undefined) {
      try { fs.fsyncSync(directoryDescriptor); }
      catch {
        const error = new Error("Configuration was replaced, but saving its directory to disk was not confirmed. Reload the saved configuration before retrying.");
        error.code = "CONFIG_DURABILITY_UNCONFIRMED";
        error.statusCode = 503;
        error.configurationReplaced = true;
        throw error;
      }
    }
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporaryPath); } catch { /* Nothing remains after a successful rename. */ }
    throw error;
  } finally {
    if (directoryDescriptor !== undefined) fs.closeSync(directoryDescriptor);
  }
}

export function platformEnabled(values, platform) {
  return values[`${platform.toUpperCase()}_ENABLED`] !== "0";
}

export function workersEnabled(values) {
  return values.GITREPOSTED_WORKERS_ENABLED !== "0";
}

export function applyRuntimeTimezone(values) {
  if (values.TZ === undefined) return;
  try {
    if (typeof values.TZ !== "string" || !values.TZ) throw new Error("Empty timezone");
    const timezone = new Intl.DateTimeFormat("en", { timeZone: values.TZ }).resolvedOptions().timeZone;
    process.env.TZ = timezone;
  } catch {
    throw new Error("TZ must contain a valid IANA time zone.");
  }
}

export function validateRuntimeUrls(values) {
  if (values.PUBLIC_BASE_URL) publicBaseInfo(values.PUBLIC_BASE_URL);
  for (const key of ["PUBLIC_BASE_URL", "TELEGRAM_API_BASE_URL", "MAX_API_BASE_URL", "TELEGRAM_BOT_URL", "MAX_BOT_URL"]) {
    if (!values[key]) continue;
    let url;
    try { url = new URL(values[key]); } catch { throw new Error(`${key} must contain a valid HTTP(S) URL.`); }
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash
      || (key.includes("API_BASE_URL") && url.protocol !== "https:"
        && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
      || (key.endsWith("BOT_URL") && (url.protocol !== "https:"
        || url.hostname !== (key === "TELEGRAM_BOT_URL" ? "t.me" : "max.ru")
        || url.port || !/^\/[A-Za-z0-9_]+$/.test(url.pathname)))) {
      throw new Error(`${key} contains an unsupported URL.`);
    }
  }
}

export function passwordHashConfigured(value) {
  return /^scrypt\$16384\$8\$1\$[a-f0-9]{32}\$[a-f0-9]{64}$/.test(String(value || ""));
}

export function createAdminPasswordHash(password, salt = crypto.randomBytes(16)) {
  const derived = crypto.scryptSync(String(password), salt, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$16384$8$1$${salt.toString("hex")}$${derived.toString("hex")}`;
}

export function verifyAdminPassword(values, password) {
  if (typeof password !== "string" || !password || password.length > 4096) return false;
  if (values.ADMIN_PASSWORD_HASH) {
    if (!passwordHashConfigured(values.ADMIN_PASSWORD_HASH)) return false;
    const [, , , , salt, expected] = values.ADMIN_PASSWORD_HASH.split("$");
    const actual = crypto.scryptSync(password, Buffer.from(salt, "hex"), 32,
      { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    return crypto.timingSafeEqual(actual, Buffer.from(expected, "hex"));
  }
  const actual = Buffer.from(password);
  const expected = Buffer.from(String(values.ADMIN_API_KEY || ""));
  return expected.length > 0 && actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function verifyAdminCredentials(values, username, password) {
  // Existing env installations accepted only a password; preserve that interface until migrated.
  if (values.ADMIN_PASSWORD_HASH) {
    const actual = Buffer.from(String(username || ""));
    const expected = Buffer.from(values.ADMIN_USERNAME || "admin");
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return false;
  }
  return verifyAdminPassword(values, password);
}

export const EXPECTED_RUNTIME_TABLES = Object.freeze([
  "account_channels", "account_link_codes", "admin_passkeys", "app_schema_migrations",
  "bot_event_receipts", "bot_ingress_events", "bridges", "delivery_log", "inbound_events",
  "linked_accounts", "max_channels", "max_users", "relay_outbound_messages",
  "relay_outbound_operations", "relay_source_events", "repost_route_targets", "repost_routes",
  "telegram_channels", "telegram_users"
]);

export async function verifyRuntimeSchema(query) {
  const tables = await query("SELECT TABLE_NAME AS table_name, TABLE_TYPE AS table_type FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY TABLE_NAME");
  const actual = tables.map((row) => String(row.table_name)).sort();
  if (tables.some((row) => row.table_type !== "BASE TABLE")
    || actual.join("|") !== EXPECTED_RUNTIME_TABLES.join("|")) {
    throw new Error("Runtime schema does not contain exactly the expected application tables.");
  }
  // Verify the current durable-delivery contract, not merely a count of table names.
  const columns = await query("SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, IS_NULLABLE AS is_nullable FROM information_schema.columns WHERE table_schema = DATABASE()");
  const required = {
    bot_ingress_events: ["ingress_id", "actor_key", "payload_json", "lease_token", "lease_until", "state"],
    relay_source_events: ["queue_id", "job_key", "payload_json", "routing_json", "lease_token", "lease_until", "terminal_at"],
    relay_outbound_operations: ["operation_key", "lease_token", "lease_until", "state"],
    linked_accounts: ["is_blocked", "telegram_blocked", "max_blocked", "block_reason"],
    account_channels: ["is_blocked", "block_reason"]
  };
  for (const [table, names] of Object.entries(required)) {
    for (const name of names) {
      const column = columns.find((row) => row.table_name === table && row.column_name === name);
      if (!column || (["payload_json", "routing_json", "actor_key"].includes(name) && column.is_nullable !== "NO")) {
        throw new Error("Runtime schema is missing a required current column contract.");
      }
    }
  }
  const indexes = await query("SELECT TABLE_NAME AS table_name, INDEX_NAME AS index_name, COLUMN_NAME AS column_name, SEQ_IN_INDEX AS sequence_number, NON_UNIQUE AS non_unique FROM information_schema.statistics WHERE table_schema = DATABASE() ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX");
  for (const [table, index, names, unique] of [
    ["bot_ingress_events", "idx_bot_ingress_actor_order", "platform,actor_key,ingress_id,state", false],
    ["relay_source_events", "uq_relay_source_job", "platform,chat_id,job_key", true],
    ["relay_outbound_operations", "uq_relay_outbound_target", "source_platform,source_chat_id,source_event_id,target_platform,target_chat_id,operation_key", true],
    ["account_channels", "uq_account_channel_platform_chat", "platform,chat_id", true]
  ]) {
    const rows = indexes.filter((row) => row.table_name === table && row.index_name === index)
      .sort((a, b) => Number(a.sequence_number) - Number(b.sequence_number));
    if (rows.map((row) => row.column_name).join(",") !== names
      || (unique && rows.some((row) => Number(row.non_unique) !== 0))) {
      throw new Error("Runtime schema is missing a required current index contract.");
    }
  }
  return { tables: actual.length };
}
