import fs from "node:fs";
import http from "node:http";
import crypto from "node:crypto";
import mysql from "mysql2/promise";
import { publicBaseInfo, publicLocalPath, publicPathPrefix, renderPublicHtml } from "./src/public-base.js";
import {
  applyRuntimeTimezone,
  createAdminPasswordHash,
  jsonConfiguration,
  passwordHashConfigured,
  platformEnabled,
  readRuntimeEnvironment,
  verifyAdminCredentials,
  verifyAdminPassword,
  verifyRuntimeSchema,
  validateRuntimeUrls,
  workersEnabled,
  writeRuntimeEnvironment
} from "./src/portable-runtime.js";
import {
  maxInlineKeyboardRowsForTelegram,
  maxMessageEntitiesForTelegram,
  maxMessageTextForMax,
  telegramCompatibleUrl,
  telegramMessageTextForMax
} from "./src/link-format.js";
import {
  combineTelegramPayloadParts,
  createTelegramLocalFileContent,
  extractMaxUploadToken,
  mapSequential,
  maxAttachmentRequests,
  maxRelayContentMessages,
  maxSpecialAttachmentForTelegram,
  maxTelegramTextParts,
  splitMaxPayload,
  telegramKindForMaxAttachment,
  telegramInlineKeyboardForMax,
  telegramSpecialAttachmentsForMax,
  telegramDocumentUploadDescriptor,
  uploadMaxAttachmentWithFallbacks
} from "./src/relay-media.js";
import { createMultipartFileUpload } from "./src/multipart-stream.js";
import {
  downloadMaxFileToTelegramRelay,
  maxAttachmentFilename,
  TELEGRAM_LOCAL_UPLOAD_LIMIT_BYTES
} from "./src/relay-temp-file.js";
import {
  extractMaxOutboundMessageIds,
  extractTelegramOutboundMessageIds,
  maxMessageId,
  maxSourceIdentity,
  normalizePlatformMessageIds,
  outboundOperationDisposition,
  stableOutboundOperationId,
  telegramSourceIdentity
} from "./src/relay-idempotency.js";
import {
  buildTelegramRelayEnvelope,
  forEachRelayTargetWithLease,
  mergeTelegramRelayMessages,
  relayRetryDelaySeconds,
  relayRetryDisposition,
  relayRetryPolicy,
  telegramRelayJobKey,
  telegramRelaySettleMilliseconds,
  withRelayLeaseHeartbeat
} from "./src/relay-retry.js";
import {
  assertPublicAccountAccess,
  consumeAccountLinkCodeTransaction,
  deleteRouteAndReleaseUnusedChannels as deleteRouteAndReleaseUnusedChannelsWithQuery,
  grantAccountChannelOwnership,
  ownedRouteAccount,
  retireLegacyRouteSource,
  syncRepostRouteTargets,
  unlinkLinkedAccountCounterpart,
  upsertRepostRoute
} from "./src/account-routing.js";
import { requestIp } from "./src/request-ip.js";
import {
  runtimeSecretConfigured,
  webhookSecretConfigured
} from "./src/runtime-secrets.js";
import {
  BoundedRateLimiter,
  BoundedTtlStore,
  HashedSessionRegistry
} from "./src/security-state.js";
import {
  bridgeSummaryText,
  compactUnicodeText,
  maxCallbackButton
} from "./src/bot-ui.js";

const ENV_FILE_PATH = process.env.GITREPOSTED_ENV_FILE
  || process.env.REPOSTED_ENV_FILE
  || "/etc/gitreposted/application.env";

const env = readEnvFile();

function adminApiKeyConfigured() {
  return runtimeSecretConfigured(env.ADMIN_API_KEY);
}

function assertRuntimeConfiguration() {
  applyRuntimeTimezone(env);
  if (env.PUBLIC_BASE_URL) publicBaseInfo(env.PUBLIC_BASE_URL);
  if (!adminApiKeyConfigured()) {
    throw new Error("ADMIN_API_KEY must be set to a non-placeholder secret before startup.");
  }
  if ((jsonConfiguration(ENV_FILE_PATH) || env.ADMIN_PASSWORD_HASH)
    && !passwordHashConfigured(env.ADMIN_PASSWORD_HASH)) {
    throw new Error("ADMIN_PASSWORD_HASH must contain a valid scrypt password hash before startup.");
  }
  if (jsonConfiguration(ENV_FILE_PATH) && !/^[a-f0-9]{64}$/.test(env.ADMIN_API_KEY)) {
    throw new Error("ADMIN_API_KEY must contain an independent random 32-byte hexadecimal secret.");
  }
  for (const key of ["TELEGRAM_ENABLED", "MAX_ENABLED", "HCAPTCHA_ENABLED", "GITREPOSTED_WORKERS_ENABLED"]) {
    if ((jsonConfiguration(ENV_FILE_PATH) || env[key] !== undefined) && !["0", "1"].includes(env[key])) {
      throw new Error(`${key} must be explicitly 0 or 1 in JSON configuration, or when configured in an env file.`);
    }
  }
  if (jsonConfiguration(ENV_FILE_PATH)) validateRuntimeUrls(env);
  if (jsonConfiguration(ENV_FILE_PATH)) {
    for (const platform of ["telegram", "max"]) {
      if (platformEnabled(env, platform) && !runtimeSecretConfigured(env[`${platform.toUpperCase()}_BOT_TOKEN`])) {
        throw new Error(`${platform.toUpperCase()}_BOT_TOKEN must be configured for the enabled platform.`);
      }
    }
  }
  if (platformEnabled(env, "telegram") && !webhookSecretConfigured(env.TELEGRAM_WEBHOOK_SECRET)) {
    throw new Error(
      "TELEGRAM_WEBHOOK_SECRET must contain at least 16 non-placeholder characters before startup."
    );
  }
  if (platformEnabled(env, "max") && !webhookSecretConfigured(env.MAX_WEBHOOK_SECRET)) {
    throw new Error(
      "MAX_WEBHOOK_SECRET must contain at least 16 non-placeholder characters before startup."
    );
  }
}

function assertPlatformEnabled(platform) {
  if (!platformEnabled(env, platform)) {
    const error = new Error(`${platform} отключён в настройках установки.`);
    error.code = "PLATFORM_DISABLED";
    error.statusCode = 503;
    throw error;
  }
}

const TELEGRAM_BOT_API_CONTAINER_DATA_DIR = env.TELEGRAM_BOT_API_CONTAINER_DATA_DIR
  || "/var/lib/telegram-bot-api";
const TELEGRAM_BOT_API_HOST_DATA_DIR = env.TELEGRAM_BOT_API_HOST_DATA_DIR
  || "/var/lib/gitreposted/telegram-bot-api";
const TELEGRAM_RELAY_TEMP_SUBDIR = env.TELEGRAM_RELAY_TEMP_SUBDIR
  || "gitreposted-relay";
const TELEGRAM_DEFAULT_API_BASE_URL = "https://api.telegram.org";

const pool = mysql.createPool({
  host: env.DB_HOST || "127.0.0.1",
  port: Number(env.DB_PORT || 3306),
  database: env.DB_NAME || "GitRePosted",
  user: env.DB_USER || "gitreposted",
  password: env.DB_PASSWORD || "",
  waitForConnections: true,
  connectionLimit: 10,
  charset: "utf8mb4"
});

const RELAY_EVENT_LEASE_SECONDS = Math.max(
  30,
  Number.parseInt(String(env.RELAY_EVENT_LEASE_SECONDS || "300"), 10) || 300
);
const RELAY_ID_TTL_DAYS = Math.max(
  1,
  Number.parseInt(String(env.RELAY_ID_TTL_DAYS || "30"), 10) || 30
);
const RELAY_RETRY_POLICY = relayRetryPolicy({
  maxAttempts: env.RELAY_RETRY_MAX_ATTEMPTS,
  baseDelaySeconds: env.RELAY_RETRY_BASE_SECONDS,
  maxDelaySeconds: env.RELAY_RETRY_MAX_SECONDS,
  pollMilliseconds: env.RELAY_RETRY_POLL_MS,
  albumSettleMilliseconds: env.TELEGRAM_ALBUM_SETTLE_MS
});
const API_REQUEST_TIMEOUT_MS = Math.max(
  5000,
  Number.parseInt(String(env.API_REQUEST_TIMEOUT_MS || "45000"), 10) || 45000
);
const MEDIA_TRANSFER_TIMEOUT_MS = Math.max(
  60000,
  Number.parseInt(String(env.MEDIA_TRANSFER_TIMEOUT_MS || "1800000"), 10) || 1800000
);
const TELEGRAM_CLOUD_UPLOAD_LIMIT_BYTES = 50 * 1024 * 1024;
const TELEGRAM_PHOTO_UPLOAD_LIMIT_BYTES = 10 * 1024 * 1024;
const DEBUG_LOG_PATH = env.DEBUG_LOG_PATH || "";

const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const adminSessions = new HashedSessionRegistry({ maxEntries: 256 });
const adminLoginAttempts = new Map();
const passkeyChallenges = new BoundedTtlStore({
  maxEntries: 1024,
  ttlMs: 5 * 60 * 1000
});
const passkeyAuthenticationRateLimiter = new BoundedRateLimiter({
  maxAttempts: 20,
  windowMs: 60 * 1000,
  maxKeys: 4096
});
const telegramUpdateIds = new Map();
const accountLinkAttempts = new Map();
const channelPublishingAccessCache = new Map();
const reconciledTelegramChannelIds = new Set();
const CHANNEL_ACCESS_CACHE_MS = 60 * 1000;
const platformSendRateState = {
  telegram: {
    chain: Promise.resolve(),
    globalNextAt: 0,
    globalGapMs: 35,
    chatGapMs: 1000,
    chatNextAt: new Map()
  },
  max: {
    chain: Promise.resolve(),
    globalNextAt: 0,
    globalGapMs: 35,
    chatGapMs: 500,
    chatNextAt: new Map()
  }
};
const MAIN_MENU_TEXT = "GitRePosted - автоматические пересылки публикаций между каналами Telegram и МАКС.\n\nВыберите раздел из меню:";
const BOT_PAGE_SIZE = 25;
const ADMIN_PERMISSIONS = [
  { key: "panel_access", title: "Доступ к панели управления" },
  { key: "manage_bridges", title: "Управление связками" },
  { key: "view_channels", title: "Просмотр каналов" },
  { key: "manage_webhooks", title: "Подключение и синхронизация бота" },
  { key: "manage_config", title: "Изменение настроек бота" },
  { key: "manage_admins", title: "Управление пользователями и правами" }
];

async function db(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

async function withDbTransaction(work) {
  const connection = await pool.getConnection();
  const query = async (sql, params = []) => {
    const [rows] = await connection.execute(sql, params);
    return rows;
  };
  try {
    await connection.beginTransaction();
    const result = await work(query);
    await connection.commit();
    return result;
  } catch (error) {
    try {
      await connection.rollback();
    } catch (rollbackError) {
      debugLog("database_rollback_failed", { message: rollbackError.message });
    }
    throw error;
  } finally {
    connection.release();
  }
}

function waitMilliseconds(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, milliseconds)));
}

async function withPlatformChatSendLimit(platform, chatId, send) {
  const state = platformSendRateState[platform];
  if (!state || !chatId) return send();
  const normalizedChatId = String(chatId);
  const reservation = state.chain.catch(() => {}).then(async () => {
    const now = Date.now();
    const scheduledAt = Math.max(
      now,
      Number(state.globalNextAt || 0),
      Number(state.chatNextAt.get(normalizedChatId) || 0)
    );
    if (scheduledAt > now) await waitMilliseconds(scheduledAt - now);
    const startedAt = Date.now();
    state.globalNextAt = startedAt + state.globalGapMs;
    state.chatNextAt.delete(normalizedChatId);
    state.chatNextAt.set(normalizedChatId, startedAt + state.chatGapMs);
    while (state.chatNextAt.size > 2000) {
      const oldest = state.chatNextAt.keys().next().value;
      if (oldest === undefined) break;
      state.chatNextAt.delete(oldest);
    }
  });
  state.chain = reservation.catch(() => {});
  await reservation;
  try {
    return await send();
  } catch (error) {
    const retryAfterSeconds = Number(error?.retryAfterSeconds || 0);
    if (retryAfterSeconds > 0) {
      const blockedUntil = Date.now() + Math.ceil(retryAfterSeconds * 1000);
      state.globalNextAt = Math.max(state.globalNextAt, blockedUntil);
      state.chatNextAt.set(
        normalizedChatId,
        Math.max(Number(state.chatNextAt.get(normalizedChatId) || 0), blockedUntil)
      );
    }
    throw error;
  }
}

function retryAfterSecondsFromHeader(value) {
  const raw = String(value || "").trim();
  if (!raw) return 0;
  const numeric = Number(raw);
  if (Number.isFinite(numeric) && numeric > 0) return Math.ceil(numeric);
  const date = Date.parse(raw);
  return Number.isFinite(date) ? Math.max(0, Math.ceil((date - Date.now()) / 1000)) : 0;
}

async function columnExists(tableName, columnName) {
  const rows = await db(
    `SELECT 1
     FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = ?
       AND COLUMN_NAME = ?
     LIMIT 1`,
    [tableName, columnName]
  );
  return rows.length > 0;
}

async function columnType(tableName, columnName) {
  const rows = await db(
    `SELECT COLUMN_TYPE
     FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = ?
       AND COLUMN_NAME = ?
     LIMIT 1`,
    [tableName, columnName]
  );
  return String(rows[0]?.COLUMN_TYPE || "");
}

async function columnIsNullable(tableName, columnName) {
  const rows = await db(
    `SELECT IS_NULLABLE
     FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = ?
       AND COLUMN_NAME = ?
     LIMIT 1`,
    [tableName, columnName]
  );
  return String(rows[0]?.IS_NULLABLE || "").toUpperCase() === "YES";
}

async function indexExists(tableName, indexName) {
  const rows = await db(
    `SELECT 1 FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ? LIMIT 1`,
    [tableName, indexName]
  );
  return rows.length > 0;
}

async function indexColumns(tableName, indexName) {
  const rows = await db(
    `SELECT COLUMN_NAME FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?
     ORDER BY SEQ_IN_INDEX`,
    [tableName, indexName]
  );
  return rows.map((row) => String(row.COLUMN_NAME));
}

function json(res, code, payload) {
  res.writeHead(code, {
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()"
  });
  res.end(JSON.stringify(payload));
}

function readEnvFile(filePath = ENV_FILE_PATH) {
  return readRuntimeEnvironment(filePath);
}

function writeEnvFile(nextEnv) {
  try { writeRuntimeEnvironment(ENV_FILE_PATH, nextEnv); }
  catch (error) {
    if (error.configurationReplaced === true) {
      // Rename succeeded but its directory fsync failed. The file already
      // contains the new values: reconcile memory without claiming durability
      // or retrying the write, especially after a credential rotation.
      let published;
      try { published = readEnvFile(); }
      catch {
        env.ADMIN_API_KEY = "";
        env.ADMIN_PASSWORD_HASH = "";
        adminSessions.clear();
        throw error;
      }
      const authChanged = ["ADMIN_API_KEY", "ADMIN_PASSWORD_HASH", "ADMIN_USERNAME"]
        .some((key) => String(published[key] ?? "") !== String(env[key] ?? ""));
      for (const key of new Set([...Object.keys(env), ...Object.keys(published)])) {
        if (RESTART_CONFIG_KEYS.includes(key)) continue;
        if (Object.hasOwn(published, key)) env[key] = published[key];
        else delete env[key];
      }
      if (authChanged) adminSessions.clear();
    }
    throw error;
  }
}

function maskSecret(value) {
  const text = String(value || "");
  if (!text) return "";
  if (text.length <= 8) return "********";
  return `${text.slice(0, 4)}••••${text.slice(-4)}`;
}

const RESTART_CONFIG_KEYS = [
  "TELEGRAM_ENABLED", "MAX_ENABLED", "TELEGRAM_BOT_TOKEN", "MAX_BOT_TOKEN",
  "TELEGRAM_BOT_URL", "MAX_BOT_URL",
  "TELEGRAM_WEBHOOK_SECRET", "MAX_WEBHOOK_SECRET", "TELEGRAM_API_BASE_URL", "MAX_API_BASE_URL",
  "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"
];

function editableConfigState() {
  const saved = readEnvFile();
  return {
    restart_required: RESTART_CONFIG_KEYS.some((key) => String(saved[key] ?? "") !== String(env[key] ?? "")),
    public_base_url: env.PUBLIC_BASE_URL || "",
    telegram: {
      enabled: platformEnabled(saved, "telegram"),
      active_enabled: platformEnabled(env, "telegram"),
      bot_token_configured: runtimeSecretConfigured(saved.TELEGRAM_BOT_TOKEN),
      webhook_secret_configured: webhookSecretConfigured(saved.TELEGRAM_WEBHOOK_SECRET),
      bot_url: saved.TELEGRAM_BOT_URL || "",
      public_enabled: env.PUBLIC_TELEGRAM_ENABLED === "1",
      webhook_url: `${env.PUBLIC_BASE_URL || ""}/webhooks/telegram`
    },
    max: {
      enabled: platformEnabled(saved, "max"),
      active_enabled: platformEnabled(env, "max"),
      bot_token_configured: runtimeSecretConfigured(saved.MAX_BOT_TOKEN),
      webhook_secret_configured: webhookSecretConfigured(saved.MAX_WEBHOOK_SECRET),
      bot_url: saved.MAX_BOT_URL || "",
      public_enabled: env.PUBLIC_MAX_ENABLED === "1",
      api_base_url: saved.MAX_API_BASE_URL || "",
      webhook_url: `${env.PUBLIC_BASE_URL || ""}/webhooks/max`
    },
    database: {
      host_configured: Boolean(saved.DB_HOST),
      port_configured: Boolean(saved.DB_PORT),
      name_configured: Boolean(saved.DB_NAME),
      user_configured: Boolean(saved.DB_USER),
      password_configured: Boolean(saved.DB_PASSWORD)
    }
  };
}

async function updateEditableConfig(payload) {
  const fileEnv = readEnvFile();
  const nextEnv = { ...fileEnv };

  for (const platform of ["telegram", "max"]) {
    if (payload?.[platform]?.enabled !== undefined) {
      if (typeof payload[platform].enabled !== "boolean") {
        const error = new Error("Переключатель платформы должен быть логическим значением.");
        error.statusCode = 400;
        throw error;
      }
      nextEnv[`${platform.toUpperCase()}_ENABLED`] = payload[platform].enabled ? "1" : "0";
    }
  }

  for (const [field, value] of [
    ["TELEGRAM_WEBHOOK_SECRET", payload?.telegram?.webhook_secret],
    ["MAX_WEBHOOK_SECRET", payload?.max?.webhook_secret]
  ]) {
    if (typeof value === "string" && value.trim() && !webhookSecretConfigured(value)) {
      const error = new Error(`${field} должен содержать не менее 16 символов и не быть шаблонным.`);
      error.statusCode = 400;
      throw error;
    }
  }

  if (typeof payload.public_base_url === "string" && payload.public_base_url.trim()) {
    let proposed;
    try { proposed = publicBaseInfo(payload.public_base_url); }
    catch { const error = new Error("Укажите адрес HTTP(S) без параметров, с путём /GitRePosted или без пути."); error.statusCode = 400; throw error; }
    if (proposed.pathPrefix !== publicPathPrefix(env.PUBLIC_BASE_URL)) {
      const error = new Error("Путь приложения меняется через установщик вместе с настройками сайта. Сохраните текущий путь адреса.");
      error.statusCode = 400;
      throw error;
    }
    nextEnv.PUBLIC_BASE_URL = proposed.baseUrl;
  }

  if (payload.telegram && typeof payload.telegram === "object") {
    if (typeof payload.telegram.bot_token === "string" && payload.telegram.bot_token.trim()) {
      nextEnv.TELEGRAM_BOT_TOKEN = payload.telegram.bot_token.trim();
    }
    if (typeof payload.telegram.webhook_secret === "string" && payload.telegram.webhook_secret.trim()) {
      nextEnv.TELEGRAM_WEBHOOK_SECRET = payload.telegram.webhook_secret.trim();
    }
    if (typeof payload.telegram.bot_url === "string" && payload.telegram.bot_url.trim()) {
      nextEnv.TELEGRAM_BOT_URL = payload.telegram.bot_url.trim();
    }
    if (typeof payload.telegram.public_enabled === "boolean") {
      nextEnv.PUBLIC_TELEGRAM_ENABLED = payload.telegram.public_enabled ? "1" : "0";
    }
  }

  if (payload.max && typeof payload.max === "object") {
    if (typeof payload.max.bot_token === "string" && payload.max.bot_token.trim()) {
      nextEnv.MAX_BOT_TOKEN = payload.max.bot_token.trim();
    }
    if (typeof payload.max.webhook_secret === "string" && payload.max.webhook_secret.trim()) {
      nextEnv.MAX_WEBHOOK_SECRET = payload.max.webhook_secret.trim();
    }
    if (typeof payload.max.bot_url === "string" && payload.max.bot_url.trim()) {
      nextEnv.MAX_BOT_URL = payload.max.bot_url.trim();
    }
    if (typeof payload.max.public_enabled === "boolean") {
      nextEnv.PUBLIC_MAX_ENABLED = payload.max.public_enabled ? "1" : "0";
    }
    if (typeof payload.max.api_base_url === "string" && payload.max.api_base_url.trim()) {
      nextEnv.MAX_API_BASE_URL = payload.max.api_base_url.trim();
    }
  }

  if (payload.database && typeof payload.database === "object") {
    const databaseFields = {
      host: "DB_HOST",
      port: "DB_PORT",
      name: "DB_NAME",
      user: "DB_USER",
      password: "DB_PASSWORD"
    };
    for (const [field, envKey] of Object.entries(databaseFields)) {
      if (typeof payload.database[field] === "string" && payload.database[field].trim()) {
        nextEnv[envKey] = payload.database[field].trim();
      }
    }
  }

  for (const platform of ["telegram", "max"]) {
    if (payload?.[platform]?.enabled === true) {
      const key = platform.toUpperCase();
      const token = String(nextEnv[`${key}_BOT_TOKEN`] || "");
      if (!runtimeSecretConfigured(token) || /\s/.test(token)
        || (platform === "telegram" && !/^[1-9][0-9]{5,11}:[A-Za-z0-9_-]{30,200}$/.test(token))
        || (platform === "max" && (token.length < 10 || token.length > 4096))
        || !webhookSecretConfigured(nextEnv[`${key}_WEBHOOK_SECRET`])) {
        const error = new Error(`Для включения ${key} укажите корректный токен и секретный ключ уведомлений.`);
        error.statusCode = 400;
        throw error;
      }
    }
  }

  try { validateRuntimeUrls(nextEnv); }
  catch { const error = new Error("Проверьте адрес сайта, API и ссылки ботов: нужны корректные HTTP(S)-адреса без пароля, query и fragment."); error.statusCode = 400; throw error; }
  writeEnvFile(nextEnv);
  for (const [key, value] of Object.entries(nextEnv)) {
    if (!RESTART_CONFIG_KEYS.includes(key)) env[key] = value;
  }
  return editableConfigState();
}

function debugLog(event, payload = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    event,
    payload
  });
  if (process.argv.length > 2) console.error(line);
  else console.log(line);
  if (DEBUG_LOG_PATH) {
    try {
      fs.appendFileSync(DEBUG_LOG_PATH, line + "\n", "utf8");
    } catch {
    }
  }
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    let rejected = false;
    req.on("data", (chunk) => {
      if (rejected) return;
      raw += chunk;
      if (Buffer.byteLength(raw, "utf8") > 2 * 1024 * 1024) {
        rejected = true;
        const error = new Error("Размер запроса превышает допустимый предел.");
        error.statusCode = 413;
        reject(error);
      }
    });
    req.on("end", () => {
      if (rejected) return;
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function hashKey(parts) {
  return crypto.createHash("sha256").update(parts.join("|")).digest("hex");
}

async function ensureSchema() {
  await db(`CREATE TABLE IF NOT EXISTS bridges (
    id VARCHAR(191) NOT NULL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    direction ENUM('tg_to_max','max_to_tg','both') NOT NULL DEFAULT 'both',
    telegram_chat_id VARCHAR(191) NOT NULL,
    max_chat_id VARCHAR(191) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    account_id BIGINT UNSIGNED DEFAULT NULL,
    KEY idx_tg (telegram_chat_id),
    KEY idx_max (max_chat_id),
    KEY idx_bridge_account (account_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS repost_routes (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    source_platform ENUM('telegram','max') NOT NULL,
    source_chat_id VARCHAR(191) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_route_source (account_id, source_platform, source_chat_id),
    KEY idx_route_source (source_platform, source_chat_id),
    KEY idx_route_account (account_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS repost_route_targets (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    route_id VARCHAR(64) NOT NULL,
    platform ENUM('telegram','max') NOT NULL,
    chat_id VARCHAR(191) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_route_target (route_id, platform, chat_id),
    KEY idx_target_chat (platform, chat_id),
    CONSTRAINT fk_route_target FOREIGN KEY (route_id) REFERENCES repost_routes(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS telegram_users (
    telegram_user_id VARCHAR(191) PRIMARY KEY,
    username VARCHAR(191) DEFAULT NULL,
    first_name VARCHAR(191) DEFAULT NULL,
    is_admin TINYINT(1) NOT NULL DEFAULT 0,
    permissions JSON DEFAULT NULL,
    state VARCHAR(64) DEFAULT NULL,
    state_payload JSON DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS max_users (
    max_user_id VARCHAR(191) PRIMARY KEY,
    chat_id VARCHAR(191) DEFAULT NULL,
    username VARCHAR(191) DEFAULT NULL,
    first_name VARCHAR(191) DEFAULT NULL,
    is_admin TINYINT(1) NOT NULL DEFAULT 0,
    permissions JSON DEFAULT NULL,
    state VARCHAR(64) DEFAULT NULL,
    state_payload JSON DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS admin_passkeys (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    credential_id VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name VARCHAR(100) NOT NULL,
    public_key_spki TEXT NOT NULL,
    algorithm INT NOT NULL,
    sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    transports JSON DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL DEFAULT NULL,
    UNIQUE KEY uq_admin_passkey_credential (credential_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS telegram_channels (
    chat_id VARCHAR(191) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    username VARCHAR(191) DEFAULT NULL,
    bot_status VARCHAR(64) DEFAULT NULL,
    can_post TINYINT(1) NOT NULL DEFAULT 0,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    last_seen_at DATETIME NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS max_channels (
    chat_id VARCHAR(191) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    chat_type VARCHAR(64) DEFAULT NULL,
    bot_status VARCHAR(64) DEFAULT NULL,
    can_post TINYINT(1) NOT NULL DEFAULT 1,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    last_seen_at DATETIME NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS delivery_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    dedupe_key CHAR(64) NOT NULL,
    platform ENUM('telegram','max') NOT NULL,
    chat_id VARCHAR(191) NOT NULL,
    created_at DATETIME NOT NULL,
    KEY idx_dedupe (dedupe_key, created_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS inbound_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    platform ENUM('telegram','max') NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    source_chat_id VARCHAR(191) DEFAULT NULL,
    source_user_id VARCHAR(191) DEFAULT NULL,
    payload_json JSON DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_inbound_platform_created (platform, created_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS bot_event_receipts (
    platform ENUM('telegram','max') NOT NULL,
    event_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    state ENUM('processing','completed','failed') NOT NULL DEFAULT 'processing',
    lease_token CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    lease_until DATETIME DEFAULT NULL,
    last_error VARCHAR(191) DEFAULT NULL,
    result_json JSON DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (platform, event_id),
    KEY idx_bot_event_receipt_cleanup (updated_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS bot_ingress_events (
    ingress_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    platform ENUM('telegram','max') NOT NULL,
    event_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    actor_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    payload_json JSON NOT NULL,
    state ENUM('queued','processing','completed','failed','terminal') NOT NULL DEFAULT 'queued',
    next_attempt_at DATETIME DEFAULT NULL,
    lease_token CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    lease_until DATETIME DEFAULT NULL,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    last_error VARCHAR(191) DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (platform, event_id),
    UNIQUE KEY uq_bot_ingress_order (ingress_id),
    KEY idx_bot_ingress_actor_order (platform, actor_key, ingress_id, state),
    KEY idx_bot_ingress_retry (platform, state, next_attempt_at, lease_until),
    KEY idx_bot_ingress_cleanup (updated_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS app_schema_migrations (
    migration_key VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS relay_source_events (
    queue_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    platform ENUM('telegram','max') NOT NULL,
    chat_id VARCHAR(191) NOT NULL,
    event_id CHAR(64) NOT NULL,
    job_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    message_ids JSON NOT NULL,
    group_id VARCHAR(191) DEFAULT NULL,
    payload_json JSON NOT NULL,
    routing_json JSON DEFAULT NULL,
    state ENUM('queued','processing','completed','failed','terminal') NOT NULL DEFAULT 'queued',
    next_attempt_at DATETIME DEFAULT NULL,
    lease_token CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    lease_until DATETIME DEFAULT NULL,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    last_error VARCHAR(191) DEFAULT NULL,
    terminal_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (platform, chat_id, event_id),
    UNIQUE KEY uq_relay_source_order (queue_id),
    UNIQUE KEY uq_relay_source_job (platform, chat_id, job_key),
    KEY idx_relay_source_channel_order (platform, chat_id, created_at, queue_id, state),
    KEY idx_relay_source_retry (platform, state, next_attempt_at, lease_until),
    KEY idx_relay_source_cleanup (updated_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS relay_outbound_operations (
    id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    target_platform ENUM('telegram','max') NOT NULL,
    target_chat_id VARCHAR(191) NOT NULL,
    operation_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'whole',
    source_platform ENUM('telegram','max') NOT NULL,
    source_chat_id VARCHAR(191) NOT NULL,
    source_event_id CHAR(64) NOT NULL,
    state ENUM('pending','sending','completed','failed','uncertain') NOT NULL DEFAULT 'pending',
    lease_token CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    lease_until DATETIME DEFAULT NULL,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 1,
    last_error VARCHAR(191) DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_relay_outbound_target
      (source_platform, source_chat_id, source_event_id, target_platform, target_chat_id, operation_key),
    KEY idx_relay_outbound_pending (target_platform, target_chat_id, state, created_at),
    KEY idx_relay_outbound_operation_cleanup (updated_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS relay_outbound_messages (
    platform ENUM('telegram','max') NOT NULL,
    chat_id VARCHAR(191) NOT NULL,
    message_id VARCHAR(191) NOT NULL,
    operation_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_platform ENUM('telegram','max') NOT NULL,
    source_chat_id VARCHAR(191) NOT NULL,
    source_event_id CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (platform, chat_id, message_id),
    KEY idx_relay_outbound_operation (operation_id),
    KEY idx_relay_outbound_cleanup (created_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS linked_accounts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    telegram_user_id VARCHAR(191) DEFAULT NULL,
    max_user_id VARCHAR(191) DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_linked_telegram (telegram_user_id),
    UNIQUE KEY uq_linked_max (max_user_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS account_link_codes (
    code CHAR(6) PRIMARY KEY,
    account_id BIGINT UNSIGNED NOT NULL,
    source_platform ENUM('telegram','max') NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_link_expiry (expires_at),
    CONSTRAINT fk_link_code_account FOREIGN KEY (account_id) REFERENCES linked_accounts(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await db(`CREATE TABLE IF NOT EXISTS account_channels (
    account_id BIGINT UNSIGNED NOT NULL,
    platform ENUM('telegram','max') NOT NULL,
    chat_id VARCHAR(191) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, platform, chat_id),
    KEY idx_account_channel_lookup (platform, chat_id),
    UNIQUE KEY uq_account_channel_platform_chat (platform, chat_id),
    CONSTRAINT fk_account_channel_owner FOREIGN KEY (account_id) REFERENCES linked_accounts(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  if (!(await columnExists("telegram_users", "is_admin"))) {
    await db("ALTER TABLE telegram_users ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0");
  }
  if (!(await columnExists("telegram_users", "permissions"))) {
    await db("ALTER TABLE telegram_users ADD COLUMN permissions JSON DEFAULT NULL");
  }
  if (!(await columnExists("max_users", "is_admin"))) {
    await db("ALTER TABLE max_users ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0");
  }
  if (!(await columnExists("max_users", "permissions"))) {
    await db("ALTER TABLE max_users ADD COLUMN permissions JSON DEFAULT NULL");
  }
  if (!(await columnExists("bridges", "account_id"))) {
    await db("ALTER TABLE bridges ADD COLUMN account_id BIGINT UNSIGNED DEFAULT NULL, ADD KEY idx_bridge_account (account_id)");
  }
  if (!(await columnExists("linked_accounts", "is_blocked"))) {
    await db("ALTER TABLE linked_accounts ADD COLUMN is_blocked TINYINT(1) NOT NULL DEFAULT 0");
  }
  if (!(await columnExists("linked_accounts", "telegram_blocked"))) {
    await db("ALTER TABLE linked_accounts ADD COLUMN telegram_blocked TINYINT(1) NOT NULL DEFAULT 0");
  }
  if (!(await columnExists("linked_accounts", "max_blocked"))) {
    await db("ALTER TABLE linked_accounts ADD COLUMN max_blocked TINYINT(1) NOT NULL DEFAULT 0");
  }
  if (!(await columnExists("linked_accounts", "block_reason"))) {
    await db("ALTER TABLE linked_accounts ADD COLUMN block_reason VARCHAR(500) DEFAULT NULL");
  }
  if (!(await columnExists("account_channels", "is_blocked"))) {
    await db("ALTER TABLE account_channels ADD COLUMN is_blocked TINYINT(1) NOT NULL DEFAULT 0");
  }
  if (!(await columnExists("account_channels", "block_reason"))) {
    await db("ALTER TABLE account_channels ADD COLUMN block_reason VARCHAR(500) DEFAULT NULL");
  }
  if (!(await columnExists("bot_event_receipts", "result_json"))) {
    await db("ALTER TABLE bot_event_receipts ADD COLUMN result_json JSON DEFAULT NULL AFTER last_error");
  }
  if (!(await columnExists("bot_ingress_events", "ingress_id"))) {
    await db(`ALTER TABLE bot_ingress_events
      ADD COLUMN ingress_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT FIRST,
      ADD UNIQUE KEY uq_bot_ingress_order (ingress_id)`);
  }
  if (!(await columnExists("bot_ingress_events", "actor_key"))) {
    await db(`ALTER TABLE bot_ingress_events
      ADD COLUMN actor_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL
      AFTER event_id`);
  }
  while (true) {
    const legacyIngress = await db(
      `SELECT platform, event_id, event_type, payload_json
       FROM bot_ingress_events WHERE actor_key IS NULL LIMIT 200`
    );
    if (!legacyIngress.length) break;
    for (const row of legacyIngress) {
      await db(
        `UPDATE bot_ingress_events SET actor_key = ?
         WHERE platform = ? AND event_id = ? AND actor_key IS NULL`,
        [
          botIngressActorKey(
            String(row.platform),
            String(row.event_type),
            parseJsonObject(row.payload_json)
          ),
          String(row.platform),
          String(row.event_id)
        ]
      );
    }
  }
  if (await columnIsNullable("bot_ingress_events", "actor_key")) {
    await db(`ALTER TABLE bot_ingress_events
      MODIFY COLUMN actor_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL`);
  }
  if (!(await indexExists("bot_ingress_events", "idx_bot_ingress_actor_order"))) {
    await db(`ALTER TABLE bot_ingress_events
      ADD KEY idx_bot_ingress_actor_order (platform, actor_key, ingress_id, state)`);
  }
  if (!(await indexExists("account_channels", "uq_account_channel_platform_chat"))) {
    const ownershipConflicts = await db(
      `SELECT platform, chat_id, COUNT(DISTINCT account_id) AS owner_count,
              GROUP_CONCAT(DISTINCT account_id ORDER BY account_id SEPARATOR ',') AS account_ids
       FROM account_channels
       GROUP BY platform, chat_id
       HAVING COUNT(DISTINCT account_id) > 1
       ORDER BY platform, chat_id
       LIMIT 20`
    );
    if (ownershipConflicts.length) {
      const conflicts = ownershipConflicts.map((row) => ({
        platform: String(row.platform),
        chatId: String(row.chat_id),
        accountIds: String(row.account_ids || "")
      }));
      debugLog("account_channel_ownership_migration_conflict", { conflicts });
      const error = new Error(
        `Невозможно включить уникальное владение каналами: найдены конфликты ${JSON.stringify(conflicts)}. `
        + "Сначала вручную определите владельца каждого канала и удалите конфликтующие привязки."
      );
      error.code = "ACCOUNT_CHANNEL_OWNERSHIP_CONFLICT";
      throw error;
    }
    await db("ALTER TABLE account_channels ADD UNIQUE KEY uq_account_channel_platform_chat (platform, chat_id)");
  }
  if (!(await columnExists("relay_source_events", "group_id"))) {
    await db("ALTER TABLE relay_source_events ADD COLUMN group_id VARCHAR(191) DEFAULT NULL AFTER message_ids");
  }
  if (!(await columnExists("relay_source_events", "queue_id"))) {
    await db(`ALTER TABLE relay_source_events
      ADD COLUMN queue_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT FIRST,
      ADD UNIQUE KEY uq_relay_source_order (queue_id)`);
  }
  if (!(await indexExists("relay_source_events", "idx_relay_source_channel_order"))) {
    await db(`ALTER TABLE relay_source_events
      ADD KEY idx_relay_source_channel_order (platform, chat_id, created_at, queue_id, state)`);
  }
  if (!(await columnExists("relay_source_events", "job_key"))) {
    await db("ALTER TABLE relay_source_events ADD COLUMN job_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL AFTER event_id");
  }
  await db("UPDATE relay_source_events SET job_key = event_id WHERE job_key IS NULL");
  if (await columnIsNullable("relay_source_events", "job_key")) {
    await db("ALTER TABLE relay_source_events MODIFY COLUMN job_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL");
  }
  if (!(await columnExists("relay_source_events", "payload_json"))) {
    await db("ALTER TABLE relay_source_events ADD COLUMN payload_json JSON DEFAULT NULL AFTER group_id");
  }
  if (!(await columnExists("relay_source_events", "routing_json"))) {
    await db("ALTER TABLE relay_source_events ADD COLUMN routing_json JSON DEFAULT NULL AFTER payload_json");
  }
  if (!(await columnExists("relay_source_events", "next_attempt_at"))) {
    await db("ALTER TABLE relay_source_events ADD COLUMN next_attempt_at DATETIME DEFAULT NULL AFTER state");
  }
  if (!(await columnExists("relay_source_events", "lease_token"))) {
    await db("ALTER TABLE relay_source_events ADD COLUMN lease_token CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL AFTER next_attempt_at");
  }
  if (!(await columnExists("relay_source_events", "terminal_at"))) {
    await db("ALTER TABLE relay_source_events ADD COLUMN terminal_at DATETIME DEFAULT NULL AFTER last_error");
  }
  const relaySourceStateType = await columnType("relay_source_events", "state");
  if (!relaySourceStateType.includes("'queued'") || !relaySourceStateType.includes("'terminal'")) {
    await db(`ALTER TABLE relay_source_events
      MODIFY COLUMN state ENUM('queued','processing','completed','failed','terminal')
      NOT NULL DEFAULT 'queued'`);
  }
  await migrateLegacyRelayEventsWithoutPayload();
  if (await columnIsNullable("relay_source_events", "payload_json")) {
    await db("ALTER TABLE relay_source_events MODIFY COLUMN payload_json JSON NOT NULL");
  }
  await reconcileAllLegacyBridgeRoutes();
  await backfillRelayRoutingSnapshots();
  if (await columnIsNullable("relay_source_events", "routing_json")) {
    await db("ALTER TABLE relay_source_events MODIFY COLUMN routing_json JSON NOT NULL");
  }
  if (!(await indexExists("relay_source_events", "idx_relay_source_retry"))) {
    await db(`ALTER TABLE relay_source_events
      ADD KEY idx_relay_source_retry (platform, state, next_attempt_at, lease_until)`);
  }
  if (!(await indexExists("relay_source_events", "uq_relay_source_job"))) {
    await db(`ALTER TABLE relay_source_events
      ADD UNIQUE KEY uq_relay_source_job (platform, chat_id, job_key)`);
  }
  if (!(await columnExists("relay_outbound_operations", "lease_token"))) {
    await db(`ALTER TABLE relay_outbound_operations
      ADD COLUMN lease_token CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL
      AFTER state`);
  }
  if (!(await columnExists("relay_outbound_operations", "operation_key"))) {
    await db(`ALTER TABLE relay_outbound_operations
      ADD COLUMN operation_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin
      NOT NULL DEFAULT 'whole' AFTER target_chat_id`);
  }
  const outboundStateType = await columnType("relay_outbound_operations", "state");
  if (!outboundStateType.includes("'sending'") || !outboundStateType.includes("'uncertain'")) {
    await db(`ALTER TABLE relay_outbound_operations
      MODIFY COLUMN state ENUM('pending','sending','completed','failed','uncertain')
      NOT NULL DEFAULT 'pending'`);
  }
  const outboundUniqueColumns = [
    "source_platform",
    "source_chat_id",
    "source_event_id",
    "target_platform",
    "target_chat_id",
    "operation_key"
  ];
  const currentOutboundUniqueColumns = await indexColumns(
    "relay_outbound_operations",
    "uq_relay_outbound_target"
  );
  if (currentOutboundUniqueColumns.join("|") !== outboundUniqueColumns.join("|")) {
    if (currentOutboundUniqueColumns.length) {
      await db("ALTER TABLE relay_outbound_operations DROP INDEX uq_relay_outbound_target");
    }
    await db(`ALTER TABLE relay_outbound_operations
      ADD UNIQUE KEY uq_relay_outbound_target
      (source_platform, source_chat_id, source_event_id, target_platform, target_chat_id, operation_key)`);
  }
  await migrateLegacyPendingOutboundOperations();
  await migrateLegacyCompletedOutboundTargets();
}

function legacyRouteId(accountId, sourcePlatform, sourceChatId) {
  const prefix = sourcePlatform === "telegram" ? "route_tg_" : "route_max_";
  const digest = crypto
    .createHash("sha256")
    .update(`${accountId}:${String(sourceChatId)}`)
    .digest("hex")
    .slice(0, 24);
  return `${prefix}${digest}`;
}

async function reconcileLegacyBridgeRoute(
  query,
  accountId,
  sourcePlatform,
  sourceChatId,
  {
    removeWhenMissing = false,
    preserveExistingState = false,
    removedLegacyTargetChatIds = []
  } = {}
) {
  if (!accountId || !["telegram", "max"].includes(sourcePlatform)) return null;
  const sourceColumn = sourcePlatform === "telegram" ? "telegram_chat_id" : "max_chat_id";
  const targetColumn = sourcePlatform === "telegram" ? "max_chat_id" : "telegram_chat_id";
  const targetPlatform = sourcePlatform === "telegram" ? "max" : "telegram";
  const directions = sourcePlatform === "telegram"
    ? ["tg_to_max", "both"]
    : ["max_to_tg", "both"];
  const bridgeRows = await query(
    `SELECT id, enabled, ${targetColumn} AS target_chat_id
     FROM bridges
     WHERE account_id = ? AND ${sourceColumn} = ? AND direction IN (?, ?)
     ORDER BY id
     FOR UPDATE`,
    [accountId, String(sourceChatId), ...directions]
  );
  const existingRoutes = await query(
    `SELECT id, enabled FROM repost_routes
     WHERE account_id = ? AND source_platform = ? AND source_chat_id = ?
     LIMIT 1 FOR UPDATE`,
    [accountId, sourcePlatform, String(sourceChatId)]
  );
  const existingRoute = existingRoutes[0] || null;
  const existingRouteId = existingRoute?.id ? String(existingRoute.id) : null;
  // Older releases already materialized legacy bridges into this table. Once a
  // route exists it is the authoritative, user-visible configuration: trying
  // to infer whether any target came from a bridge or the universal editor can
  // silently resurrect or delete a deliberate choice.
  if (existingRoute && preserveExistingState) return existingRouteId;
  if (!bridgeRows.length) {
    if (removeWhenMissing && existingRouteId) {
      const removedTargets = [...new Set(removedLegacyTargetChatIds
        .map((value) => String(value || ""))
        .filter(Boolean))];
      for (const targetChatId of removedTargets) {
        await query(
          `DELETE FROM repost_route_targets
           WHERE route_id = ? AND platform = ? AND chat_id = ?`,
          [existingRouteId, targetPlatform, targetChatId]
        );
      }
      const remaining = await query(
        "SELECT COUNT(*) AS total FROM repost_route_targets WHERE route_id = ?",
        [existingRouteId]
      );
      if (Number(remaining[0]?.total || 0) === 0 && removedTargets.length) {
        await query("DELETE FROM repost_routes WHERE id = ?", [existingRouteId]);
      }
    }
    return null;
  }

  const legacyTargets = [...new Set(bridgeRows
    .map((row) => String(row.target_chat_id || ""))
    .filter(Boolean))];
  const activeTargets = [...new Set(bridgeRows
    .filter((row) => Boolean(row.enabled))
    .map((row) => String(row.target_chat_id || ""))
    .filter(Boolean))];
  let routeId = existingRouteId;
  if (!routeId && activeTargets.length) {
    routeId = await upsertRepostRoute(
      query,
      legacyRouteId(accountId, sourcePlatform, sourceChatId),
      accountId,
      sourcePlatform,
      sourceChatId,
      true
    );
  }
  if (!routeId) return null;

  const activeTargetSet = new Set(activeTargets);
  for (const targetChatId of legacyTargets) {
    if (activeTargetSet.has(targetChatId)) continue;
    await query(
      `DELETE FROM repost_route_targets
       WHERE route_id = ? AND platform = ? AND chat_id = ?`,
      [routeId, targetPlatform, targetChatId]
    );
  }
  for (const targetChatId of activeTargets) {
    await query(
      "INSERT IGNORE INTO repost_route_targets (route_id, platform, chat_id) VALUES (?, ?, ?)",
      [routeId, targetPlatform, targetChatId]
    );
  }
  const remaining = await query(
    "SELECT COUNT(*) AS total FROM repost_route_targets WHERE route_id = ?",
    [routeId]
  );
  const hasTargets = Number(remaining[0]?.total || 0) > 0;
  const desiredEnabled = activeTargets.length
    ? (existingRoute && preserveExistingState ? Boolean(existingRoute.enabled) : true)
    : (hasTargets ? Boolean(existingRoute?.enabled) : false);
  await query(
    "UPDATE repost_routes SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    [desiredEnabled ? 1 : 0, routeId]
  );
  return routeId;
}

async function reconcileAllLegacyBridgeRoutes() {
  const migrationKey = "legacy_bridges_to_routes_v2";
  await withDbTransaction(async (query) => {
    const applied = await query(
      "SELECT migration_key FROM app_schema_migrations WHERE migration_key = ? LIMIT 1 FOR UPDATE",
      [migrationKey]
    );
    if (applied[0]) return;
    const sources = await query(`
      SELECT DISTINCT account_id, 'telegram' AS source_platform,
             telegram_chat_id AS source_chat_id
      FROM bridges
      WHERE account_id IS NOT NULL AND direction IN ('tg_to_max','both')
      UNION
      SELECT DISTINCT account_id, 'max' AS source_platform,
             max_chat_id AS source_chat_id
      FROM bridges
      WHERE account_id IS NOT NULL AND direction IN ('max_to_tg','both')
      ORDER BY account_id, source_platform, source_chat_id
    `);
    for (const source of sources) {
      await reconcileLegacyBridgeRoute(
        query,
        source.account_id,
        String(source.source_platform),
        String(source.source_chat_id),
        { preserveExistingState: true }
      );
    }
    await query(
      "INSERT INTO app_schema_migrations (migration_key) VALUES (?)",
      [migrationKey]
    );
  });
}

async function backfillRelayRoutingSnapshots() {
  const completed = await db(
    `UPDATE relay_source_events
     SET routing_json = JSON_ARRAY()
     WHERE routing_json IS NULL AND state = 'completed'`
  );
  let activeRows = 0;
  let emptySnapshots = 0;
  while (true) {
    const rows = await db(
      `SELECT platform, chat_id, event_id
       FROM relay_source_events
       WHERE routing_json IS NULL
       ORDER BY created_at, platform, chat_id, event_id
       LIMIT 200`
    );
    if (!rows.length) break;
    for (const row of rows) {
      const outcome = await withDbTransaction(async (query) => {
        const locked = await query(
          `SELECT state
           FROM relay_source_events
           WHERE platform = ? AND chat_id = ? AND event_id = ?
             AND routing_json IS NULL
           LIMIT 1 FOR UPDATE`,
          [String(row.platform), String(row.chat_id), String(row.event_id)]
        );
        if (!locked[0]) return null;
        const routes = String(locked[0].state) === "completed"
          ? []
          : await relayRoutesSnapshot(String(row.platform), String(row.chat_id), query);
        const result = await query(
          `UPDATE relay_source_events
           SET routing_json = ?, updated_at = UTC_TIMESTAMP()
           WHERE platform = ? AND chat_id = ? AND event_id = ?
             AND routing_json IS NULL`,
          [
            JSON.stringify(routes),
            String(row.platform),
            String(row.chat_id),
            String(row.event_id)
          ]
        );
        return Number(result.affectedRows) === 1 ? routes.length : null;
      });
      if (outcome == null) continue;
      activeRows += 1;
      if (outcome === 0) emptySnapshots += 1;
    }
  }
  const completedRows = Number(completed.affectedRows || 0);
  if (completedRows || activeRows) {
    debugLog("relay_routing_snapshot_migrated", {
      completedRows,
      activeRows,
      emptySnapshots
    });
  }
}

async function migrateLegacyRelayEventsWithoutPayload() {
  const quarantined = await db(
    `UPDATE relay_source_events
     SET state = 'terminal', next_attempt_at = NULL,
         lease_token = NULL, lease_until = NULL,
         payload_json = JSON_OBJECT('legacy_payload_missing', 1),
         routing_json = COALESCE(routing_json, JSON_ARRAY()),
         last_error = 'legacy_payload_missing', terminal_at = UTC_TIMESTAMP(),
         updated_at = UTC_TIMESTAMP()
     WHERE payload_json IS NULL AND state NOT IN ('completed','terminal')`
  );
  const inert = await db(
    `UPDATE relay_source_events
     SET payload_json = JSON_OBJECT('legacy_payload_missing', 1),
         routing_json = COALESCE(routing_json, JSON_ARRAY()),
         updated_at = UTC_TIMESTAMP()
     WHERE payload_json IS NULL`
  );
  if (Number(quarantined.affectedRows || 0) || Number(inert.affectedRows || 0)) {
    debugLog("legacy_relay_payloads_quarantined", {
      quarantinedRows: Number(quarantined.affectedRows || 0),
      inertRows: Number(inert.affectedRows || 0)
    });
  }
}

async function migrateLegacyPendingOutboundOperations() {
  const migrationKey = "outbound_sending_state_v1";
  await withDbTransaction(async (query) => {
    const applied = await query(
      "SELECT migration_key FROM app_schema_migrations WHERE migration_key = ? LIMIT 1 FOR UPDATE",
      [migrationKey]
    );
    if (applied[0]) return;
    const result = await query(
      `UPDATE relay_outbound_operations
       SET state = 'uncertain', lease_token = NULL, lease_until = NULL,
           last_error = 'legacy_pending_delivery_uncertain', updated_at = UTC_TIMESTAMP()
       WHERE state = 'pending'`
    );
    await query(
      "INSERT INTO app_schema_migrations (migration_key) VALUES (?)",
      [migrationKey]
    );
    if (Number(result.affectedRows || 0) > 0) {
      debugLog("legacy_pending_outbound_marked_uncertain", {
        rows: Number(result.affectedRows)
      });
    }
  });
}

async function migrateLegacyCompletedOutboundTargets() {
  const migrationKey = "legacy_completed_outbound_targets_v1";
  await withDbTransaction(async (query) => {
    const applied = await query(
      "SELECT migration_key FROM app_schema_migrations WHERE migration_key = ? LIMIT 1 FOR UPDATE",
      [migrationKey]
    );
    if (applied[0]) return;
    const rows = await query(
      `SELECT DISTINCT source_platform, source_chat_id, source_event_id,
              target_platform, target_chat_id
       FROM relay_outbound_operations
       WHERE state = 'completed' AND operation_key = 'whole'
       ORDER BY source_platform, source_chat_id, source_event_id,
                target_platform, target_chat_id`
    );
    let inserted = 0;
    for (const row of rows) {
      const operationId = stableOutboundOperationId({
        sourcePlatform: String(row.source_platform),
        sourceChatId: String(row.source_chat_id),
        sourceEventId: String(row.source_event_id),
        targetPlatform: String(row.target_platform),
        targetChatId: String(row.target_chat_id),
        operationKey: OUTBOUND_TARGET_COMPLETE_KEY
      });
      const result = await query(
        `INSERT IGNORE INTO relay_outbound_operations
           (id, target_platform, target_chat_id, operation_key, source_platform,
            source_chat_id, source_event_id, state, lease_token, lease_until,
            attempt_count, last_error)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', NULL, NULL, 1, NULL)`,
        [
          operationId,
          String(row.target_platform),
          String(row.target_chat_id),
          OUTBOUND_TARGET_COMPLETE_KEY,
          String(row.source_platform),
          String(row.source_chat_id),
          String(row.source_event_id)
        ]
      );
      inserted += Number(result.affectedRows || 0);
    }
    await query(
      "INSERT INTO app_schema_migrations (migration_key) VALUES (?)",
      [migrationKey]
    );
    if (inserted > 0) {
      debugLog("legacy_completed_outbound_targets_migrated", { rows: inserted });
    }
  });
}

function normalizePermissions(input) {
  const allowed = new Set(ADMIN_PERMISSIONS.map((item) => item.key));
  const values = Array.isArray(input) ? input : [];
  return [...new Set(values.map((item) => String(item)).filter((item) => allowed.has(item)))];
}

function parsePermissions(value) {
  if (!value) return [];
  if (Array.isArray(value)) return normalizePermissions(value);
  try {
    return normalizePermissions(JSON.parse(value));
  } catch {
    return [];
  }
}

function parseJsonArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function parseJsonObject(value) {
  if (!value) return {};
  if (typeof value === "object" && !Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

async function linkedAccount(platform, userId, create = true) {
  const column = platform === "max" ? "max_user_id" : "telegram_user_id";
  const id = String(userId || "");
  if (!id) return null;
  let rows = await db(`SELECT * FROM linked_accounts WHERE ${column} = ? LIMIT 1`, [id]);
  if (rows[0] || !create) return rows[0] || null;
  await db(`INSERT IGNORE INTO linked_accounts (${column}) VALUES (?)`, [id]);
  rows = await db(`SELECT * FROM linked_accounts WHERE ${column} = ? LIMIT 1`, [id]);
  return rows[0] || null;
}

async function linkedAccountStatus(platform, userId) {
  const account = await linkedAccount(platform, userId, true);
  const rows = await db(`SELECT a.*,
    tu.first_name AS telegram_name, tu.username AS telegram_username,
    mu.first_name AS max_name, mu.username AS max_username
    FROM linked_accounts a
    LEFT JOIN telegram_users tu ON tu.telegram_user_id = a.telegram_user_id
    LEFT JOIN max_users mu ON mu.max_user_id = a.max_user_id
    WHERE a.id = ? LIMIT 1`, [account.id]);
  return rows[0] || account;
}

function linkedIdentityLabel(name, username, id, html = false) {
  if (!id) return "не связан";
  const visibleName = String(name || "").trim();
  const visibleUsername = String(username || "").trim().replace(/^@/, "");
  const label = `${visibleName || (visibleUsername ? `@${visibleUsername}` : id)} (${id})`;
  return html ? escapeHtml(label) : label;
}

function accountLinkStatusText(account, telegramCustomEmoji = false) {
  const telegramIcon = telegramCustomEmoji ? '<tg-emoji emoji-id="5285350148451344065">💬</tg-emoji>' : "✈️";
  const maxIcon = telegramCustomEmoji ? '<tg-emoji emoji-id="5456166744479533085">💬</tg-emoji>' : "🟣";
  const warning = account.telegram_user_id && account.max_user_id
    ? "\n\nПри замене аккаунта все текущие каналы и настроенные пересылки будут удалены."
    : "";
  return `Связанные аккаунты\n\n${telegramIcon} Telegram: ${linkedIdentityLabel(account.telegram_name, account.telegram_username, account.telegram_user_id, telegramCustomEmoji)}\n${maxIcon} МАКС: ${linkedIdentityLabel(account.max_name, account.max_username, account.max_user_id, telegramCustomEmoji)}${warning}`;
}

async function resetLinkedAccountConfiguration(accountId, query = db) {
  await query("DELETE FROM repost_route_targets WHERE route_id IN (SELECT id FROM repost_routes WHERE account_id = ?)", [accountId]);
  await query("DELETE FROM repost_routes WHERE account_id = ?", [accountId]);
  await query("DELETE FROM bridges WHERE account_id = ?", [accountId]);
  await query("DELETE FROM account_channels WHERE account_id = ? AND is_blocked = 0", [accountId]);
}

async function unlinkMaxAccountFromTelegram(telegramUserId, expectedMaxUserId = undefined) {
  return withDbTransaction((query) => unlinkLinkedAccountCounterpart(
    query,
    "telegram",
    telegramUserId,
    (accountId) => resetLinkedAccountConfiguration(accountId, query),
    expectedMaxUserId
  ));
}

async function unlinkTelegramAccountFromMax(maxUserId, expectedTelegramUserId = undefined) {
  return withDbTransaction((query) => unlinkLinkedAccountCounterpart(
    query,
    "max",
    maxUserId,
    (accountId) => resetLinkedAccountConfiguration(accountId, query),
    expectedTelegramUserId
  ));
}

async function deleteRouteAndReleaseUnusedChannels(routeId, accountId) {
  return withDbTransaction((query) => deleteRouteAndReleaseUnusedChannelsWithQuery(
    query,
    routeId,
    accountId
  ));
}

async function createAccountLinkCode(platform, userId) {
  const column = platform === "max" ? "max_user_id" : "telegram_user_id";
  const normalizedUserId = String(userId || "");
  if (!normalizedUserId) throw new Error("Аккаунт пользователя не найден.");
  return withDbTransaction(async (query) => {
    await query(`INSERT IGNORE INTO linked_accounts (${column}) VALUES (?)`, [normalizedUserId]);
    const rows = await query(
      `SELECT id, is_blocked, telegram_blocked, max_blocked, block_reason
       FROM linked_accounts WHERE ${column} = ? LIMIT 1 FOR UPDATE`,
      [normalizedUserId]
    );
    const account = rows[0];
    const accountId = account?.id;
    if (!accountId) throw new Error("Аккаунт пользователя не найден.");
    const platformBlocked = platform === "max" ? account.max_blocked : account.telegram_blocked;
    if (account.is_blocked || platformBlocked) {
      throw new Error(account.block_reason || "Доступ заблокирован владельцем сервиса.");
    }
    await query("DELETE FROM account_link_codes WHERE expires_at <= NOW()");
    const activeCodes = await query(
      `SELECT code FROM account_link_codes
       WHERE account_id = ? AND source_platform = ? AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
      [accountId, platform]
    );
    if (activeCodes[0]?.code) return String(activeCodes[0].code);
    await query("DELETE FROM account_link_codes WHERE account_id = ?", [accountId]);
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const code = String(crypto.randomInt(100000, 1000000));
      try {
        await query(
          "INSERT INTO account_link_codes (code, account_id, source_platform, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))",
          [code, accountId, platform]
        );
        return code;
      } catch (error) {
        if (error?.code !== "ER_DUP_ENTRY") throw error;
      }
    }
    throw new Error("Не удалось создать код привязки");
  });
}

function otherBotUrl(platform) {
  return platform === "telegram" ? env.MAX_BOT_URL : env.TELEGRAM_BOT_URL;
}

async function consumeAccountLinkCode(platform, userId, code, { receipt = null } = {}) {
  const attemptKey = `${platform}:${userId}`;
  const now = Date.now();
  const attemptState = accountLinkAttempts.get(attemptKey);
  if (attemptState?.blockedUntil > now) {
    const minutes = Math.ceil((attemptState.blockedUntil - now) / 60000);
    return { ok: false, message: `Слишком много неверных кодов. Повторите через ${minutes} мин.` };
  }
  let result;
  try {
    result = await withDbTransaction(async (query) => {
      const outcome = await consumeAccountLinkCodeTransaction(
        query,
        platform,
        userId,
        code,
        (accountId) => resetLinkedAccountConfiguration(accountId, query)
      );
      if (outcome.status === "linked") {
        await persistBotEventResult(query, receipt, {
          action: "consume_link_code",
          ok: true,
          message: "Аккаунты Telegram и МАКС успешно связаны. При замене прежние каналы и пересылки удалены — настройте их заново."
        });
      }
      return outcome;
    });
  } catch (error) {
    if (error?.code === "ER_DUP_ENTRY") {
      return { ok: false, message: "Этот аккаунт уже связан." };
    }
    throw error;
  }
  if (result.status === "invalid") {
    const recent = attemptState && now - attemptState.startedAt < 10 * 60 * 1000
      ? attemptState
      : { count: 0, startedAt: now, blockedUntil: 0 };
    recent.count += 1;
    if (recent.count >= 5) recent.blockedUntil = now + 15 * 60 * 1000;
    accountLinkAttempts.set(attemptKey, recent);
    return { ok: false, message: recent.blockedUntil ? "Слишком много неверных кодов. Ввод заблокирован на 15 минут." : "Код не найден или срок его действия истёк." };
  }
  if (result.status === "wrong_platform") {
    const target = platform === "telegram" ? "МАКС" : "Telegram";
    const url = otherBotUrl(platform);
    return { ok: false, message: `Этот код нужно отправить боту в ${target}.${url ? `\n\n${url}` : ""}` };
  }
  if (result.status === "blocked") {
    return { ok: false, message: result.reason };
  }
  if (result.status === "already_linked") {
    return { ok: false, message: "Новый аккаунт уже связан с другим аккаунтом. Сначала замените или удалите прежнюю связь." };
  }
  if (result.status === "occupied") {
    return { ok: false, message: "Новый аккаунт уже содержит свои каналы или пересылки. Сначала удалите их либо обратитесь к владельцу сервиса." };
  }
  if (result.status !== "linked") throw new Error("Неизвестный результат привязки аккаунта.");
  accountLinkAttempts.delete(attemptKey);
  return { ok: true, message: "Аккаунты Telegram и МАКС успешно связаны. При замене прежние каналы и пересылки удалены — настройте их заново." };
}

async function grantAccountChannel(platform, userId, chatId) {
  return grantAccountChannelOwnership(db, linkedAccount, platform, userId, chatId);
}

async function accountAccess(platform, userId) {
  const account = await linkedAccount(platform, userId, true);
  const platformBlocked = platform === "max" ? account.max_blocked : account.telegram_blocked;
  return {
    account,
    blocked: Boolean(account.is_blocked || platformBlocked),
    reason: account.block_reason || "Доступ заблокирован владельцем сервиса."
  };
}

async function channelsForAccount(platform, userId, channelPlatform) {
  const access = await accountAccess(platform, userId);
  if (access.blocked) return [];
  const table = channelPlatform === "max" ? "max_channels" : "telegram_channels";
  const extra = channelPlatform === "max"
    ? "AND COALESCE(c.chat_type, '') NOT IN ('dialog', 'private')"
    : "AND c.chat_id LIKE '-%'";
  return db(
    `SELECT c.* FROM ${table} c JOIN account_channels ac ON ac.platform = ? AND ac.chat_id = c.chat_id AND ac.account_id = ? WHERE c.is_active = 1 AND ac.is_blocked = 0 ${extra} ORDER BY c.title`,
    [channelPlatform, access.account.id]
  );
}

async function channelChoicesForAccount(platform, userId) {
  const [telegramRows, maxRows] = await Promise.all([
    channelsForAccount(platform, userId, "telegram"),
    channelsForAccount(platform, userId, "max")
  ]);
  return [
    ...telegramRows.map((row) => ({ ...row, platform: "telegram" })),
    ...maxRows.map((row) => ({ ...row, platform: "max" }))
  ];
}

function parseStatePayload(value) {
  if (!value) return {};
  if (typeof value === "object") return value;
  try { return JSON.parse(value); } catch { return {}; }
}

async function assertNoRouteCycle(accountId, currentRouteId, sourcePlatform, sourceChatId, targets, query = db) {
  const rows = await query(`SELECT r.id, r.source_platform, r.source_chat_id, t.platform, t.chat_id
    FROM repost_routes r JOIN repost_route_targets t ON t.route_id = r.id
    WHERE r.account_id = ? AND r.id <> ?`, [accountId, String(currentRouteId || "")]);
  const graph = new Map();
  const addEdge = (from, to) => {
    const edges = graph.get(from) || new Set();
    edges.add(to);
    graph.set(from, edges);
  };
  for (const row of rows) addEdge(`${row.source_platform}:${row.source_chat_id}`, `${row.platform}:${row.chat_id}`);
  const source = `${sourcePlatform}:${sourceChatId}`;
  for (const target of targets) addEdge(source, `${target.platform}:${target.chat_id}`);
  const createsLongCycle = (node, depth = 0, seen = new Set()) => {
    if (seen.has(node)) return false;
    seen.add(node);
    return [...(graph.get(node) || [])].some((next) => {
      if (next === source) {
        // A direct reciprocal route (A -> B together with B -> A) is the
        // supported synchronous mode. Longer cycles can fan out indefinitely.
        return depth > 0;
      }
      return createsLongCycle(next, depth + 1, new Set(seen));
    });
  };
  for (const target of targets) {
    if (createsLongCycle(`${target.platform}:${target.chat_id}`)) {
      const error = new Error("Нельзя сохранить циклическую пересылку через три и более каналов.");
      error.statusCode = 400;
      throw error;
    }
  }
}

async function assertRoutingChannelsAvailable(query, accountId, sourcePlatform, sourceChatId, targets) {
  const channels = [
    { platform: sourcePlatform, chat_id: String(sourceChatId) },
    ...targets.map((target) => ({
      platform: String(target.platform),
      chat_id: String(target.chat_id)
    }))
  ];
  for (const channel of channels) {
    const rows = await query(
      `SELECT ac.chat_id
       FROM account_channels ac
       LEFT JOIN telegram_channels tc
         ON ac.platform = 'telegram' AND tc.chat_id = ac.chat_id
       LEFT JOIN max_channels mc
         ON ac.platform = 'max' AND mc.chat_id = ac.chat_id
       WHERE ac.account_id = ? AND ac.platform = ? AND ac.chat_id = ?
         AND ac.is_blocked = 0
         AND ((ac.platform = 'telegram' AND tc.is_active = 1 AND tc.can_post = 1)
           OR (ac.platform = 'max' AND mc.is_active = 1 AND mc.can_post = 1))
       LIMIT 1 FOR UPDATE`,
      [accountId, channel.platform, channel.chat_id]
    );
    if (!rows[0]) {
      throw new Error("Канал не принадлежит этому пользователю, заблокирован или бот потерял право публикации.");
    }
  }
}

function proposedRouteId(_accountId, sourcePlatform, _sourceChatId) {
  return `route_${sourcePlatform}_${crypto.randomBytes(12).toString("hex")}`;
}

async function routeIdForSource(accountId, sourcePlatform, sourceChatId, query = db) {
  const rows = await query(
    `SELECT id FROM repost_routes
     WHERE account_id = ? AND source_platform = ? AND source_chat_id = ?
     LIMIT 1`,
    [accountId, sourcePlatform, String(sourceChatId)]
  );
  return rows[0]?.id ? String(rows[0].id) : null;
}

async function lockLinkedAccountForRouting(query, accountId) {
  const rows = await query(
    `SELECT id, is_blocked, telegram_blocked, max_blocked, block_reason
     FROM linked_accounts WHERE id = ? LIMIT 1 FOR UPDATE`,
    [accountId]
  );
  if (!rows[0]) throw new Error("Аккаунт владельца пересылки не найден.");
  return rows[0];
}

async function saveUniversalRouteForUser(
  platform,
  userId,
  sourcePlatform,
  sourceChatId,
  targets,
  { receipt = null, responseKind = "callback" } = {}
) {
  const access = await accountAccess(platform, userId);
  if (access.blocked) throw new Error(access.reason);
  let savedRouteId = "";
  let savedTargetCount = 0;
  await withDbTransaction(async (query) => {
    const lockedAccount = await lockLinkedAccountForRouting(query, access.account.id);
    const platformBlocked = platform === "max"
      ? lockedAccount.max_blocked
      : lockedAccount.telegram_blocked;
    if (lockedAccount.is_blocked || platformBlocked) {
      throw new Error(lockedAccount.block_reason || "Доступ заблокирован владельцем сервиса.");
    }
    const userTable = platform === "max" ? "max_users" : "telegram_users";
    const userIdColumn = platform === "max" ? "max_user_id" : "telegram_user_id";
    const userRows = await query(
      `SELECT state, state_payload FROM ${userTable}
       WHERE ${userIdColumn} = ? LIMIT 1 FOR UPDATE`,
      [String(userId)]
    );
    const draftState = String(userRows[0]?.state || "");
    if (receipt && !["route_targets", "route_targets_reply"].includes(draftState)) {
      const error = new Error("Выбор получателей устарел. Откройте создание пересылки заново.");
      error.code = "ROUTE_TARGET_STATE_STALE";
      throw error;
    }
    const draft = receipt ? parseStatePayload(userRows[0]?.state_payload) : null;
    const finalSourcePlatform = String(draft?.source_platform || sourcePlatform || "");
    const finalSourceChatId = String(draft?.source_chat_id || sourceChatId || "");
    const rawTargets = receipt
      ? (draft?.targets || []).map((key) => {
          const [targetPlatform, ...chatIdParts] = String(key).split(":");
          return { platform: targetPlatform, chat_id: chatIdParts.join(":") };
        })
      : targets;
    const sourceKey = `${finalSourcePlatform}:${finalSourceChatId}`;
    const cleanTargets = [...new Map((Array.isArray(rawTargets) ? rawTargets : [])
      .map((target) => ({
        platform: String(target?.platform || ""),
        chat_id: String(target?.chat_id || "")
      }))
      .filter((target) => ["telegram", "max"].includes(target.platform)
        && target.chat_id
        && `${target.platform}:${target.chat_id}` !== sourceKey)
      .map((target) => [`${target.platform}:${target.chat_id}`, target])).values()];
    if (!["telegram", "max"].includes(finalSourcePlatform)
      || !finalSourceChatId
      || !cleanTargets.length) {
      const error = new Error("Выберите доступный источник и хотя бы один канал-получатель.");
      error.code = "ROUTE_SELECTION_INVALID";
      throw error;
    }
    await assertRoutingChannelsAvailable(
      query,
      access.account.id,
      finalSourcePlatform,
      finalSourceChatId,
      cleanTargets
    );
    const proposedId = proposedRouteId(
      access.account.id,
      finalSourcePlatform,
      finalSourceChatId
    );
    const currentRouteId = await routeIdForSource(
      access.account.id,
      finalSourcePlatform,
      finalSourceChatId,
      query
    ) || proposedId;
    await assertNoRouteCycle(
      access.account.id,
      currentRouteId,
      finalSourcePlatform,
      finalSourceChatId,
      cleanTargets,
      query
    );
    await retireLegacyRouteSource(
      query,
      access.account.id,
      finalSourcePlatform,
      finalSourceChatId
    );
    savedRouteId = await upsertRepostRoute(
      query,
      proposedId,
      access.account.id,
      finalSourcePlatform,
      finalSourceChatId,
      true
    );
    await syncRepostRouteTargets(query, savedRouteId, cleanTargets);
    savedTargetCount = cleanTargets.length;
    await query(
      `UPDATE ${userTable} SET state = NULL, state_payload = NULL WHERE ${userIdColumn} = ?`,
      [String(userId)]
    );
    await persistBotEventResult(query, receipt, {
      action: "save_route",
      route_id: savedRouteId,
      target_count: savedTargetCount,
      response_kind: responseKind
    });
  });
  return { routeId: savedRouteId, targetCount: savedTargetCount };
}

async function bridgesForAccount(platform, userId) {
  const access = await accountAccess(platform, userId);
  if (access.blocked) return [];
  return db(`
    SELECT b.*, tg.title AS telegram_title, mx.title AS max_title
    FROM bridges b
    LEFT JOIN telegram_channels tg ON tg.chat_id = b.telegram_chat_id
    LEFT JOIN max_channels mx ON mx.chat_id = b.max_chat_id
    WHERE b.account_id = ?
    ORDER BY b.created_at DESC
  `, [access.account.id]);
}

async function routesForAccount(platform, userId) {
  const access = await accountAccess(platform, userId);
  if (access.blocked) return [];
  const routes = await db(`SELECT r.*,
    CASE WHEN r.source_platform = 'telegram' THEN tc.title ELSE mc.title END AS source_title
    FROM repost_routes r
    LEFT JOIN telegram_channels tc ON r.source_platform = 'telegram' AND tc.chat_id = r.source_chat_id
    LEFT JOIN max_channels mc ON r.source_platform = 'max' AND mc.chat_id = r.source_chat_id
    WHERE r.account_id = ? ORDER BY r.updated_at DESC`, [access.account.id]);
  for (const route of routes) {
    route.targets = await db(`SELECT t.platform, t.chat_id,
      CASE WHEN t.platform = 'telegram' THEN tc.title ELSE mc.title END AS title
      FROM repost_route_targets t
      LEFT JOIN telegram_channels tc ON t.platform = 'telegram' AND tc.chat_id = t.chat_id
      LEFT JOIN max_channels mc ON t.platform = 'max' AND mc.chat_id = t.chat_id
      WHERE t.route_id = ? ORDER BY t.id`, [route.id]);
  }
  return routes;
}

async function assertOwnedRoute(platform, userId, routeId) {
  return ownedRouteAccount(db, accountAccess, platform, userId, routeId);
}

async function assertOwnedBridge(platform, userId, bridgeId) {
  const access = await accountAccess(platform, userId);
  if (access.blocked) throw new Error(access.reason);
  const rows = await db("SELECT id FROM bridges WHERE id = ? AND account_id = ? LIMIT 1", [String(bridgeId), access.account.id]);
  if (!rows[0]) throw new Error("Связка не найдена или принадлежит другому пользователю.");
  return access.account;
}

async function assertAccountChannel(accountId, platform, chatId) {
  const rows = await db(
    "SELECT 1 FROM account_channels WHERE account_id = ? AND platform = ? AND chat_id = ? AND is_blocked = 0 LIMIT 1",
    [accountId, platform, String(chatId)]
  );
  if (!rows[0]) throw new Error("Канал не принадлежит этому пользователю или заблокирован.");
}

async function rememberInboundEvent(platform, eventType, sourceChatId, sourceUserId, payload) {
  await db(
    `INSERT INTO inbound_events (platform, event_type, source_chat_id, source_user_id, payload_json)
     VALUES (?, ?, ?, ?, ?)`,
    [
      platform,
      eventType,
      sourceChatId ? String(sourceChatId) : null,
      sourceUserId ? String(sourceUserId) : null,
      JSON.stringify(payload ?? {})
    ]
  );
}

async function claimBotEventReceipt(platform, eventType, eventId) {
  const normalizedEventId = String(eventId || "").trim();
  if (!normalizedEventId) return { claimed: true, key: null };
  const key = hashKey([platform, eventType, normalizedEventId]);
  const leaseToken = crypto.randomUUID();
  return withDbTransaction(async (query) => {
    const result = await query(
      `INSERT IGNORE INTO bot_event_receipts
         (platform, event_id, event_type, state, lease_token, lease_until, last_error)
       VALUES (?, ?, ?, 'processing', ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), NULL)`,
      [platform, key, eventType, leaseToken, RELAY_EVENT_LEASE_SECONDS]
    );
    if (Number(result.affectedRows) === 1) {
      return {
        claimed: true,
        key,
        leaseToken,
        platform,
        result: null,
        lastError: null,
        disposition: "claimed"
      };
    }
    const rows = await query(
      `SELECT state, result_json, last_error,
              CASE WHEN lease_until IS NOT NULL AND lease_until > UTC_TIMESTAMP() THEN 1 ELSE 0 END AS lease_active
       FROM bot_event_receipts
       WHERE platform = ? AND event_id = ?
       FOR UPDATE`,
      [platform, key]
    );
    const existing = rows[0];
    if (existing?.state === "completed") {
      return { claimed: false, key, leaseToken: null, platform, result: parseJsonObject(existing.result_json), lastError: existing.last_error || null, disposition: "completed" };
    }
    if (existing?.state === "processing" && Number(existing.lease_active) === 1) {
      return { claimed: false, key, leaseToken: null, platform, result: parseJsonObject(existing.result_json), lastError: existing.last_error || null, disposition: "in_progress" };
    }
    // Preserve the previous delivery disposition until replay finishes. Clearing
    // it while claiming would lose a guaranteed 429 retry if this worker exits
    // after the claim but before it reaches the provider call.
    await query(
      `UPDATE bot_event_receipts
       SET event_type = ?, state = 'processing', lease_token = ?,
            lease_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
            updated_at = UTC_TIMESTAMP()
       WHERE platform = ? AND event_id = ?`,
      [eventType, leaseToken, RELAY_EVENT_LEASE_SECONDS, platform, key]
    );
    return {
      claimed: true,
      key,
      leaseToken,
      platform,
      result: parseJsonObject(existing?.result_json),
      lastError: existing?.last_error || null,
      disposition: "reclaimed"
    };
  });
}

async function persistBotEventResult(query, receipt, result) {
  if (!receipt?.key) return;
  const update = await query(
    `UPDATE bot_event_receipts
     SET result_json = ?, updated_at = UTC_TIMESTAMP()
     WHERE platform = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?`,
    [JSON.stringify(result ?? {}), receipt.platform, receipt.key, receipt.leaseToken]
  );
  if (Number(update.affectedRows) !== 1) {
    const error = new Error("Bot event receipt lease was lost before committing the action result.");
    error.code = "BOT_EVENT_LEASE_LOST";
    throw error;
  }
}

async function finishBotEventReceipt(receipt, platform, state, error = null) {
  if (!receipt?.key) return true;
  const result = await db(
    `UPDATE bot_event_receipts
     SET state = ?, lease_token = NULL, lease_until = NULL,
         last_error = ?, updated_at = UTC_TIMESTAMP()
     WHERE platform = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?`,
    [
      state,
      error ? relayFailureCode(error) : null,
      platform,
      receipt.key,
      receipt.leaseToken
    ]
  );
  return Number(result.affectedRows) === 1;
}

async function renewBotEventReceipt(receipt) {
  if (!receipt?.key) return true;
  const result = await db(
    `UPDATE bot_event_receipts
     SET lease_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
         updated_at = UTC_TIMESTAMP()
     WHERE platform = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?`,
    [RELAY_EVENT_LEASE_SECONDS, receipt.platform, receipt.key, receipt.leaseToken]
  );
  return Number(result.affectedRows) === 1;
}

async function assertBotEventReceipt(receipt) {
  if (!receipt?.key) return;
  const rows = await db(
    `SELECT 1 FROM bot_event_receipts
     WHERE platform = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?
       AND lease_until > UTC_TIMESTAMP()
     LIMIT 1`,
    [receipt.platform, receipt.key, receipt.leaseToken]
  );
  if (!rows[0]) {
    const error = new Error("Bot event receipt lease was lost.");
    error.code = "BOT_EVENT_LEASE_LOST";
    throw error;
  }
}

async function withBotEventReceiptHeartbeat(receipt, work) {
  if (!receipt?.key) return work();
  return withRelayLeaseHeartbeat({
    leaseSeconds: RELAY_EVENT_LEASE_SECONDS,
    renewLease: () => renewBotEventReceipt(receipt),
    assertLease: () => assertBotEventReceipt(receipt),
    work,
    onRenewError: (error) => debugLog("bot_event_receipt_renew_failed", {
      platform: receipt.platform,
      eventId: receipt.key,
      code: relayFailureCode(error)
    }),
    leaseLostCode: "BOT_EVENT_LEASE_LOST",
    leaseLostMessage: "Bot event receipt lease was lost."
  });
}

function telegramIngressEventType(update) {
  if (update?.my_chat_member) return "my_chat_member";
  if (update?.callback_query) return "callback_query";
  if (update?.message) return "message";
  if (update?.edited_channel_post) return "edited_channel_post";
  if (update?.channel_post) return "channel_post";
  return "unknown";
}

function maxIngressEventType(update) {
  return String(update?.update_type || update?.type || update?.event || update?.update?.type || "unknown");
}

function maxIngressProviderEventId(body, eventType) {
  const callback = extractMaxCallback(body);
  const message = extractMaxMessage(body);
  return String(
    callback?.callback_id
    || callback?.id
    || maxMessageId(message)
    || body?.update_id
    || body?.event_id
    || `${eventType}:${JSON.stringify(body || {})}`
  );
}

function botIngressActorKey(platform, eventType, payload) {
  let actorId = "";
  if (platform === "telegram") {
    actorId = String(
      payload?.callback_query?.from?.id
      || payload?.message?.from?.id
      || payload?.my_chat_member?.from?.id
      || payload?.channel_post?.chat?.id
      || payload?.edited_channel_post?.chat?.id
      || ""
    );
  } else {
    const callback = extractMaxCallback(payload);
    const user = extractMaxUser(payload) || {};
    const message = extractMaxMessage(payload);
    const chat = extractMaxChat(payload) || {};
    actorId = String(
      callback?.user_id
      || callback?.user?.user_id
      || callback?.user?.id
      || user?.user_id
      || user?.id
      || maxEventChatId(payload, chat, message, callback)
      || ""
    );
  }
  return hashKey([platform, actorId ? `actor:${actorId}` : `event:${eventType}`]);
}

async function enqueueBotIngressEvent(platform, eventType, providerEventId, payload) {
  const key = hashKey([platform, eventType, String(providerEventId || "")]);
  const actorKey = botIngressActorKey(platform, eventType, payload);
  const enqueueLockName = `gitreposted:bi:${platform}:${actorKey.slice(0, 32)}`;
  const connection = await pool.getConnection();
  let lockAcquired = false;
  let result;
  try {
    const [lockRows] = await connection.execute("SELECT GET_LOCK(?, 5) AS acquired", [enqueueLockName]);
    lockAcquired = Number(lockRows[0]?.acquired) === 1;
    if (!lockAcquired) {
      const error = new Error("Bot ingress actor queue is busy; webhook must be retried.");
      error.code = "BOT_INGRESS_ENQUEUE_BUSY";
      error.statusCode = 503;
      throw error;
    }
    [result] = await connection.execute(
      `INSERT IGNORE INTO bot_ingress_events
         (platform, event_id, actor_key, event_type, payload_json, state, next_attempt_at,
          lease_token, lease_until, attempt_count, last_error)
       VALUES (?, ?, ?, ?, ?, 'queued', UTC_TIMESTAMP(), NULL, NULL, 0, NULL)`,
      [platform, key, actorKey, eventType, JSON.stringify(payload ?? {})]
    );
  } finally {
    if (lockAcquired) {
      try {
        await connection.execute("SELECT RELEASE_LOCK(?)", [enqueueLockName]);
      } catch (error) {
        debugLog("bot_ingress_enqueue_unlock_failed", {
          platform,
          actorKey,
          code: relayFailureCode(error)
        });
      }
    }
    connection.release();
  }
  void runBotIngressWorker(platform);
  return {
    eventId: key,
    queued: Number(result.affectedRows) === 1
  };
}

async function claimNextBotIngressEvent(platform) {
  await cleanupRelayIdempotencyRecords();
  const leaseToken = crypto.randomUUID();
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.execute(
      `SELECT candidate.event_id, candidate.event_type,
              candidate.payload_json, candidate.attempt_count
       FROM bot_ingress_events candidate
       WHERE candidate.platform = ?
          AND (
            (candidate.state IN ('queued','failed')
              AND candidate.next_attempt_at IS NOT NULL
              AND candidate.next_attempt_at <= UTC_TIMESTAMP())
            OR (candidate.state = 'processing'
              AND (candidate.lease_until IS NULL OR candidate.lease_until <= UTC_TIMESTAMP()))
          )
         AND NOT EXISTS (
           SELECT 1 FROM bot_ingress_events earlier
           WHERE earlier.platform = candidate.platform
             AND earlier.actor_key = candidate.actor_key
             AND earlier.ingress_id < candidate.ingress_id
             AND earlier.state NOT IN ('completed','terminal')
         )
       ORDER BY candidate.ingress_id
       LIMIT 1 FOR UPDATE SKIP LOCKED`,
      [platform]
    );
    const row = rows[0];
    if (!row) {
      await connection.commit();
      return null;
    }
    if (Number(row.attempt_count || 0) >= RELAY_RETRY_POLICY.maxAttempts) {
      await connection.execute(
        `UPDATE bot_ingress_events
         SET state = 'terminal', next_attempt_at = NULL,
             lease_token = NULL, lease_until = NULL,
             last_error = COALESCE(last_error, 'retry_limit_exhausted'),
             updated_at = UTC_TIMESTAMP()
         WHERE platform = ? AND event_id = ?`,
        [platform, row.event_id]
      );
      await connection.commit();
      return {
        terminalized: true,
        eventId: String(row.event_id),
        attemptCount: Number(row.attempt_count || 0)
      };
    }
    const attemptCount = Number(row.attempt_count || 0) + 1;
    await connection.execute(
      `UPDATE bot_ingress_events
       SET state = 'processing', next_attempt_at = NULL,
           lease_token = ?, lease_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
           attempt_count = ?, last_error = NULL, updated_at = UTC_TIMESTAMP()
       WHERE platform = ? AND event_id = ?`,
      [leaseToken, RELAY_EVENT_LEASE_SECONDS, attemptCount, platform, row.event_id]
    );
    await connection.commit();
    return {
      platform,
      eventId: String(row.event_id),
      eventType: String(row.event_type),
      payload: parseJsonObject(row.payload_json),
      leaseToken,
      attemptCount
    };
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
    }
    throw error;
  } finally {
    connection.release();
  }
}

async function finishBotIngressEvent(job, error = null) {
  const terminal = Boolean(error)
    && relayRetryDisposition(job.attemptCount, RELAY_RETRY_POLICY) === "terminal";
  const retryAfterSeconds = error ? relayRetryAfterSeconds(error) : 0;
  const retryDelay = error && !terminal
    ? Math.max(retryAfterSeconds, relayRetryDelaySeconds(job.attemptCount, RELAY_RETRY_POLICY))
    : null;
  const state = error ? (terminal ? "terminal" : "failed") : "completed";
  const result = await db(
    `UPDATE bot_ingress_events
     SET state = ?,
         next_attempt_at = CASE WHEN ? IS NULL THEN NULL
           ELSE DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND) END,
         lease_token = NULL, lease_until = NULL, last_error = ?,
         updated_at = UTC_TIMESTAMP()
     WHERE platform = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?`,
    [
      state,
      retryDelay,
      retryDelay || 0,
      error ? relayFailureCode(error) : null,
      job.platform,
      job.eventId,
      job.leaseToken
    ]
  );
  return {
    updated: Number(result.affectedRows) === 1,
    state,
    retryDelay
  };
}

async function renewBotIngressLease(job) {
  const result = await db(
    `UPDATE bot_ingress_events
     SET lease_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
         updated_at = UTC_TIMESTAMP()
     WHERE platform = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?`,
    [RELAY_EVENT_LEASE_SECONDS, job.platform, job.eventId, job.leaseToken]
  );
  return Number(result.affectedRows) === 1;
}

async function assertBotIngressLease(job) {
  const rows = await db(
    `SELECT 1 FROM bot_ingress_events
     WHERE platform = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?
       AND lease_until > UTC_TIMESTAMP()
     LIMIT 1`,
    [job.platform, job.eventId, job.leaseToken]
  );
  if (!rows[0]) {
    const error = new Error("Bot ingress lease was lost.");
    error.code = "BOT_INGRESS_LEASE_LOST";
    throw error;
  }
}

const botIngressWorkerRunning = { telegram: false, max: false };

async function runBotIngressWorker(platform) {
  if (!workersEnabled(env) || !platformEnabled(env, platform)) return;
  if (botIngressWorkerRunning[platform]) return;
  botIngressWorkerRunning[platform] = true;
  try {
    for (let processed = 0; processed < 25; processed += 1) {
      const job = await claimNextBotIngressEvent(platform);
      if (!job) break;
      if (job.terminalized) {
        debugLog("bot_ingress_terminal", {
          platform,
          eventId: job.eventId,
          attempt: job.attemptCount
        });
        continue;
      }
      try {
        await withRelayLeaseHeartbeat({
          leaseSeconds: RELAY_EVENT_LEASE_SECONDS,
          renewLease: () => renewBotIngressLease(job),
          assertLease: () => assertBotIngressLease(job),
          work: async () => {
            if (platform === "telegram") await queueTelegramUpdate(job.payload);
            else await handleMaxEvent(job.payload);
          },
          onRenewError: (error) => debugLog("bot_ingress_renew_failed", {
            platform,
            eventId: job.eventId,
            code: relayFailureCode(error)
          }),
          leaseLostCode: "BOT_INGRESS_LEASE_LOST",
          leaseLostMessage: "Bot ingress lease was lost."
        });
        await finishBotIngressEvent(job);
      } catch (error) {
        const outcome = await finishBotIngressEvent(job, error);
        debugLog("bot_ingress_failed", {
          platform,
          eventId: job.eventId,
          attempt: job.attemptCount,
          state: outcome.state,
          retryDelaySeconds: outcome.retryDelay,
          code: relayFailureCode(error)
        });
      }
    }
  } catch (error) {
    debugLog("bot_ingress_worker_failed", { platform, code: relayFailureCode(error) });
  } finally {
    botIngressWorkerRunning[platform] = false;
  }
}

function startBotIngressWorkers() {
  if (!workersEnabled(env)) return;
  void runBotIngressWorker("telegram");
  void runBotIngressWorker("max");
  const timer = setInterval(() => {
    void runBotIngressWorker("telegram");
    void runBotIngressWorker("max");
  }, RELAY_RETRY_POLICY.pollMilliseconds);
  timer.unref?.();
}

async function rememberTelegramUser(userId, username, firstName) {
  await db(
    `INSERT INTO telegram_users (telegram_user_id, username, first_name, is_admin, permissions)
     VALUES (?, ?, ?, 0, JSON_ARRAY())
     ON DUPLICATE KEY UPDATE username = VALUES(username), first_name = VALUES(first_name)`,
    [String(userId), username || null, firstName || null]
  );
}

async function rememberMaxUser(userId, chatId, username, firstName) {
  await db(
    `INSERT INTO max_users (max_user_id, chat_id, username, first_name, is_admin, permissions)
     VALUES (?, ?, ?, ?, 0, JSON_ARRAY())
     ON DUPLICATE KEY UPDATE chat_id = VALUES(chat_id), username = VALUES(username), first_name = VALUES(first_name)`,
    [String(userId), chatId ? String(chatId) : null, username || null, firstName || null]
  );
}

async function setTelegramState(userId, state, payload = null) {
  await db("UPDATE telegram_users SET state = ?, state_payload = ? WHERE telegram_user_id = ?", [state, payload ? JSON.stringify(payload) : null, String(userId)]);
}

async function getTelegramUser(userId) {
  const rows = await db("SELECT * FROM telegram_users WHERE telegram_user_id = ? LIMIT 1", [String(userId)]);
  return rows[0] || null;
}

async function setMaxState(userId, state, payload = null) {
  await db("UPDATE max_users SET state = ?, state_payload = ? WHERE max_user_id = ?", [state, payload ? JSON.stringify(payload) : null, String(userId)]);
}

async function getMaxUser(userId) {
  const rows = await db("SELECT * FROM max_users WHERE max_user_id = ? LIMIT 1", [String(userId)]);
  return rows[0] || null;
}

async function mutateTelegramReplyState(
  userId,
  expectedState,
  mutate,
  { receipt = null } = {}
) {
  return withDbTransaction(async (query) => {
    const rows = await query(
      `SELECT state, state_payload FROM telegram_users
       WHERE telegram_user_id = ? LIMIT 1 FOR UPDATE`,
      [String(userId)]
    );
    const current = rows[0];
    if (String(current?.state || "") !== String(expectedState)) {
      const error = new Error("Выбор каналов устарел. Откройте создание пересылки заново.");
      error.code = "ROUTE_TARGET_STATE_STALE";
      throw error;
    }
    const next = mutate(parseStatePayload(current.state_payload));
    if (!next || !Object.prototype.hasOwnProperty.call(next, "state")) {
      throw new TypeError("Telegram reply-state mutation must return a state.");
    }
    const nextPayload = next.payload ?? null;
    await query(
      `UPDATE telegram_users SET state = ?, state_payload = ?
       WHERE telegram_user_id = ?`,
      [
        next.state || null,
        nextPayload ? JSON.stringify(nextPayload) : null,
        String(userId)
      ]
    );
    await persistBotEventResult(query, receipt, {
      action: "telegram_reply_state",
      state: next.state || null,
      state_payload: nextPayload
    });
    return { state: next.state || null, payload: nextPayload };
  });
}

async function mutateRouteTargetState(platform, userId, key, action) {
  const table = platform === "max" ? "max_users" : "telegram_users";
  const idColumn = platform === "max" ? "max_user_id" : "telegram_user_id";
  return withDbTransaction(async (query) => {
    const rows = await query(
      `SELECT state, state_payload FROM ${table}
       WHERE ${idColumn} = ? LIMIT 1 FOR UPDATE`,
      [String(userId)]
    );
    const current = rows[0];
    if (current?.state !== "route_targets") {
      const error = new Error("Выбор получателей устарел. Откройте создание пересылки заново.");
      error.code = "ROUTE_TARGET_STATE_STALE";
      throw error;
    }
    const payload = parseStatePayload(current.state_payload);
    const targets = new Set(payload.targets || []);
    if (action === "add") targets.add(key);
    else targets.delete(key);
    const nextPayload = { ...payload, targets: [...targets] };
    await query(
      `UPDATE ${table} SET state_payload = ? WHERE ${idColumn} = ?`,
      [JSON.stringify(nextPayload), String(userId)]
    );
    return nextPayload;
  });
}

async function upsertTelegramChannel(chatId, title, username, botStatus = null, canPost = 0) {
  const isActive = canPost && ["administrator", "creator"].includes(String(botStatus || "")) ? 1 : 0;
  await db(
    `INSERT INTO telegram_channels (chat_id, title, username, bot_status, can_post, is_active, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE title = VALUES(title), username = VALUES(username), bot_status = VALUES(bot_status), can_post = VALUES(can_post), is_active = VALUES(is_active), last_seen_at = UTC_TIMESTAMP()`,
    [String(chatId), title || String(chatId), username || null, botStatus || null, canPost ? 1 : 0, isActive]
  );
  channelPublishingAccessCache.delete(`telegram:${chatId}`);
}

async function rememberTelegramChannelActivity(chatId, title, username) {
  await db(
    `INSERT INTO telegram_channels
       (chat_id, title, username, bot_status, can_post, is_active, last_seen_at)
     VALUES (?, ?, ?, NULL, 0, 0, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE title = VALUES(title), username = VALUES(username),
       last_seen_at = UTC_TIMESTAMP()`,
    [String(chatId), title || String(chatId), username || null]
  );
}

function normalizeTelegramChatId(chatId) {
  const value = String(chatId || "").trim();
  if (!value) return "";
  if (value.startsWith("-100")) return value;
  if (/^\d+$/.test(value)) return `-100${value}`;
  return value;
}

function legacyTelegramChatId(chatId) {
  const value = normalizeTelegramChatId(chatId);
  return value.startsWith("-100") ? value.slice(4) : value;
}

async function telegramLegacyAliasExists(legacy) {
  const directRows = await db(
    `SELECT 1 AS present FROM (
     SELECT 1 FROM account_channels
       WHERE platform = 'telegram' AND chat_id = ?
     UNION ALL
     SELECT 1 FROM repost_routes
       WHERE source_platform = 'telegram' AND source_chat_id = ?
     UNION ALL
     SELECT 1 FROM repost_route_targets
       WHERE platform = 'telegram' AND chat_id = ?
     UNION ALL
     SELECT 1 FROM bridges WHERE telegram_chat_id = ?
     UNION ALL
     SELECT 1 FROM telegram_channels WHERE chat_id = ?
     UNION ALL
     SELECT 1 FROM relay_source_events
       WHERE platform = 'telegram' AND chat_id = ?
         AND state IN ('queued','processing','failed','terminal')
     UNION ALL
     SELECT 1 FROM relay_outbound_operations
       WHERE target_platform = 'telegram' AND target_chat_id = ?
     ) AS legacy_aliases
     LIMIT 1`,
    [legacy, legacy, legacy, legacy, legacy, legacy, legacy]
  );
  if (directRows.length) return true;
  const snapshotRows = await db(
    `SELECT 1
     FROM relay_source_events
     WHERE state IN ('queued','processing','failed','terminal')
       AND JSON_SEARCH(routing_json, 'one', ?, NULL, '$[*].chat_id') IS NOT NULL
     LIMIT 1`,
    [legacy]
  );
  if (snapshotRows.length) return true;
  // A previous release could have normalized the operation row but left its
  // diagnostic source identity in the outbound-message ledger.
  const messageRows = await db(
    `SELECT 1 FROM relay_outbound_messages
     WHERE platform = 'telegram' AND chat_id = ?
     LIMIT 1`,
    [legacy]
  );
  return messageRows.length > 0;
}

async function reconcileTelegramBridgeIds(chatId, { force = false } = {}) {
  const normalized = normalizeTelegramChatId(chatId);
  const legacy = legacyTelegramChatId(chatId);
  if (!normalized || !legacy || normalized === legacy) return;
  if (!force && reconciledTelegramChannelIds.has(normalized)) return;
  if (!(await telegramLegacyAliasExists(legacy))) {
    reconciledTelegramChannelIds.add(normalized);
    return;
  }
  await withDbTransaction(async (query) => {
    const ownership = await query(
      `SELECT account_id, chat_id, is_blocked, block_reason
       FROM account_channels
       WHERE platform = 'telegram' AND chat_id IN (?, ?)
       ORDER BY chat_id FOR UPDATE`,
      [legacy, normalized]
    );
    const legacyOwner = ownership.find((row) => String(row.chat_id) === legacy);
    const normalizedOwner = ownership.find((row) => String(row.chat_id) === normalized);
    if (
      legacyOwner
      && normalizedOwner
      && String(legacyOwner.account_id) !== String(normalizedOwner.account_id)
    ) {
      debugLog("telegram_chat_id_reconcile_owner_conflict", {
        legacy,
        normalized,
        legacyAccountId: String(legacyOwner.account_id),
        normalizedAccountId: String(normalizedOwner.account_id)
      });
      const error = new Error(
        "Telegram-канал уже закреплён за двумя разными аккаунтами; требуется ручное разрешение владельца."
      );
      error.code = "TELEGRAM_CHANNEL_ALIAS_OWNER_CONFLICT";
      throw error;
    }
    if (legacyOwner && normalizedOwner) {
      await query(
        `UPDATE account_channels
         SET is_blocked = GREATEST(is_blocked, ?),
             block_reason = COALESCE(block_reason, ?)
         WHERE account_id = ? AND platform = 'telegram' AND chat_id = ?`,
        [
          legacyOwner.is_blocked ? 1 : 0,
          legacyOwner.block_reason || null,
          normalizedOwner.account_id,
          normalized
        ]
      );
      await query(
        "DELETE FROM account_channels WHERE account_id = ? AND platform = 'telegram' AND chat_id = ?",
        [legacyOwner.account_id, legacy]
      );
    } else if (legacyOwner) {
      await query(
        `UPDATE account_channels SET chat_id = ?
         WHERE account_id = ? AND platform = 'telegram' AND chat_id = ?`,
        [normalized, legacyOwner.account_id, legacy]
      );
    }

    const legacyRoutes = await query(
      `SELECT id, account_id FROM repost_routes
       WHERE source_platform = 'telegram' AND source_chat_id = ?
       FOR UPDATE`,
      [legacy]
    );
    for (const route of legacyRoutes) {
      const matching = await query(
        `SELECT id FROM repost_routes
         WHERE account_id = ? AND source_platform = 'telegram' AND source_chat_id = ?
         LIMIT 1 FOR UPDATE`,
        [route.account_id, normalized]
      );
      if (matching[0]) {
        debugLog("telegram_chat_id_reconcile_route_conflict", {
          legacy,
          normalized,
          legacyRouteId: String(route.id),
          normalizedRouteId: String(matching[0].id),
          accountId: String(route.account_id)
        });
        const error = new Error(
          "Для старого и нового Telegram ID существуют разные маршруты; объедините их вручную."
        );
        error.code = "TELEGRAM_ROUTE_ALIAS_CONFLICT";
        throw error;
      }
      await query(
        "UPDATE repost_routes SET source_chat_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [normalized, route.id]
      );
    }
    const legacyTargets = await query(
      `SELECT id, route_id FROM repost_route_targets
       WHERE platform = 'telegram' AND chat_id = ?
       ORDER BY id FOR UPDATE`,
      [legacy]
    );
    for (const target of legacyTargets) {
      const matching = await query(
        `SELECT id FROM repost_route_targets
         WHERE route_id = ? AND platform = 'telegram' AND chat_id = ?
         LIMIT 1 FOR UPDATE`,
        [target.route_id, normalized]
      );
      if (matching[0]) {
        debugLog("telegram_chat_id_reconcile_target_conflict", {
          legacy,
          normalized,
          legacyTargetId: String(target.id),
          normalizedTargetId: String(matching[0].id),
          routeId: String(target.route_id)
        });
        const error = new Error(
          "Маршрут одновременно содержит старый и новый Telegram ID; исправьте цели вручную."
        );
        error.code = "TELEGRAM_ROUTE_TARGET_ALIAS_CONFLICT";
        throw error;
      }
      await query(
        `UPDATE repost_route_targets
         SET chat_id = ? WHERE id = ? AND route_id = ?`,
        [normalized, target.id, target.route_id]
      );
    }
    const relaySnapshots = await query(
      `SELECT platform, chat_id, event_id, routing_json
       FROM relay_source_events
       WHERE state IN ('queued','failed','terminal')
         AND routing_json IS NOT NULL
         AND JSON_SEARCH(routing_json, 'one', ?, NULL, '$[*].chat_id') IS NOT NULL
       ORDER BY created_at, platform, chat_id, event_id
       FOR UPDATE`
      , [legacy]
    );
    for (const relay of relaySnapshots) {
      const routes = parseJsonArray(relay.routing_json);
      let changed = false;
      const normalizedRoutes = routes.map((target) => {
        if (String(target?.platform) !== "telegram"
          || String(target?.chat_id) !== legacy) {
          return target;
        }
        changed = true;
        return { ...target, chat_id: normalized };
      });
      if (!changed) continue;
      await query(
        `UPDATE relay_source_events SET routing_json = ?, updated_at = UTC_TIMESTAMP()
         WHERE platform = ? AND chat_id = ? AND event_id = ?`,
        [
          JSON.stringify(normalizedRoutes),
          String(relay.platform),
          String(relay.chat_id),
          String(relay.event_id)
        ]
      );
    }
    await query(
      `UPDATE bridges SET telegram_chat_id = ?, updated_at = CURRENT_TIMESTAMP
       WHERE telegram_chat_id = ?`,
      [normalized, legacy]
    );
    const outboundOperations = await query(
      `SELECT id, source_platform, source_chat_id, source_event_id,
              target_platform, target_chat_id, operation_key
       FROM relay_outbound_operations
       WHERE target_platform = 'telegram' AND target_chat_id = ?
       ORDER BY id FOR UPDATE`,
      [legacy]
    );
    for (const operation of outboundOperations) {
      const sourceChatId = String(operation.source_chat_id);
      const targetChatId = operation.target_platform === "telegram"
        && String(operation.target_chat_id) === legacy
        ? normalized
        : String(operation.target_chat_id);
      const matching = await query(
        `SELECT id FROM relay_outbound_operations
         WHERE source_platform = ? AND source_chat_id = ? AND source_event_id = ?
           AND target_platform = ? AND target_chat_id = ? AND operation_key = ?
           AND id <> ?
         LIMIT 1 FOR UPDATE`,
        [
          operation.source_platform,
          sourceChatId,
          operation.source_event_id,
          operation.target_platform,
          targetChatId,
          operation.operation_key,
          operation.id
        ]
      );
      if (matching[0]) {
        const error = new Error(
          "Для старого и нового Telegram ID существуют разные записи доставки; требуется ручная сверка."
        );
        error.code = "TELEGRAM_OUTBOUND_ALIAS_CONFLICT";
        throw error;
      }
      await query(
        `UPDATE relay_outbound_operations
         SET source_chat_id = ?, target_chat_id = ?, updated_at = UTC_TIMESTAMP()
         WHERE id = ?`,
        [sourceChatId, targetChatId, operation.id]
      );
    }
    const outboundMessages = await query(
      `SELECT platform, chat_id, message_id, operation_id,
              source_platform, source_chat_id, source_event_id
       FROM relay_outbound_messages
       WHERE platform = 'telegram' AND chat_id IN (?, ?)
       ORDER BY message_id, chat_id FOR UPDATE`,
      [legacy, normalized]
    );
    for (const message of outboundMessages.filter((row) => String(row.chat_id) === legacy)) {
      const matching = outboundMessages.find((row) => (
        String(row.chat_id) === normalized
        && String(row.message_id) === String(message.message_id)
      ));
      if (matching && (
        String(matching.operation_id) !== String(message.operation_id)
        || String(matching.source_platform) !== String(message.source_platform)
        || String(matching.source_chat_id) !== String(message.source_chat_id)
        || String(matching.source_event_id) !== String(message.source_event_id)
      )) {
        const error = new Error(
          "Для старого и нового Telegram ID существуют разные записи исходящего сообщения; требуется ручная сверка."
        );
        error.code = "TELEGRAM_OUTBOUND_MESSAGE_ALIAS_CONFLICT";
        throw error;
      }
      if (matching) {
        await query(
          `DELETE FROM relay_outbound_messages
           WHERE platform = 'telegram' AND chat_id = ? AND message_id = ?`,
          [legacy, message.message_id]
        );
      } else {
        await query(
          `UPDATE relay_outbound_messages SET chat_id = ?
           WHERE platform = 'telegram' AND chat_id = ? AND message_id = ?`,
          [normalized, legacy, message.message_id]
        );
      }
    }
    const channelRows = await query(
      `SELECT chat_id, title, username, bot_status, can_post, is_active
       FROM telegram_channels WHERE chat_id IN (?, ?) ORDER BY chat_id FOR UPDATE`,
      [legacy, normalized]
    );
    const legacyChannel = channelRows.find((row) => String(row.chat_id) === legacy);
    const normalizedChannel = channelRows.find((row) => String(row.chat_id) === normalized);
    if (legacyChannel && normalizedChannel) {
      await query("DELETE FROM telegram_channels WHERE chat_id = ?", [legacy]);
    } else if (legacyChannel) {
      await query(
        "UPDATE telegram_channels SET chat_id = ? WHERE chat_id = ?",
        [normalized, legacy]
      );
    }
  });
  reconciledTelegramChannelIds.add(normalized);
}

async function upsertMaxChannel(chatId, title, chatType = null, botStatus = null) {
  const isActive = ["administrator", "owner"].includes(String(botStatus || "")) ? 1 : 0;
  await db(
    `INSERT INTO max_channels (chat_id, title, chat_type, bot_status, can_post, is_active, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE title = VALUES(title), chat_type = VALUES(chat_type), bot_status = VALUES(bot_status), can_post = VALUES(can_post), is_active = VALUES(is_active), last_seen_at = UTC_TIMESTAMP()`,
    [String(chatId), title || String(chatId), chatType || null, botStatus || null, isActive, isActive]
  );
  channelPublishingAccessCache.delete(`max:${chatId}`);
}

async function rememberMaxChannelActivity(chatId, title, chatType = null) {
  await db(
    `INSERT INTO max_channels
       (chat_id, title, chat_type, bot_status, can_post, is_active, last_seen_at)
     VALUES (?, ?, ?, NULL, 0, 0, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE title = VALUES(title), chat_type = VALUES(chat_type),
       last_seen_at = UTC_TIMESTAMP()`,
    [String(chatId), title || String(chatId), chatType || null]
  );
}

async function fetchMaxChat(chatId) {
  try {
    return await maxApi(`/chats/${encodeURIComponent(String(chatId))}`);
  } catch (error) {
    debugLog("max_fetch_chat_failed", { chatId: String(chatId), message: error.message });
    return null;
  }
}

async function syncMaxChannel(chatId, fallbackTitle = null, fallbackType = null, botStatus = null) {
  const info = await fetchMaxChat(chatId);
  const resolvedChatId = info?.chat_id || chatId;
  const resolvedTitle = info?.title || fallbackTitle || String(chatId);
  const resolvedType = info?.type || fallbackType || null;
  await upsertMaxChannel(resolvedChatId, resolvedTitle, resolvedType, botStatus);
}

async function channelHasPublishingAccess(platform, chatId) {
  const normalizedChatId = String(chatId);
  const cacheKey = `${platform}:${normalizedChatId}`;
  const cached = channelPublishingAccessCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.allowed;
  let allowed = false;
  try {
    if (platform === "telegram") {
      const bot = await getTelegramBotIdentity();
      const member = await tgApi("getChatMember", {
        chat_id: normalizedChatId,
        user_id: bot.id
      });
      allowed = member?.status === "creator"
        || (member?.status === "administrator" && Boolean(member?.can_post_messages));
      await db(
        `UPDATE telegram_channels
         SET bot_status = ?, can_post = ?, is_active = ?, last_seen_at = UTC_TIMESTAMP()
         WHERE chat_id = ?`,
        [member?.status || null, allowed ? 1 : 0, allowed ? 1 : 0, normalizedChatId]
      );
    } else if (platform === "max") {
      const member = await maxApi(`/chats/${encodeURIComponent(normalizedChatId)}/members/me`);
      const permissions = new Set(Array.isArray(member?.permissions) ? member.permissions : []);
      allowed = Boolean(member?.is_owner)
        || (Boolean(member?.is_admin)
          && (permissions.has("write") || permissions.has("post_edit_delete_message")));
      const status = member?.is_owner ? "owner" : member?.is_admin ? "administrator" : "member";
      await db(
        `UPDATE max_channels
         SET bot_status = ?, can_post = ?, is_active = ?, last_seen_at = UTC_TIMESTAMP()
         WHERE chat_id = ?`,
        [status, allowed ? 1 : 0, allowed ? 1 : 0, normalizedChatId]
      );
    } else {
      return false;
    }
  } catch (error) {
    const permanent = /:\s(?:400|403|404)\b/.test(String(error?.message || ""));
    if (!permanent) throw error;
    const table = platform === "max" ? "max_channels" : "telegram_channels";
    await db(
      `UPDATE ${table} SET can_post = 0, is_active = 0, last_seen_at = UTC_TIMESTAMP()
       WHERE chat_id = ?`,
      [normalizedChatId]
    );
    allowed = false;
  }
  channelPublishingAccessCache.set(cacheKey, {
    allowed,
    expiresAt: Date.now() + CHANNEL_ACCESS_CACHE_MS
  });
  if (channelPublishingAccessCache.size > 2000) {
    const oldest = channelPublishingAccessCache.keys().next().value;
    if (oldest !== undefined) channelPublishingAccessCache.delete(oldest);
  }
  return allowed;
}

function forwardedMaxChannel(message) {
  const link = message?.link;
  if (link?.type !== "forward" || !link.chat_id) return null;
  return { chatId: String(link.chat_id) };
}

async function claimForwardedMaxChannel(userId, forwardedChannel) {
  const chatId = String(forwardedChannel.chatId);
  const access = await accountAccess("max", userId);
  assertPublicAccountAccess(access, env.PUBLIC_MAX_ENABLED);
  let botMember = null;
  try {
    botMember = await maxApi(`/chats/${encodeURIComponent(chatId)}/members/me`);
  } catch (error) {
    debugLog("max_bot_member_check_failed", { chatId, message: error.message });
    throw new Error("Канал не добавлен: сначала добавьте бота GitRePosted администратором этого МАКС-канала с правом публикации.");
  }
  const botPermissions = new Set(Array.isArray(botMember?.permissions) ? botMember.permissions : []);
  const botCanPost = botPermissions.has("write") || botPermissions.has("post_edit_delete_message");
  if (!botMember?.is_owner && (!botMember?.is_admin || !botCanPost)) {
    throw new Error("Канал не добавлен: выдайте боту GitRePosted права администратора и публикации в этом МАКС-канале.");
  }
  const chatInfo = await fetchMaxChat(chatId);
  if (!chatInfo || chatInfo.type !== "channel") {
    throw new Error("Канал не добавлен: репост должен быть из МАКС-канала.");
  }
  let adminsResult;
  try {
    adminsResult = await maxApi(`/chats/${encodeURIComponent(chatId)}/members/admins`);
  } catch (error) {
    debugLog("max_administrator_list_failed", { chatId, message: error.message });
    throw new Error("Канал не добавлен: не удалось проверить администраторов МАКС-канала. Проверьте права бота GitRePosted.");
  }
  const admins = Array.isArray(adminsResult?.members) ? adminsResult.members : [];
  const userIsAdmin = admins.some((member) => String(member.user_id) === String(userId) && (member.is_owner || member.is_admin));
  if (!userIsAdmin) {
    throw new Error("Канал не добавлен: ваш аккаунт МАКС должен быть владельцем или администратором канала.");
  }
  const owners = await db(
    "SELECT account_id FROM account_channels WHERE platform = 'max' AND chat_id = ? AND account_id <> ? LIMIT 1",
    [chatId, access.account.id]
  );
  if (owners[0]) throw new Error("Этот МАКС-канал уже закреплён за другим пользователем GitRePosted.");
  await upsertMaxChannel(chatId, chatInfo.title || chatId, chatInfo.type, "administrator");
  await grantAccountChannel("max", userId, chatId);
  return chatInfo.title || chatId;
}

async function telegramChannels() {
  return db("SELECT * FROM telegram_channels WHERE is_active = 1 AND chat_id LIKE '-%' ORDER BY title");
}

async function maxChannels() {
  return db("SELECT * FROM max_channels WHERE is_active = 1 AND COALESCE(chat_type, '') NOT IN ('dialog', 'private') ORDER BY title");
}

async function bridges() {
  return db(`
    SELECT
      b.*,
      tg.title AS telegram_title,
      mx.title AS max_title
    FROM bridges b
    LEFT JOIN telegram_channels tg ON tg.chat_id = b.telegram_chat_id
    LEFT JOIN max_channels mx ON mx.chat_id = b.max_chat_id
    ORDER BY b.created_at DESC
  `);
}

async function bridgeById(id) {
  const rows = await db(`
    SELECT
      b.*,
      tg.title AS telegram_title,
      mx.title AS max_title
    FROM bridges b
    LEFT JOIN telegram_channels tg ON tg.chat_id = b.telegram_chat_id
    LEFT JOIN max_channels mx ON mx.chat_id = b.max_chat_id
    WHERE b.id = ?
    LIMIT 1
  `, [String(id)]);
  return rows[0] || null;
}

async function debugState() {
  const [
    bridgeRows,
    telegramRows,
    maxRows,
    inboundRows,
    relayStateRows,
    uncertainRows,
    quarantinedRows
  ] = await Promise.all([
    db("SELECT id, title, enabled, direction, telegram_chat_id, max_chat_id, created_at, updated_at FROM bridges ORDER BY updated_at DESC LIMIT 100"),
    db("SELECT chat_id, title, username, bot_status, can_post, is_active, last_seen_at, updated_at FROM telegram_channels ORDER BY updated_at DESC LIMIT 100"),
    db("SELECT chat_id, title, chat_type, bot_status, can_post, is_active, last_seen_at, updated_at FROM max_channels ORDER BY updated_at DESC LIMIT 100"),
    db("SELECT platform, event_type, source_chat_id, source_user_id, created_at FROM inbound_events ORDER BY id DESC LIMIT 50"),
    db(`SELECT 'source' AS queue, platform, state, COUNT(*) AS total
        FROM relay_source_events GROUP BY platform, state
        UNION ALL
        SELECT 'outbound' AS queue, target_platform AS platform, state, COUNT(*) AS total
        FROM relay_outbound_operations GROUP BY target_platform, state
        UNION ALL
        SELECT 'ingress' AS queue, platform, state, COUNT(*) AS total
        FROM bot_ingress_events GROUP BY platform, state
        ORDER BY queue, platform, state`),
    db(`SELECT id, source_platform, source_chat_id, source_event_id,
               target_platform, target_chat_id, operation_key, last_error,
               attempt_count, created_at, updated_at
        FROM relay_outbound_operations
        WHERE state = 'uncertain'
        ORDER BY updated_at DESC LIMIT 100`),
    db(`SELECT platform, chat_id, event_id, job_key, message_ids,
               last_error, created_at, updated_at
        FROM relay_source_events
        WHERE state = 'terminal' AND last_error = 'OUTBOUND_ECHO_UNCERTAIN'
        ORDER BY updated_at DESC LIMIT 100`)
  ]);
  return {
    bridges: bridgeRows,
    telegram_channels: telegramRows,
    max_channels: maxRows,
    inbound_events: inboundRows,
    relay_states: relayStateRows,
    uncertain_outbound_operations: uncertainRows,
    quarantined_source_events: quarantinedRows
  };
}

async function resolveUncertainOutboundOperation(operationId, resolution, messageIds = []) {
  const normalizedResolution = String(resolution || "");
  if (!["delivered", "retry"].includes(normalizedResolution)) {
    const error = new Error("resolution должен быть delivered или retry.");
    error.statusCode = 400;
    throw error;
  }
  const normalizedIds = normalizePlatformMessageIds(messageIds);
  if (normalizedResolution === "delivered" && !normalizedIds.length) {
    const error = new Error("Для delivered укажите message_ids из канала назначения.");
    error.statusCode = 400;
    throw error;
  }
  return withDbTransaction(async (query) => {
    const rows = await query(
      `SELECT id, source_platform, source_chat_id, source_event_id,
              target_platform, target_chat_id, operation_key
       FROM relay_outbound_operations
       WHERE id = ? AND state = 'uncertain'
       LIMIT 1 FOR UPDATE`,
      [String(operationId || "")]
    );
    const operation = rows[0];
    if (!operation) {
      const error = new Error("Uncertain-операция не найдена или уже разрешена.");
      error.statusCode = 404;
      throw error;
    }
    if (normalizedResolution === "delivered") {
      for (const messageId of normalizedIds) {
        await query(
          `INSERT IGNORE INTO relay_outbound_messages
             (platform, chat_id, message_id, operation_id,
              source_platform, source_chat_id, source_event_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            operation.target_platform,
            String(operation.target_chat_id),
            messageId,
            operation.id,
            operation.source_platform,
            String(operation.source_chat_id),
            operation.source_event_id
          ]
        );
      }
    }
    await query(
      `UPDATE relay_outbound_operations
       SET state = ?, lease_token = NULL, lease_until = NULL,
           last_error = NULL, updated_at = UTC_TIMESTAMP()
       WHERE id = ? AND state = 'uncertain'`,
      [normalizedResolution === "delivered" ? "completed" : "failed", operation.id]
    );
    if (normalizedResolution === "delivered" && String(operation.operation_key) === "whole") {
      const markerTargetChatId = String(operation.target_platform) === "telegram"
        ? normalizeTelegramChatId(operation.target_chat_id)
        : String(operation.target_chat_id);
      const markerId = stableOutboundOperationId({
        sourcePlatform: String(operation.source_platform),
        sourceChatId: String(operation.source_chat_id),
        sourceEventId: String(operation.source_event_id),
        targetPlatform: String(operation.target_platform),
        targetChatId: markerTargetChatId,
        operationKey: OUTBOUND_TARGET_COMPLETE_KEY
      });
      await query(
        `INSERT INTO relay_outbound_operations
           (id, target_platform, target_chat_id, operation_key, source_platform,
            source_chat_id, source_event_id, state, lease_token, lease_until,
            attempt_count, last_error)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', NULL, NULL, 1, NULL)
         ON DUPLICATE KEY UPDATE state = 'completed', lease_token = NULL,
           lease_until = NULL, last_error = NULL, updated_at = UTC_TIMESTAMP()`,
        [
          markerId,
          String(operation.target_platform),
          markerTargetChatId,
          OUTBOUND_TARGET_COMPLETE_KEY,
          String(operation.source_platform),
          String(operation.source_chat_id),
          String(operation.source_event_id)
        ]
      );
    }
    await query(
      `UPDATE relay_outbound_operations
       SET updated_at = UTC_TIMESTAMP()
       WHERE source_platform = ? AND source_chat_id = ? AND source_event_id = ?`,
      [operation.source_platform, String(operation.source_chat_id), operation.source_event_id]
    );
    await query(
      `UPDATE relay_outbound_messages
       SET created_at = UTC_TIMESTAMP()
       WHERE source_platform = ? AND source_chat_id = ? AND source_event_id = ?`,
      [operation.source_platform, String(operation.source_chat_id), operation.source_event_id]
    );
    await query(
      `UPDATE relay_source_events
       SET state = 'failed', next_attempt_at = UTC_TIMESTAMP(),
           lease_token = NULL, lease_until = NULL, terminal_at = NULL,
           attempt_count = 0, last_error = 'operator_reconciled',
           updated_at = UTC_TIMESTAMP()
       WHERE platform = ? AND chat_id = ? AND event_id = ?
         AND state = 'terminal'`,
      [
        operation.source_platform,
        String(operation.source_chat_id),
        operation.source_event_id
      ]
    );
    const targetChatIds = operation.target_platform === "telegram"
      ? [...new Set([
          String(operation.target_chat_id),
          normalizeTelegramChatId(operation.target_chat_id),
          legacyTelegramChatId(operation.target_chat_id)
        ].filter(Boolean))]
      : [String(operation.target_chat_id)];
    const targetPlaceholders = targetChatIds.map(() => "?").join(",");
    await query(
      `UPDATE relay_source_events
       SET state = 'failed', next_attempt_at = UTC_TIMESTAMP(),
           lease_token = NULL, lease_until = NULL, terminal_at = NULL,
           attempt_count = 0, last_error = 'operator_reconciled',
           updated_at = UTC_TIMESTAMP()
       WHERE platform = ? AND chat_id IN (${targetPlaceholders})
         AND state = 'terminal' AND last_error = 'OUTBOUND_ECHO_UNCERTAIN'`,
      [operation.target_platform, ...targetChatIds]
    );
    return {
      id: String(operation.id),
      resolution: normalizedResolution,
      message_ids: normalizedIds
    };
  });
}

async function adminReconcileTelegramBridgeIds() {
  const rows = await db("SELECT DISTINCT chat_id FROM telegram_channels WHERE is_active = 1");
  for (const row of rows) {
    await reconcileTelegramBridgeIds(row.chat_id, { force: true });
  }
  return bridges();
}

async function adminUpsertMaxChannel(chatId, title, chatType = "channel", botStatus = "member") {
  await upsertMaxChannel(chatId, title, chatType, botStatus);
  return maxChannels();
}

async function adminChannelState() {
  const [telegramRows, maxRows] = await Promise.all([telegramChannels(), maxChannels()]);
  return { telegram: telegramRows, max: maxRows };
}

async function adminBridgeState(page = 1, perPage = 10) {
  const routeRows = await db(`SELECT r.*,
    CASE WHEN r.source_platform = 'telegram' THEN tc.title ELSE mc.title END AS source_title
    FROM repost_routes r
    LEFT JOIN telegram_channels tc ON r.source_platform = 'telegram' AND tc.chat_id = r.source_chat_id
    LEFT JOIN max_channels mc ON r.source_platform = 'max' AND mc.chat_id = r.source_chat_id
    ORDER BY r.updated_at DESC`);
  const targetRows = await db(`SELECT t.*,
    CASE WHEN t.platform = 'telegram' THEN tc.title ELSE mc.title END AS target_title
    FROM repost_route_targets t
    LEFT JOIN telegram_channels tc ON t.platform = 'telegram' AND tc.chat_id = t.chat_id
    LEFT JOIN max_channels mc ON t.platform = 'max' AND mc.chat_id = t.chat_id
    ORDER BY t.id`);
  const targetsByRoute = new Map();
  for (const target of targetRows) {
    const list = targetsByRoute.get(String(target.route_id)) || [];
    list.push({ platform: target.platform, chat_id: String(target.chat_id), title: target.target_title || String(target.chat_id) });
    targetsByRoute.set(String(target.route_id), list);
  }
  const rows = routeRows.map((row, index) => ({ ...row, _index: index + 1, targets: targetsByRoute.get(String(row.id)) || [] }));
  const paged = paginateRows(rows, Math.max(0, page - 1), perPage);
  return {
    page: paged.page + 1,
    per_page: paged.perPage,
    total: paged.total,
    total_pages: paged.totalPages,
    items: paged.items.map((row) => ({
      id: row.id,
      enabled: Boolean(row.enabled),
      index: row._index,
      source_platform: row.source_platform,
      source_chat_id: String(row.source_chat_id),
      source_title: row.source_title || String(row.source_chat_id),
      targets: row.targets,
      created_at: row.created_at,
      updated_at: row.updated_at
    }))
  };
}

async function adminSaveBridge(payload) {
  const sourcePlatform = String(payload.source_platform || "");
  const sourceChatId = String(payload.source_chat_id || "");
  const rawTargets = Array.isArray(payload.targets) ? payload.targets
    .map((target) => ({ platform: String(target.platform || ""), chat_id: String(target.chat_id || "") }))
    .filter((target) => ["telegram", "max"].includes(target.platform) && target.chat_id) : [];
  const targets = [...new Map(rawTargets.map((target) => [
    `${target.platform}:${target.chat_id}`,
    target
  ])).values()];
  if (!["telegram", "max"].includes(sourcePlatform) || !sourceChatId || !targets.length) {
    throw new Error("Выберите исходный канал и хотя бы один канал-получатель.");
  }
  if (targets.some((target) => target.platform === sourcePlatform && target.chat_id === sourceChatId)) {
    throw new Error("Исходный канал нельзя добавить в получатели.");
  }
  const sourceAccounts = await db(
    "SELECT account_id FROM account_channels WHERE platform = ? AND chat_id = ? AND is_blocked = 0 LIMIT 1",
    [sourcePlatform, sourceChatId]
  );
  const accountId = sourceAccounts[0]?.account_id;
  if (!accountId) throw new Error("Исходный канал не привязан ни к одному пользователю.");
  const proposedId = proposedRouteId(accountId, sourcePlatform, sourceChatId);
  let savedRouteId = proposedId;
  await withDbTransaction(async (query) => {
    await lockLinkedAccountForRouting(query, accountId);
    await assertRoutingChannelsAvailable(
      query,
      accountId,
      sourcePlatform,
      sourceChatId,
      targets
    );
    const existingRouteId = await routeIdForSource(
      accountId,
      sourcePlatform,
      sourceChatId,
      query
    );
    if (payload.id && existingRouteId && String(payload.id) !== existingRouteId) {
      throw new Error("Для выбранного исходного канала уже настроена другая пересылка.");
    }
    const routeId = existingRouteId || proposedId;
    await assertNoRouteCycle(
      accountId,
      payload.id || routeId,
      sourcePlatform,
      sourceChatId,
      targets,
      query
    );
    if (payload.id && String(payload.id) !== routeId) {
      const oldRoutes = await query(
        "SELECT account_id, source_platform, source_chat_id FROM repost_routes WHERE id = ? LIMIT 1 FOR UPDATE",
        [String(payload.id)]
      );
      if (oldRoutes[0]) {
        await retireLegacyRouteSource(
          query,
          oldRoutes[0].account_id,
          oldRoutes[0].source_platform,
          oldRoutes[0].source_chat_id
        );
      }
      await query("DELETE FROM repost_route_targets WHERE route_id = ?", [String(payload.id)]);
      await query("DELETE FROM repost_routes WHERE id = ?", [String(payload.id)]);
    }
    await retireLegacyRouteSource(query, accountId, sourcePlatform, sourceChatId);
    savedRouteId = await upsertRepostRoute(
      query,
      proposedId,
      accountId,
      sourcePlatform,
      sourceChatId,
      payload.enabled !== false
    );
    await syncRepostRouteTargets(query, savedRouteId, targets);
  });
  return { id: savedRouteId };
}

async function adminSystemState() {
  const state = await debugState();
  return {
    bridge_count: state.bridges.length,
    telegram_channel_count: state.telegram_channels.length,
    max_channel_count: state.max_channels.length,
    recent_bridges: state.bridges.slice(0, 10),
    recent_events: state.inbound_events.slice(0, 20)
  };
}

async function adminUsersState(platform, query = "") {
  const q = `%${String(query || "").trim()}%`;
  if (platform === "telegram") {
    const rows = await db(
      `SELECT telegram_user_id AS user_id, username, first_name, is_admin, permissions, updated_at
       FROM telegram_users
       WHERE telegram_user_id LIKE ? OR COALESCE(username, '') LIKE ? OR COALESCE(first_name, '') LIKE ?
       ORDER BY is_admin DESC, updated_at DESC
       LIMIT 100`,
      [q, q, q]
    );
    return rows.map((row) => ({ ...row, permissions: parsePermissions(row.permissions), platform }));
  }
  const rows = await db(
    `SELECT max_user_id AS user_id, chat_id, username, first_name, is_admin, permissions, updated_at
     FROM max_users
     WHERE max_user_id LIKE ? OR COALESCE(username, '') LIKE ? OR COALESCE(first_name, '') LIKE ? OR COALESCE(chat_id, '') LIKE ?
     ORDER BY is_admin DESC, updated_at DESC
     LIMIT 100`,
    [q, q, q, q]
  );
  return rows.map((row) => ({ ...row, permissions: parsePermissions(row.permissions), platform }));
}

async function adminAccountsState() {
  const accounts = await db(`
    SELECT a.*,
      tu.first_name AS telegram_name, tu.username AS telegram_username,
      mu.first_name AS max_name, mu.username AS max_username,
      (SELECT COUNT(*) FROM account_channels ac WHERE ac.account_id = a.id) AS channel_count,
      (SELECT COUNT(*) FROM repost_routes r WHERE r.account_id = a.id) AS bridge_count
    FROM linked_accounts a
    LEFT JOIN telegram_users tu ON tu.telegram_user_id = a.telegram_user_id
    LEFT JOIN max_users mu ON mu.max_user_id = a.max_user_id
    ORDER BY a.id
  `);
  for (const account of accounts) {
    account.channels = await db(`
      SELECT ac.platform, ac.chat_id, ac.is_blocked,
        COALESCE(tc.title, mc.title, ac.chat_id) AS title
      FROM account_channels ac
      LEFT JOIN telegram_channels tc ON ac.platform = 'telegram' AND tc.chat_id = ac.chat_id
      LEFT JOIN max_channels mc ON ac.platform = 'max' AND mc.chat_id = ac.chat_id
      WHERE ac.account_id = ? ORDER BY ac.platform, title`, [account.id]);
    account.routes = await db(`SELECT r.id, r.source_platform, r.source_chat_id, r.enabled,
      COALESCE(tc.title, mc.title, r.source_chat_id) AS source_title
      FROM repost_routes r
      LEFT JOIN telegram_channels tc ON r.source_platform = 'telegram' AND tc.chat_id = r.source_chat_id
      LEFT JOIN max_channels mc ON r.source_platform = 'max' AND mc.chat_id = r.source_chat_id
      WHERE r.account_id = ? ORDER BY r.updated_at DESC`, [account.id]);
    for (const route of account.routes) {
      route.targets = await db(`SELECT t.platform, t.chat_id,
        COALESCE(tc.title, mc.title, t.chat_id) AS title
        FROM repost_route_targets t
        LEFT JOIN telegram_channels tc ON t.platform = 'telegram' AND tc.chat_id = t.chat_id
        LEFT JOIN max_channels mc ON t.platform = 'max' AND mc.chat_id = t.chat_id
        WHERE t.route_id = ? ORDER BY t.id`, [route.id]);
    }
  }
  return accounts;
}

async function adminModerateAccount(payload) {
  const accountId = String(payload.account_id || "");
  if (!accountId) throw new Error("account_id is required");
  const action = String(payload.action || "update");
  await withDbTransaction(async (query) => {
    const accountRows = await query(
      "SELECT id FROM linked_accounts WHERE id = ? LIMIT 1 FOR UPDATE",
      [accountId]
    );
    if (!accountRows[0]) throw new Error("account not found");
    if (action === "delete_bridges") {
      await query(
        "DELETE FROM repost_route_targets WHERE route_id IN (SELECT id FROM repost_routes WHERE account_id = ?)",
        [accountId]
      );
      await query("DELETE FROM repost_routes WHERE account_id = ?", [accountId]);
      await query("DELETE FROM bridges WHERE account_id = ?", [accountId]);
    } else if (action === "delete_channel_links") {
      await query(
        "DELETE FROM repost_route_targets WHERE route_id IN (SELECT id FROM repost_routes WHERE account_id = ?)",
        [accountId]
      );
      await query("DELETE FROM repost_routes WHERE account_id = ?", [accountId]);
      await query("DELETE FROM bridges WHERE account_id = ?", [accountId]);
      await query("DELETE FROM account_channels WHERE account_id = ? AND is_blocked = 0", [accountId]);
    } else if (action === "block_channel") {
      const channelPlatform = String(payload.platform);
      const channelChatId = String(payload.chat_id);
      await query(
        `SELECT chat_id FROM account_channels
         WHERE account_id = ? AND platform = ? AND chat_id = ? LIMIT 1 FOR UPDATE`,
        [accountId, channelPlatform, channelChatId]
      );
      await query(
        "UPDATE account_channels SET is_blocked = ?, block_reason = ? WHERE account_id = ? AND platform = ? AND chat_id = ?",
        [payload.channel_blocked ? 1 : 0, payload.block_reason ? String(payload.block_reason) : null, accountId, channelPlatform, channelChatId]
      );
      if (payload.channel_blocked) {
        await query(`UPDATE repost_routes SET enabled = 0 WHERE account_id = ? AND
          ((source_platform = ? AND source_chat_id = ?) OR id IN
            (SELECT route_id FROM repost_route_targets WHERE platform = ? AND chat_id = ?))`,
          [accountId, channelPlatform, channelChatId, channelPlatform, channelChatId]);
        const column = channelPlatform === "max" ? "max_chat_id" : "telegram_chat_id";
        await query(`UPDATE bridges SET enabled = 0 WHERE account_id = ? AND ${column} = ?`, [accountId, channelChatId]);
      }
    } else if (action === "delete_channel") {
      const channelPlatform = String(payload.platform);
      const channelChatId = String(payload.chat_id);
      await query(
        `SELECT chat_id FROM account_channels
         WHERE account_id = ? AND platform = ? AND chat_id = ? LIMIT 1 FOR UPDATE`,
        [accountId, channelPlatform, channelChatId]
      );
      await query(
        `DELETE FROM repost_route_targets
         WHERE route_id IN (SELECT id FROM repost_routes
           WHERE account_id = ? AND source_platform = ? AND source_chat_id = ?)`,
        [accountId, channelPlatform, channelChatId]
      );
      await query(
        "DELETE FROM repost_routes WHERE account_id = ? AND source_platform = ? AND source_chat_id = ?",
        [accountId, channelPlatform, channelChatId]
      );
      await query(
        "DELETE FROM repost_route_targets WHERE platform = ? AND chat_id = ? AND route_id IN (SELECT id FROM repost_routes WHERE account_id = ?)",
        [channelPlatform, channelChatId, accountId]
      );
      await query(
        "DELETE FROM repost_routes WHERE account_id = ? AND id NOT IN (SELECT DISTINCT route_id FROM repost_route_targets)",
        [accountId]
      );
      const column = channelPlatform === "max" ? "max_chat_id" : "telegram_chat_id";
      await query(`DELETE FROM bridges WHERE account_id = ? AND ${column} = ?`, [accountId, channelChatId]);
      await query(
        "DELETE FROM account_channels WHERE account_id = ? AND platform = ? AND chat_id = ? AND is_blocked = 0",
        [accountId, channelPlatform, channelChatId]
      );
    } else {
      await query(
        "UPDATE linked_accounts SET is_blocked = ?, telegram_blocked = ?, max_blocked = ?, block_reason = ? WHERE id = ?",
        [payload.is_blocked ? 1 : 0, payload.telegram_blocked ? 1 : 0, payload.max_blocked ? 1 : 0, payload.block_reason ? String(payload.block_reason) : null, accountId]
      );
    }
  });
  return (await adminAccountsState()).find((row) => String(row.id) === accountId) || null;
}

async function adminUpsertUserAccess(payload) {
  const platform = String(payload.platform || "");
  const permissions = normalizePermissions(payload.permissions);
  const isAdmin = payload.is_admin ? 1 : 0;
  if (platform === "telegram") {
    const userId = String(payload.user_id || "");
    await db(
      `INSERT INTO telegram_users (telegram_user_id, username, first_name, is_admin, permissions)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE username = VALUES(username), first_name = VALUES(first_name), is_admin = VALUES(is_admin), permissions = VALUES(permissions)`,
      [userId, payload.username ? String(payload.username) : null, payload.first_name ? String(payload.first_name) : null, isAdmin, JSON.stringify(permissions)]
    );
    const rows = await adminUsersState("telegram", userId);
    return rows[0] || null;
  }
  const userId = String(payload.user_id || "");
  await db(
    `INSERT INTO max_users (max_user_id, chat_id, username, first_name, is_admin, permissions)
     VALUES (?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE chat_id = VALUES(chat_id), username = VALUES(username), first_name = VALUES(first_name), is_admin = VALUES(is_admin), permissions = VALUES(permissions)`,
    [userId, payload.chat_id ? String(payload.chat_id) : null, payload.username ? String(payload.username) : null, payload.first_name ? String(payload.first_name) : null, isAdmin, JSON.stringify(permissions)]
  );
  const rows = await adminUsersState("max", userId);
  return rows[0] || null;
}

async function adminDeleteUserAccess(payload) {
  const platform = String(payload.platform || "");
  const userId = String(payload.user_id || "");
  if (platform === "telegram") {
    await db("UPDATE telegram_users SET is_admin = 0, permissions = JSON_ARRAY() WHERE telegram_user_id = ?", [userId]);
    return;
  }
  await db("UPDATE max_users SET is_admin = 0, permissions = JSON_ARRAY() WHERE max_user_id = ?", [userId]);
}

async function syncLegacyPairToRoutes(accountId, telegramChatId, maxChatId, direction, enabled = true) {
  void direction;
  void enabled;
  await withDbTransaction(async (query) => {
    await reconcileLegacyBridgeRoute(
      query,
      accountId,
      "telegram",
      String(telegramChatId),
      {
        removeWhenMissing: true,
        removedLegacyTargetChatIds: [String(maxChatId)]
      }
    );
    await reconcileLegacyBridgeRoute(
      query,
      accountId,
      "max",
      String(maxChatId),
      {
        removeWhenMissing: true,
        removedLegacyTargetChatIds: [String(telegramChatId)]
      }
    );
  });
}

async function removeLegacyPairFromRoutes(accountId, telegramChatId, maxChatId) {
  await withDbTransaction(async (query) => {
    await reconcileLegacyBridgeRoute(
      query,
      accountId,
      "telegram",
      String(telegramChatId),
      {
        removeWhenMissing: true,
        removedLegacyTargetChatIds: [String(maxChatId)]
      }
    );
    await reconcileLegacyBridgeRoute(
      query,
      accountId,
      "max",
      String(maxChatId),
      {
        removeWhenMissing: true,
        removedLegacyTargetChatIds: [String(telegramChatId)]
      }
    );
  });
}

async function saveBridge(sourcePlatform, sourceUserId, telegramChatId, maxChatId, direction) {
  let account;
  if (String(sourceUserId) === "admin-panel") {
    const rows = await db(
      "SELECT la.* FROM linked_accounts la JOIN account_channels ac ON ac.account_id = la.id WHERE ac.platform = 'telegram' AND ac.chat_id = ? LIMIT 1",
      [String(telegramChatId)]
    );
    account = rows[0];
    if (!account) throw new Error("Telegram-канал не привязан ни к одному пользователю.");
  } else {
    account = await linkedAccount(sourcePlatform, sourceUserId, true);
  }
  await assertAccountChannel(account.id, "telegram", telegramChatId);
  await assertAccountChannel(account.id, "max", maxChatId);
  const tgRows = await db("SELECT title FROM telegram_channels WHERE chat_id = ? LIMIT 1", [String(telegramChatId)]);
  const maxRows = await db("SELECT title FROM max_channels WHERE chat_id = ? LIMIT 1", [String(maxChatId)]);
  const telegramId = String(telegramChatId);
  const maxId = String(maxChatId);
  const title = `${tgRows[0]?.title || telegramId} ↔ ${maxRows[0]?.title || maxId}`;
  const existing = await db("SELECT id FROM bridges WHERE account_id = ? AND telegram_chat_id = ? AND max_chat_id = ? LIMIT 1", [account.id, telegramId, maxId]);
  if (existing.length > 0) {
    await db(
      `UPDATE bridges
       SET title = ?, enabled = 1, direction = ?, account_id = COALESCE(account_id, ?), updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [title, direction, account.id, String(existing[0].id)]
    );
    await syncLegacyPairToRoutes(account.id, telegramId, maxId, direction, true);
    return;
  }
  const occupied = await db("SELECT account_id FROM bridges WHERE telegram_chat_id = ? AND max_chat_id = ? LIMIT 1", [telegramId, maxId]);
  if (occupied[0] && String(occupied[0].account_id) !== String(account.id)) {
    throw new Error("Эта пара каналов уже принадлежит другому пользователю GitRePosted.");
  }
  const bridgeId = `bridge_${hashKey([account.id, telegramId, maxId]).slice(0, 24)}`;
  await db(
    `INSERT INTO bridges (id, title, enabled, direction, telegram_chat_id, max_chat_id, account_id)
     VALUES (?, ?, 1, ?, ?, ?, ?)`,
    [bridgeId, title, direction, telegramId, maxId, account.id]
  );
  await syncLegacyPairToRoutes(account.id, telegramId, maxId, direction, true);
}

async function updateBridgeChannels(id, telegramChatId, maxChatId) {
  const oldRows = await db("SELECT account_id, telegram_chat_id, max_chat_id, direction, enabled FROM bridges WHERE id = ? LIMIT 1", [String(id)]);
  if (!oldRows[0]?.account_id) throw new Error("Route is missing an owner account.");
  const telegramId = String(telegramChatId);
  const maxId = String(maxChatId);
  await assertAccountChannel(oldRows[0].account_id, "telegram", telegramId);
  await assertAccountChannel(oldRows[0].account_id, "max", maxId);
  const tgRows = await db("SELECT title FROM telegram_channels WHERE chat_id = ? LIMIT 1", [telegramId]);
  const maxRows = await db("SELECT title FROM max_channels WHERE chat_id = ? LIMIT 1", [maxId]);
  const title = `${tgRows[0]?.title || telegramId} ↔ ${maxRows[0]?.title || maxId}`;
  await db(
    `UPDATE bridges
     SET title = ?, telegram_chat_id = ?, max_chat_id = ?, updated_at = CURRENT_TIMESTAMP
     WHERE id = ?`,
    [title, telegramId, maxId, String(id)]
  );
  if (oldRows[0]?.account_id) {
    await removeLegacyPairFromRoutes(oldRows[0].account_id, oldRows[0].telegram_chat_id, oldRows[0].max_chat_id);
    await syncLegacyPairToRoutes(oldRows[0].account_id, telegramId, maxId, oldRows[0].direction, Boolean(oldRows[0].enabled));
  }
}

async function updateBridgeDirection(id, direction) {
  const rows = await db("SELECT account_id, telegram_chat_id, max_chat_id, enabled FROM bridges WHERE id = ? LIMIT 1", [String(id)]);
  await db(
    `UPDATE bridges
     SET direction = ?, updated_at = CURRENT_TIMESTAMP
     WHERE id = ?`,
    [String(direction), String(id)]
  );
  if (rows[0]?.account_id) {
    await removeLegacyPairFromRoutes(rows[0].account_id, rows[0].telegram_chat_id, rows[0].max_chat_id);
    await syncLegacyPairToRoutes(rows[0].account_id, rows[0].telegram_chat_id, rows[0].max_chat_id, String(direction), Boolean(rows[0].enabled));
  }
}

async function removeBridge(id) {
  const rows = await db("SELECT account_id, telegram_chat_id, max_chat_id FROM bridges WHERE id = ? LIMIT 1", [String(id)]);
  await db("DELETE FROM bridges WHERE id = ?", [String(id)]);
  if (rows[0]?.account_id) await removeLegacyPairFromRoutes(rows[0].account_id, rows[0].telegram_chat_id, rows[0].max_chat_id);
}

async function toggleBridge(id) {
  await db("UPDATE bridges SET enabled = 1 - enabled WHERE id = ?", [String(id)]);
  const rows = await db("SELECT account_id, telegram_chat_id, max_chat_id, direction, enabled FROM bridges WHERE id = ? LIMIT 1", [String(id)]);
  if (rows[0]?.account_id) {
    await removeLegacyPairFromRoutes(rows[0].account_id, rows[0].telegram_chat_id, rows[0].max_chat_id);
    await syncLegacyPairToRoutes(rows[0].account_id, rows[0].telegram_chat_id, rows[0].max_chat_id, rows[0].direction, Boolean(rows[0].enabled));
  }
}

let lastRelayIdCleanupAt = 0;

function relayFailureCode(error) {
  const value = String(error?.code || error?.name || "relay_error");
  return /^[a-zA-Z0-9_.-]{1,191}$/.test(value) ? value : "relay_error";
}

function relayErrorTreeSome(error, predicate, seen = new Set()) {
  if (!error || seen.has(error)) return false;
  seen.add(error);
  if (predicate(error)) return true;
  if (error.cause && relayErrorTreeSome(error.cause, predicate, seen)) return true;
  if (Array.isArray(error.errors)) {
    return error.errors.some((nested) => relayErrorTreeSome(nested, predicate, seen));
  }
  return false;
}

function relayHasFailureCode(error, code) {
  return relayErrorTreeSome(error, (candidate) => candidate?.code === code);
}

function relayRetryAfterSeconds(error, seen = new Set()) {
  if (!error || seen.has(error)) return 0;
  seen.add(error);
  const ownValue = Number(error.retryAfterSeconds || 0);
  let result = Number.isFinite(ownValue) && ownValue > 0 ? Math.ceil(ownValue) : 0;
  if (error.cause) result = Math.max(result, relayRetryAfterSeconds(error.cause, seen));
  if (Array.isArray(error.errors)) {
    for (const nested of error.errors) {
      result = Math.max(result, relayRetryAfterSeconds(nested, seen));
    }
  }
  return Math.min(result, 24 * 60 * 60);
}

function throwRelayTargetFailures(failures) {
  if (!failures.length) return;
  const errors = failures.map((failure) => failure.error);
  const aggregate = new AggregateError(
    errors,
    `Не удалось доставить публикацию в ${failures.length} канал(а/ов).`
  );
  aggregate.code = "RELAY_TARGET_DELIVERY_FAILED";
  aggregate.cause = errors[0];
  throw aggregate;
}

async function cleanupRelayIdempotencyRecords() {
  const now = Date.now();
  if (now - lastRelayIdCleanupAt < 60 * 60 * 1000) return;
  lastRelayIdCleanupAt = now;
  await Promise.all([
    db(
      `DELETE FROM relay_source_events
       WHERE updated_at < (UTC_TIMESTAMP() - INTERVAL ? DAY)
         AND NOT (
           state = 'terminal'
           AND last_error IN ('OUTBOUND_DELIVERY_UNCERTAIN','OUTBOUND_ECHO_UNCERTAIN')
         )`,
      [RELAY_ID_TTL_DAYS]
    ),
    db(
      `DELETE m FROM relay_outbound_messages m
       WHERE m.created_at < (UTC_TIMESTAMP() - INTERVAL ? DAY)
         AND NOT EXISTS (
           SELECT 1 FROM relay_outbound_operations u
           WHERE u.source_platform = m.source_platform
             AND u.source_chat_id = m.source_chat_id
             AND u.source_event_id = m.source_event_id
             AND u.state = 'uncertain'
         )`,
      [RELAY_ID_TTL_DAYS]
    ),
    db(
      `DELETE o FROM relay_outbound_operations o
       LEFT JOIN relay_outbound_operations u
         ON u.source_platform = o.source_platform
        AND u.source_chat_id = o.source_chat_id
        AND u.source_event_id = o.source_event_id
        AND u.state = 'uncertain'
       WHERE o.updated_at < (UTC_TIMESTAMP() - INTERVAL ? DAY)
         AND o.state <> 'uncertain'
         AND u.id IS NULL`,
      [RELAY_ID_TTL_DAYS]
    ),
    db(
      "DELETE FROM inbound_events WHERE created_at < (UTC_TIMESTAMP() - INTERVAL ? DAY)",
      [RELAY_ID_TTL_DAYS]
    ),
    db(
      "DELETE FROM bot_event_receipts WHERE updated_at < (UTC_TIMESTAMP() - INTERVAL ? DAY)",
      [RELAY_ID_TTL_DAYS]
    ),
    db(
      `DELETE FROM bot_ingress_events
       WHERE updated_at < (UTC_TIMESTAMP() - INTERVAL ? DAY)
         AND state IN ('completed','terminal')`,
      [RELAY_ID_TTL_DAYS]
    )
  ]);
}

async function finishRelaySourceEvent(identity, state, error, leaseToken) {
  if (!leaseToken) return false;
  const result = await db(
    `UPDATE relay_source_events
     SET state = ?,
         lease_token = NULL,
         lease_until = NULL,
         next_attempt_at = NULL,
         last_error = ?,
         terminal_at = CASE WHEN ? = 'terminal' THEN UTC_TIMESTAMP() ELSE terminal_at END,
         updated_at = UTC_TIMESTAMP()
     WHERE platform = ? AND chat_id = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?`,
    [
      state,
      error ? relayFailureCode(error) : null,
      state,
      identity.platform,
      String(identity.chatId),
      identity.eventId,
      leaseToken
    ]
  );
  return Number(result.affectedRows) === 1;
}

async function relayRoutesSnapshot(platform, chatId, query = db) {
  const blockColumn = platform === "max" ? "max_blocked" : "telegram_blocked";
  const sourceChatIds = platform === "telegram"
    ? [...new Set([
        String(chatId),
        normalizeTelegramChatId(chatId),
        legacyTelegramChatId(chatId)
      ].filter(Boolean))]
    : [String(chatId)];
  const sourcePlaceholders = sourceChatIds.map(() => "?").join(",");
  const rows = await query(
    `SELECT r.id AS route_id, r.account_id, r.source_chat_id,
            t.id AS target_id, t.platform, t.chat_id
     FROM repost_routes r
     JOIN repost_route_targets t ON t.route_id = r.id
     JOIN linked_accounts a ON a.id = r.account_id
       AND a.is_blocked = 0 AND a.${blockColumn} = 0
     JOIN account_channels src ON src.account_id = r.account_id
       AND src.platform = r.source_platform AND src.chat_id = r.source_chat_id
       AND src.is_blocked = 0
     JOIN account_channels dst ON dst.account_id = r.account_id
       AND dst.platform = t.platform AND dst.chat_id = t.chat_id
       AND dst.is_blocked = 0
     WHERE r.enabled = 1 AND r.source_platform = ?
       AND r.source_chat_id IN (${sourcePlaceholders})
     ORDER BY r.id, t.id`,
    [platform, ...sourceChatIds]
  );
  if (platform === "telegram") {
    const routeIds = new Set(rows.map((row) => String(row.route_id)));
    if (routeIds.size > 1) {
      const error = new Error(
        "Для старого и нового Telegram ID найдены разные активные маршруты; требуется ручная сверка."
      );
      error.code = "TELEGRAM_ROUTE_ALIAS_CONFLICT";
      throw error;
    }
  }
  return rows.map((row) => ({
    route_id: row.route_id,
    target_id: row.target_id,
    platform: row.platform,
    chat_id: row.chat_id
  }));
}

async function enqueueTelegramRelayMessage(message, { replaceExisting = false } = {}) {
  const itemIdentity = telegramSourceIdentity([message]);
  const jobKey = telegramRelayJobKey(message);
  const settleSeconds = Math.ceil(
    telegramRelaySettleMilliseconds(message, RELAY_RETRY_POLICY) / 1000
  );
  const connection = await pool.getConnection();
  const enqueueLockName = `gitreposted:rs:telegram:${hashKey([itemIdentity.chatId]).slice(0, 32)}`;
  let enqueueLockAcquired = false;
  const query = async (sql, params = []) => {
    const [rows] = await connection.execute(sql, params);
    return rows;
  };
  try {
    const [lockRows] = await connection.execute("SELECT GET_LOCK(?, 5) AS acquired", [enqueueLockName]);
    enqueueLockAcquired = Number(lockRows[0]?.acquired) === 1;
    if (!enqueueLockAcquired) {
      const error = new Error("Telegram source queue is busy; webhook must be retried.");
      error.code = "RELAY_SOURCE_ENQUEUE_BUSY";
      error.statusCode = 503;
      throw error;
    }
    await connection.beginTransaction();
    const initialEnvelope = buildTelegramRelayEnvelope([], message);
    const initialMessageIds = normalizePlatformMessageIds(initialEnvelope.messageIds);
    if (!initialMessageIds.length) {
      throw new Error("Telegram relay payload has no stable message ID.");
    }
    const routing = await relayRoutesSnapshot("telegram", itemIdentity.chatId, query);
    const insertResult = await query(
      `INSERT IGNORE INTO relay_source_events
        (platform, chat_id, event_id, job_key, message_ids, group_id, payload_json,
         routing_json, state, next_attempt_at, lease_token, lease_until,
         attempt_count, last_error, terminal_at)
       VALUES ('telegram', ?, ?, ?, ?, ?, ?, ?, 'queued',
         DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), NULL, NULL, 0, NULL, NULL)`,
      [
        itemIdentity.chatId,
        jobKey,
        jobKey,
        JSON.stringify(initialMessageIds),
        itemIdentity.groupId || null,
        JSON.stringify(initialEnvelope.messages),
        JSON.stringify(routing),
        settleSeconds
      ]
    );
    if (Number(insertResult.affectedRows) === 1) {
      await connection.commit();
      return { jobKey, eventId: jobKey, queued: true, state: "queued" };
    }
    const [rows] = await connection.execute(
      `SELECT event_id, state, message_ids, payload_json, routing_json, attempt_count,
              CASE WHEN lease_until IS NOT NULL AND lease_until > UTC_TIMESTAMP()
                THEN 1 ELSE 0 END AS lease_active
       FROM relay_source_events
       WHERE platform = 'telegram' AND chat_id = ? AND job_key = ?
       FOR UPDATE`,
      [itemIdentity.chatId, jobKey]
    );
    const existing = rows[0];
    const previousMessages = parseJsonArray(existing?.payload_json);
    const incomingMessageId = String(message?.message_id ?? "");
    const alreadyPersisted = previousMessages.some((item) => (
      String(item?.message_id ?? "") === incomingMessageId
    ));
    const immutableState = Number(existing?.attempt_count || 0) > 0
      || ["completed", "failed", "terminal"].includes(existing?.state)
      || (existing?.state === "processing" && Number(existing.lease_active) === 1);
    if (alreadyPersisted && (!replaceExisting || immutableState)) {
      await connection.commit();
      return {
        jobKey,
        eventId: String(existing.event_id),
        queued: false,
        state: existing.state
      };
    }
    if (immutableState) {
      const lateJobKey = itemIdentity.eventId;
      const lateInsert = await query(
        `INSERT IGNORE INTO relay_source_events
          (platform, chat_id, event_id, job_key, message_ids, group_id, payload_json,
           routing_json, state, next_attempt_at, lease_token, lease_until,
           attempt_count, last_error, terminal_at)
         VALUES ('telegram', ?, ?, ?, ?, NULL, ?, ?, 'queued', UTC_TIMESTAMP(),
           NULL, NULL, 0, NULL, NULL)`,
        [
          itemIdentity.chatId,
          itemIdentity.eventId,
          lateJobKey,
          JSON.stringify(itemIdentity.messageIds),
          JSON.stringify([message]),
          typeof existing.routing_json === "string"
            ? existing.routing_json
            : JSON.stringify(parseJsonArray(existing.routing_json))
        ]
      );
      await connection.commit();
      return {
        jobKey: lateJobKey,
        eventId: itemIdentity.eventId,
        queued: Number(lateInsert.affectedRows) === 1,
        state: Number(lateInsert.affectedRows) === 1 ? "queued" : existing.state
      };
    }
    const envelope = buildTelegramRelayEnvelope(previousMessages, message);
    const messages = envelope.messages;
    const messageIds = normalizePlatformMessageIds(envelope.messageIds);
    if (!messageIds.length) {
      throw new Error("Telegram relay payload has no stable message ID.");
    }
    if (existing && JSON.stringify(previousMessages) === JSON.stringify(messages)) {
      await connection.commit();
      return {
        jobKey,
        eventId: String(existing.event_id),
        queued: false,
        state: existing.state
      };
    }

    await query(
      `UPDATE relay_source_events
         SET message_ids = ?,
             group_id = ?,
             payload_json = ?,
             state = 'queued',
             next_attempt_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
             lease_token = NULL,
             lease_until = NULL,
             last_error = NULL,
             terminal_at = NULL,
             updated_at = UTC_TIMESTAMP()
         WHERE platform = 'telegram' AND chat_id = ? AND job_key = ?`,
       [
         JSON.stringify(messageIds),
         itemIdentity.groupId || null,
         JSON.stringify(messages),
         settleSeconds,
         itemIdentity.chatId,
         jobKey
       ]
    );
    await connection.commit();
    return {
      jobKey,
      eventId: String(existing.event_id),
      queued: true,
      state: "queued"
    };
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
    }
    throw error;
  } finally {
    if (enqueueLockAcquired) {
      try {
        await connection.execute("SELECT RELEASE_LOCK(?)", [enqueueLockName]);
      } catch (error) {
        debugLog("telegram_relay_enqueue_unlock_failed", {
          chatId: itemIdentity.chatId,
          code: relayFailureCode(error)
        });
      }
    }
    connection.release();
  }
}

async function enqueueMaxRelayMessage(chatId, message) {
  const identity = maxSourceIdentity(chatId, message);
  if (!identity.messageIds.length) {
    throw new Error("MAX relay payload has no stable message ID.");
  }
  const payloadJson = JSON.stringify({ message });
  const connection = await pool.getConnection();
  const enqueueLockName = `gitreposted:rs:max:${hashKey([identity.chatId]).slice(0, 32)}`;
  let enqueueLockAcquired = false;
  const query = async (sql, params = []) => {
    const [rows] = await connection.execute(sql, params);
    return rows;
  };
  try {
    const [lockRows] = await connection.execute("SELECT GET_LOCK(?, 5) AS acquired", [enqueueLockName]);
    enqueueLockAcquired = Number(lockRows[0]?.acquired) === 1;
    if (!enqueueLockAcquired) {
      const error = new Error("MAX source queue is busy; webhook must be retried.");
      error.code = "RELAY_SOURCE_ENQUEUE_BUSY";
      error.statusCode = 503;
      throw error;
    }
    await connection.beginTransaction();
    const routing = await relayRoutesSnapshot("max", identity.chatId, query);
    const insertResult = await query(
      `INSERT IGNORE INTO relay_source_events
        (platform, chat_id, event_id, job_key, message_ids, group_id, payload_json,
         routing_json, state, next_attempt_at, lease_token, lease_until,
         attempt_count, last_error, terminal_at)
       VALUES ('max', ?, ?, ?, ?, NULL, ?, ?, 'queued', UTC_TIMESTAMP(),
         NULL, NULL, 0, NULL, NULL)`,
      [
        identity.chatId,
        identity.eventId,
        identity.eventId,
        JSON.stringify(identity.messageIds),
        payloadJson,
        JSON.stringify(routing)
      ]
    );
    if (Number(insertResult.affectedRows) === 1) {
      await connection.commit();
      return { eventId: identity.eventId, queued: true, state: "queued" };
    }
    const [rows] = await connection.execute(
      `SELECT event_id, state, payload_json, routing_json, last_error
       FROM relay_source_events
       WHERE platform = 'max' AND chat_id = ? AND job_key = ?
       LIMIT 1 FOR UPDATE`,
      [identity.chatId, identity.eventId]
    );
    const existing = rows[0];
    if (!existing) throw new Error("Не удалось сохранить MAX relay job.");
    if (existing.state === "terminal" && existing.last_error === "legacy_payload_missing") {
      await query(
        `UPDATE relay_source_events
         SET message_ids = ?, payload_json = ?, routing_json = ?, state = 'queued',
             next_attempt_at = UTC_TIMESTAMP(), lease_token = NULL, lease_until = NULL,
             attempt_count = 0, last_error = NULL, terminal_at = NULL,
             updated_at = UTC_TIMESTAMP()
         WHERE platform = 'max' AND chat_id = ? AND event_id = ?
           AND state = 'terminal' AND last_error = 'legacy_payload_missing'`,
        [
          JSON.stringify(identity.messageIds),
          payloadJson,
          JSON.stringify(routing),
          identity.chatId,
          String(existing.event_id)
        ]
      );
      await connection.commit();
      return { eventId: String(existing.event_id), queued: true, state: "queued" };
    }
    if (existing.state === "failed") {
      await query(
        `UPDATE relay_source_events
         SET next_attempt_at = COALESCE(next_attempt_at, UTC_TIMESTAMP()),
             updated_at = UTC_TIMESTAMP()
         WHERE platform = 'max' AND chat_id = ? AND event_id = ?`,
        [identity.chatId, String(existing.event_id)]
      );
    }
    await connection.commit();
    return {
      eventId: String(existing.event_id),
      queued: existing.state === "failed",
      state: existing.state
    };
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
    }
    throw error;
  } finally {
    if (enqueueLockAcquired) {
      try {
        await connection.execute("SELECT RELEASE_LOCK(?)", [enqueueLockName]);
      } catch (error) {
        debugLog("max_relay_enqueue_unlock_failed", {
          chatId: identity.chatId,
          code: relayFailureCode(error)
        });
      }
    }
    connection.release();
  }
}

async function claimNextRelayJob(platform) {
  await cleanupRelayIdempotencyRecords();
  const leaseToken = crypto.randomUUID();
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.execute(
      `SELECT candidate.platform, candidate.chat_id, candidate.event_id,
              candidate.job_key, candidate.message_ids, candidate.group_id,
              candidate.payload_json, candidate.routing_json,
              candidate.state, candidate.attempt_count
       FROM relay_source_events candidate
       WHERE candidate.platform = ?
         AND candidate.payload_json IS NOT NULL
         AND (
           (candidate.state IN ('queued','failed')
             AND candidate.next_attempt_at IS NOT NULL
             AND candidate.next_attempt_at <= UTC_TIMESTAMP())
           OR (candidate.state = 'processing'
             AND (candidate.lease_until IS NULL OR candidate.lease_until <= UTC_TIMESTAMP()))
         )
         AND NOT EXISTS (
           SELECT 1 FROM relay_source_events earlier
           WHERE earlier.platform = candidate.platform
             AND earlier.chat_id = candidate.chat_id
             AND earlier.state NOT IN ('completed','terminal')
             AND (
               earlier.created_at < candidate.created_at
               OR (earlier.created_at = candidate.created_at
                 AND earlier.queue_id < candidate.queue_id)
             )
         )
       ORDER BY candidate.created_at, candidate.queue_id
       LIMIT 1
       FOR UPDATE SKIP LOCKED`,
      [platform]
    );
    const row = rows[0];
    if (!row) {
      await connection.commit();
      return null;
    }
    if (Number(row.attempt_count || 0) >= RELAY_RETRY_POLICY.maxAttempts) {
      await connection.execute(
        `UPDATE relay_source_events
         SET state = 'terminal',
             next_attempt_at = NULL,
             lease_token = NULL,
             lease_until = NULL,
             last_error = COALESCE(last_error, 'retry_limit_exhausted'),
             terminal_at = UTC_TIMESTAMP(),
             updated_at = UTC_TIMESTAMP()
         WHERE platform = ? AND chat_id = ? AND event_id = ?`,
        [platform, String(row.chat_id), String(row.event_id)]
      );
      await connection.commit();
      return {
        terminalized: true,
        eventId: String(row.event_id),
        attemptCount: Number(row.attempt_count || 0)
      };
    }
    const messages = platform === "telegram"
      ? mergeTelegramRelayMessages(row.payload_json)
      : [];
    const maxEnvelope = platform === "max" ? parseJsonObject(row.payload_json) : {};
    const maxMessage = maxEnvelope.message || null;
    let finalIdentity;
    try {
      finalIdentity = platform === "telegram"
        ? telegramSourceIdentity(messages)
        : maxSourceIdentity(row.chat_id, maxMessage || {});
      if (!finalIdentity.messageIds.length) throw new Error("missing message id");
    } catch {
      await connection.execute(
        `UPDATE relay_source_events
         SET state = 'terminal',
             next_attempt_at = NULL,
             lease_token = NULL,
             lease_until = NULL,
             last_error = 'invalid_persisted_payload',
             terminal_at = UTC_TIMESTAMP(),
             updated_at = UTC_TIMESTAMP()
         WHERE platform = ? AND chat_id = ? AND event_id = ?`,
        [platform, String(row.chat_id), String(row.event_id)]
      );
      await connection.commit();
      return {
        terminalized: true,
        eventId: String(row.event_id),
        attemptCount: Number(row.attempt_count || 0),
        code: "invalid_persisted_payload"
      };
    }
    const attemptCount = Number(row.attempt_count || 0) + 1;
    await connection.execute(
      `UPDATE relay_source_events
       SET event_id = ?,
           message_ids = ?,
           group_id = ?,
           state = 'processing',
           next_attempt_at = NULL,
           lease_token = ?,
           lease_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
           attempt_count = ?,
           last_error = NULL,
           updated_at = UTC_TIMESTAMP()
        WHERE platform = ? AND chat_id = ? AND event_id = ?`,
      [
        finalIdentity.eventId,
        JSON.stringify(finalIdentity.messageIds),
        finalIdentity.groupId || null,
        leaseToken,
        RELAY_EVENT_LEASE_SECONDS,
        attemptCount,
        platform,
        String(row.chat_id),
        String(row.event_id)
      ]
    );
    await connection.commit();
    return {
      identity: finalIdentity,
      jobKey: String(row.job_key),
      messages,
      message: maxMessage,
      routes: parseJsonArray(row.routing_json),
      leaseToken,
      attemptCount
    };
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
    }
    throw error;
  } finally {
    connection.release();
  }
}

async function renewRelaySourceLease(job) {
  const result = await db(
    `UPDATE relay_source_events
     SET lease_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
         updated_at = UTC_TIMESTAMP()
     WHERE platform = ? AND chat_id = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?`,
    [
      RELAY_EVENT_LEASE_SECONDS,
      job.identity.platform,
      job.identity.chatId,
      job.identity.eventId,
      job.leaseToken
    ]
  );
  return Number(result.affectedRows) === 1;
}

async function assertRelaySourceLease(job) {
  const rows = await db(
    `SELECT 1
     FROM relay_source_events
     WHERE platform = ? AND chat_id = ? AND event_id = ?
       AND state = 'processing'
       AND lease_token = ?
       AND lease_until > UTC_TIMESTAMP()
     LIMIT 1`,
    [
      job.identity.platform,
      job.identity.chatId,
      job.identity.eventId,
      job.leaseToken
    ]
  );
  if (!rows[0]) {
    const error = new Error("Relay source lease was lost.");
    error.code = "RELAY_SOURCE_LEASE_LOST";
    throw error;
  }
}

async function withRelaySourceHeartbeat(job, work, logPrefix) {
  return withRelayLeaseHeartbeat({
    leaseSeconds: RELAY_EVENT_LEASE_SECONDS,
    renewLease: () => renewRelaySourceLease(job),
    assertLease: () => assertRelaySourceLease(job),
    work,
    onRenewError: (error) => {
      debugLog(`${logPrefix}_lease_renew_failed`, {
        eventId: job.identity.eventId,
        code: relayFailureCode(error)
      });
    }
  });
}

async function failRelayJob(job, error) {
  const disposition = relayRetryDisposition(job.attemptCount, RELAY_RETRY_POLICY);
  const terminal = disposition === "terminal";
  const retryDelay = terminal
    ? null
    : relayRetryDelaySeconds(job.attemptCount, RELAY_RETRY_POLICY);
  const result = await db(
    `UPDATE relay_source_events
     SET state = ?,
         next_attempt_at = CASE
           WHEN ? IS NULL THEN NULL
           ELSE DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND)
         END,
         lease_token = NULL,
         lease_until = NULL,
         last_error = ?,
         terminal_at = CASE WHEN ? = 1 THEN UTC_TIMESTAMP() ELSE NULL END,
         updated_at = UTC_TIMESTAMP()
     WHERE platform = ? AND chat_id = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?`,
    [
      terminal ? "terminal" : "failed",
      retryDelay,
      retryDelay || 0,
      relayFailureCode(error),
      terminal ? 1 : 0,
      job.identity.platform,
      job.identity.chatId,
      job.identity.eventId,
      job.leaseToken
    ]
  );
  return {
    updated: Number(result.affectedRows) === 1,
    terminal,
    retryDelay
  };
}

async function deferRelayJobWithoutAttempt(job, error, retryDelay = 1) {
  const result = await db(
    `UPDATE relay_source_events
     SET state = 'failed',
         next_attempt_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
         lease_token = NULL,
         lease_until = NULL,
         attempt_count = IF(attempt_count > 0, attempt_count - 1, 0),
         last_error = ?,
         terminal_at = NULL,
         updated_at = UTC_TIMESTAMP()
     WHERE platform = ? AND chat_id = ? AND event_id = ?
       AND state = 'processing' AND lease_token = ?`,
    [
      retryDelay,
      relayFailureCode(error),
      job.identity.platform,
      job.identity.chatId,
      job.identity.eventId,
      job.leaseToken
    ]
  );
  return {
    updated: Number(result.affectedRows) === 1,
    terminal: false,
    retryDelay,
    deferred: true
  };
}

async function terminalizeRelayJobWithCode(job, code) {
  const error = new Error("Relay delivery was stopped for operator reconciliation.");
  error.code = code;
  const updated = await finishRelaySourceEvent(
    job.identity,
    "terminal",
    error,
    job.leaseToken
  );
  return {
    updated,
    terminal: true,
    retryDelay: null,
    uncertain: true
  };
}

async function knownOutboundMessage(platform, chatId, messageIds) {
  const normalizedIds = normalizePlatformMessageIds(messageIds);
  if (!normalizedIds.length) return false;
  const chatIds = platform === "telegram"
    ? [...new Set([
        String(chatId),
        normalizeTelegramChatId(chatId),
        legacyTelegramChatId(chatId)
      ].filter(Boolean))]
    : [String(chatId)];
  const chatPlaceholders = chatIds.map(() => "?").join(",");
  const messagePlaceholders = normalizedIds.map(() => "?").join(",");
  const rows = await db(
    `SELECT 1
     FROM relay_outbound_messages
     WHERE platform = ?
       AND chat_id IN (${chatPlaceholders})
       AND message_id IN (${messagePlaceholders})
     LIMIT 1`,
    [platform, ...chatIds, ...normalizedIds]
  );
  return Boolean(rows[0]);
}

const OUTBOUND_TARGET_COMPLETE_KEY = "target-complete";

async function outboundTargetIsCompleted(sourceIdentity, targetPlatform, targetChatId) {
  const sourceChatIds = sourceIdentity.platform === "telegram"
    ? [...new Set([
        String(sourceIdentity.chatId),
        normalizeTelegramChatId(sourceIdentity.chatId),
        legacyTelegramChatId(sourceIdentity.chatId)
      ].filter(Boolean))]
    : [String(sourceIdentity.chatId)];
  const targetChatIds = targetPlatform === "telegram"
    ? [...new Set([
        String(targetChatId),
        normalizeTelegramChatId(targetChatId),
        legacyTelegramChatId(targetChatId)
      ].filter(Boolean))]
    : [String(targetChatId)];
  const sourcePlaceholders = sourceChatIds.map(() => "?").join(",");
  const targetPlaceholders = targetChatIds.map(() => "?").join(",");
  const rows = await db(
    `SELECT 1 FROM relay_outbound_operations
     WHERE source_platform = ? AND source_chat_id IN (${sourcePlaceholders})
       AND source_event_id = ?
       AND target_platform = ? AND target_chat_id IN (${targetPlaceholders})
       AND operation_key = ? AND state = 'completed'
     LIMIT 1`,
    [
      sourceIdentity.platform,
      ...sourceChatIds,
      sourceIdentity.eventId,
      targetPlatform,
      ...targetChatIds,
      OUTBOUND_TARGET_COMPLETE_KEY
    ]
  );
  return Boolean(rows[0]);
}

async function markOutboundTargetCompleted(sourceIdentity, targetPlatform, targetChatId) {
  const operationId = stableOutboundOperationId({
    sourcePlatform: sourceIdentity.platform,
    sourceChatId: sourceIdentity.chatId,
    sourceEventId: sourceIdentity.eventId,
    targetPlatform,
    targetChatId,
    operationKey: OUTBOUND_TARGET_COMPLETE_KEY
  });
  await db(
    `INSERT INTO relay_outbound_operations
       (id, target_platform, target_chat_id, operation_key, source_platform,
        source_chat_id, source_event_id, state, lease_token, lease_until,
        attempt_count, last_error)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', NULL, NULL, 1, NULL)
     ON DUPLICATE KEY UPDATE state = 'completed', lease_token = NULL,
       lease_until = NULL, last_error = NULL, updated_at = UTC_TIMESTAMP()`,
    [
      operationId,
      targetPlatform,
      String(targetChatId),
      OUTBOUND_TARGET_COMPLETE_KEY,
      sourceIdentity.platform,
      String(sourceIdentity.chatId),
      sourceIdentity.eventId
    ]
  );
}

async function pendingOutboundOperation(platform, chatId) {
  const chatIds = platform === "telegram"
    ? [...new Set([
        String(chatId),
        normalizeTelegramChatId(chatId),
        legacyTelegramChatId(chatId)
      ].filter(Boolean))]
    : [String(chatId)];
  const placeholders = chatIds.map(() => "?").join(",");
  await db(
    `UPDATE relay_outbound_operations
     SET state = 'uncertain', lease_token = NULL, lease_until = NULL,
         last_error = COALESCE(last_error, 'sending_lease_expired'),
         updated_at = UTC_TIMESTAMP()
     WHERE target_platform = ?
       AND target_chat_id IN (${placeholders})
       AND state = 'sending'
       AND (lease_until IS NULL OR lease_until <= UTC_TIMESTAMP())`,
    [platform, ...chatIds]
  );
  const rows = await db(
    `SELECT state,
       CASE WHEN lease_until IS NOT NULL AND lease_until > UTC_TIMESTAMP() THEN 1 ELSE 0 END AS lease_active
     FROM relay_outbound_operations
     WHERE target_platform = ?
       AND target_chat_id IN (${placeholders})
       AND (
         state = 'uncertain'
         OR state = 'sending'
         OR (state = 'pending'
           AND lease_until IS NOT NULL
           AND lease_until > UTC_TIMESTAMP())
       )
     ORDER BY state = 'uncertain' DESC
     LIMIT 1`,
    [platform, ...chatIds]
  );
  return rows[0]?.state ? {
    state: String(rows[0].state) === "sending" && Number(rows[0].lease_active) !== 1
      ? "uncertain"
      : String(rows[0].state)
  } : null;
}

async function shouldIgnoreOutboundWebhook(platform, chatId, messageIds) {
  const normalizedIds = normalizePlatformMessageIds(messageIds);
  if (!normalizedIds.length) return false;
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (await knownOutboundMessage(platform, chatId, normalizedIds)) return true;
    const pending = await pendingOutboundOperation(platform, chatId);
    if (!pending) {
      // The sender can commit the outbound ledger between the first lookup and
      // this state lookup. Recheck before accepting the webhook as genuine.
      return knownOutboundMessage(platform, chatId, normalizedIds);
    }
    if (pending.state === "uncertain") {
      const error = new Error(
        "Inbound message is quarantined until the uncertain outbound delivery is reconciled."
      );
      error.code = "OUTBOUND_ECHO_UNCERTAIN";
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const error = new Error("Outbound echo identity is still pending.");
  error.code = "OUTBOUND_ECHO_PENDING";
  throw error;
}

async function beginOutboundOperation(sourceIdentity, targetPlatform, targetChatId, operationKey = "whole") {
  const normalizedOperationKey = String(operationKey || "whole");
  if (!/^[a-zA-Z0-9_.:-]{1,64}$/.test(normalizedOperationKey)) {
    throw new Error("Outbound operation key is invalid.");
  }
  const operationId = stableOutboundOperationId({
    sourcePlatform: sourceIdentity.platform,
    sourceChatId: sourceIdentity.chatId,
    sourceEventId: sourceIdentity.eventId,
    targetPlatform,
    targetChatId,
    operationKey: normalizedOperationKey
  });
  const leaseToken = crypto.randomUUID();
  const targetChatIds = targetPlatform === "telegram"
    ? [...new Set([
        String(targetChatId),
        normalizeTelegramChatId(targetChatId),
        legacyTelegramChatId(targetChatId)
      ].filter(Boolean))]
    : [String(targetChatId)];
  const targetPlaceholders = targetChatIds.map(() => "?").join(",");
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const selectExisting = () => connection.execute(
      `SELECT id, state, target_chat_id, attempt_count,
        CASE WHEN lease_until IS NOT NULL AND lease_until > UTC_TIMESTAMP() THEN 1 ELSE 0 END AS lease_active
       FROM relay_outbound_operations
       WHERE source_platform = ?
         AND source_chat_id = ?
          AND source_event_id = ?
          AND target_platform = ?
          AND target_chat_id IN (${targetPlaceholders})
          AND operation_key = ?
       ORDER BY target_chat_id = ? DESC, id
       FOR UPDATE`,
      [
        sourceIdentity.platform,
        String(sourceIdentity.chatId),
        sourceIdentity.eventId,
        targetPlatform,
        ...targetChatIds,
        normalizedOperationKey,
        String(targetChatId)
      ]
    );
    let [rows] = await selectExisting();
    if (!rows.length) {
      const [insertResult] = await connection.execute(
        `INSERT IGNORE INTO relay_outbound_operations
          (id, target_platform, target_chat_id, operation_key, source_platform, source_chat_id,
           source_event_id, state, lease_token, lease_until, attempt_count, last_error)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?,
            DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), 1, NULL)`,
        [
          operationId,
          targetPlatform,
          String(targetChatId),
          normalizedOperationKey,
          sourceIdentity.platform,
          String(sourceIdentity.chatId),
          sourceIdentity.eventId,
          leaseToken,
          RELAY_EVENT_LEASE_SECONDS
        ]
      );
      if (Number(insertResult.affectedRows) === 1) {
        await connection.commit();
        return { operationId, leaseToken, skip: false };
      }
      [rows] = await selectExisting();
    }
    if (!rows.length) {
      const error = new Error("Outbound operation could not be claimed after a concurrent insert.");
      error.code = "OUTBOUND_OPERATION_CLAIM_FAILED";
      throw error;
    }
    if (rows.length > 1) {
      const active = rows.find((row) => (
        ["pending", "sending"].includes(String(row.state))
        && Number(row.lease_active) === 1
      ));
      if (active) {
        const error = new Error("Outbound relay operation alias is already in progress.");
        error.code = "OUTBOUND_OPERATION_IN_PROGRESS";
        throw error;
      }
      for (const row of rows.filter((candidate) => String(candidate.state) === "sending")) {
        await connection.execute(
          `UPDATE relay_outbound_operations
           SET state = 'uncertain', lease_token = NULL, lease_until = NULL,
               last_error = COALESCE(last_error, 'sending_lease_expired'),
               updated_at = UTC_TIMESTAMP()
           WHERE id = ? AND state = 'sending'`,
          [row.id]
        );
        row.state = "uncertain";
      }
      if (rows.some((row) => String(row.state) === "uncertain")) {
        await connection.commit();
        const error = new Error(
          "Outbound delivery has conflicting Telegram target aliases and requires operator reconciliation."
        );
        error.code = "OUTBOUND_DELIVERY_UNCERTAIN";
        throw error;
      }

      const authoritative = rows.find((row) => String(row.state) === "completed") || rows[0];
      const redundant = rows.filter((row) => String(row.id) !== String(authoritative.id));
      for (const row of redundant) {
        await connection.execute(
          "UPDATE relay_outbound_messages SET operation_id = ? WHERE operation_id = ?",
          [authoritative.id, row.id]
        );
        await connection.execute("DELETE FROM relay_outbound_operations WHERE id = ?", [row.id]);
      }
      await connection.execute(
        `UPDATE relay_outbound_operations
         SET target_chat_id = ?, attempt_count = GREATEST(attempt_count, ?),
             updated_at = UTC_TIMESTAMP()
         WHERE id = ?`,
        [
          String(targetChatId),
          Math.max(...rows.map((row) => Number(row.attempt_count) || 0)),
          authoritative.id
        ]
      );
      authoritative.target_chat_id = String(targetChatId);
      if (String(authoritative.state) === "completed") {
        await connection.commit();
        return { operationId: String(authoritative.id), leaseToken: null, skip: true };
      }
      rows = [authoritative];
    }
    const existing = rows[0];
    const storedOperationId = String(existing?.id || operationId);
    const disposition = outboundOperationDisposition(
      existing?.state,
      Number(existing?.lease_active) === 1
    );
    if (disposition === "skip") {
      await connection.commit();
      return { operationId: storedOperationId, leaseToken: null, skip: true };
    }
    if (disposition === "wait") {
      const error = new Error("Outbound relay operation is already in progress.");
      error.code = "OUTBOUND_OPERATION_IN_PROGRESS";
      throw error;
    }
    if (disposition === "uncertain") {
      if (existing?.state === "sending") {
        await connection.execute(
          `UPDATE relay_outbound_operations
           SET state = 'uncertain', lease_token = NULL, lease_until = NULL,
               last_error = 'sending_lease_expired', updated_at = UTC_TIMESTAMP()
           WHERE id = ? AND state = 'sending'`,
          [storedOperationId]
        );
      }
      await connection.commit();
      const error = new Error(
        "Outbound delivery result is uncertain and requires operator reconciliation."
      );
      error.code = "OUTBOUND_DELIVERY_UNCERTAIN";
      throw error;
    }

    await connection.execute(
      `UPDATE relay_outbound_operations
       SET state = 'pending',
           lease_token = ?,
           lease_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
           attempt_count = attempt_count + 1,
           last_error = NULL,
           updated_at = UTC_TIMESTAMP()
       WHERE id = ?`,
      [leaseToken, RELAY_EVENT_LEASE_SECONDS, storedOperationId]
    );
    await connection.commit();
    return { operationId: storedOperationId, leaseToken, skip: false };
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
    }
    throw error;
  } finally {
    connection.release();
  }
}

function outboundOperationLeaseLostError() {
  const error = new Error("Outbound relay operation lease was lost.");
  error.code = "OUTBOUND_OPERATION_LEASE_LOST";
  return error;
}

async function markOutboundOperationSending(operation) {
  const result = await db(
    `UPDATE relay_outbound_operations
     SET state = 'sending', updated_at = UTC_TIMESTAMP()
     WHERE id = ? AND state = 'pending' AND lease_token = ?
       AND lease_until > UTC_TIMESTAMP()`,
    [operation.operationId, operation.leaseToken]
  );
  return Number(result.affectedRows) === 1;
}

async function renewOutboundOperationLease(operation) {
  const result = await db(
    `UPDATE relay_outbound_operations
     SET lease_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
         updated_at = UTC_TIMESTAMP()
     WHERE id = ? AND state IN ('pending','sending') AND lease_token = ?`,
    [RELAY_EVENT_LEASE_SECONDS, operation.operationId, operation.leaseToken]
  );
  return Number(result.affectedRows) === 1;
}

async function assertOutboundOperationLease(operation) {
  const rows = await db(
    `SELECT 1
     FROM relay_outbound_operations
     WHERE id = ? AND state IN ('pending','sending') AND lease_token = ?
       AND lease_until > UTC_TIMESTAMP()
     LIMIT 1`,
    [operation.operationId, operation.leaseToken]
  );
  if (!rows[0]) throw outboundOperationLeaseLostError();
}

async function completeOutboundOperation(
  operation,
  sourceIdentity,
  targetPlatform,
  targetChatId,
  messageIds
) {
  const normalizedIds = normalizePlatformMessageIds(messageIds);
  if (!normalizedIds.length) {
    const error = new Error("Outbound API response did not contain a stable message ID.");
    error.code = "OUTBOUND_MESSAGE_ID_MISSING";
    throw error;
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [ownedRows] = await connection.execute(
      `SELECT 1
       FROM relay_outbound_operations
       WHERE id = ? AND state = 'sending' AND lease_token = ?
       FOR UPDATE`,
      [operation.operationId, operation.leaseToken]
    );
    if (!ownedRows[0]) {
      await connection.rollback();
      return null;
    }
    for (const messageId of normalizedIds) {
      await connection.execute(
        `INSERT IGNORE INTO relay_outbound_messages
          (platform, chat_id, message_id, operation_id, source_platform, source_chat_id, source_event_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          targetPlatform,
          String(targetChatId),
          messageId,
          operation.operationId,
          sourceIdentity.platform,
          String(sourceIdentity.chatId),
          sourceIdentity.eventId
        ]
      );
    }
    const [completionResult] = await connection.execute(
      `UPDATE relay_outbound_operations
       SET state = 'completed',
           lease_token = NULL,
           lease_until = NULL,
           last_error = NULL,
           updated_at = UTC_TIMESTAMP()
       WHERE id = ? AND state = 'sending' AND lease_token = ?`,
      [operation.operationId, operation.leaseToken]
    );
    if (Number(completionResult.affectedRows) !== 1) {
      await connection.rollback();
      return null;
    }
    await connection.commit();
  } catch (error) {
    try {
      await connection.rollback();
    } catch {
    }
    throw error;
  } finally {
    connection.release();
  }
  return normalizedIds;
}

async function failOutboundOperation(operation, error) {
  const result = await db(
    `UPDATE relay_outbound_operations
     SET state = 'failed',
         lease_token = NULL,
         lease_until = NULL,
         last_error = ?,
         updated_at = UTC_TIMESTAMP()
     WHERE id = ? AND state IN ('pending','sending') AND lease_token = ?`,
    [
      relayFailureCode(error),
      operation.operationId,
      operation.leaseToken
    ]
  );
  return Number(result.affectedRows) === 1;
}

async function markOutboundOperationUncertain(operation, error) {
  const result = await db(
    `UPDATE relay_outbound_operations
     SET state = 'uncertain',
         lease_token = NULL,
         lease_until = NULL,
         last_error = ?,
         updated_at = UTC_TIMESTAMP()
     WHERE id = ? AND state = 'sending' AND lease_token = ?`,
    [
      relayFailureCode(error),
      operation.operationId,
      operation.leaseToken
    ]
  );
  return Number(result.affectedRows) === 1;
}

function outboundFailureMayHaveCommitted(error, requestStarted) {
  if (!requestStarted) return false;
  const code = String(error?.code || "");
  const status = Number(error?.httpStatus || 0);
  if (["TELEGRAM_RATE_LIMIT", "MAX_RATE_LIMIT", "MAX_API_REJECTED"].includes(code)) {
    return false;
  }
  if (status >= 400 && status < 500 && ![408, 425].includes(status)) return false;
  return true;
}

function outboundDeliveryUncertainError(cause) {
  const error = new Error(
    "Outbound provider may have accepted the message; automatic retry is stopped."
  );
  error.code = "OUTBOUND_DELIVERY_UNCERTAIN";
  error.cause = cause;
  return error;
}

async function sendTrackedOutbound({
  sourceIdentity,
  targetPlatform,
  targetChatId,
  operationKey = "whole",
  send,
  extractMessageIds
}) {
  const operation = await beginOutboundOperation(
    sourceIdentity,
    targetPlatform,
    targetChatId,
    operationKey
  );
  if (operation.skip) {
    debugLog("relay_target_already_completed", {
      sourcePlatform: sourceIdentity.platform,
      sourceChatId: sourceIdentity.chatId,
      sourceEventId: sourceIdentity.eventId,
      targetPlatform,
      targetChatId: String(targetChatId),
      operationKey
    });
    return null;
  }
  // The durable row stays pending during downloads and local throttling. Only
  // the provider wrapper may cross it to sending immediately before fetch.
  let providerRequestStarted = false;
  let providerRequestStartPromise = null;
  const markProviderRequestStarted = async () => {
    if (providerRequestStarted) return;
    if (!providerRequestStartPromise) {
      providerRequestStartPromise = (async () => {
        if (!(await markOutboundOperationSending(operation))) {
          throw outboundOperationLeaseLostError();
        }
        providerRequestStarted = true;
      })();
    }
    await providerRequestStartPromise;
  };
  let providerResponseReceived = false;
  try {
    const response = await withRelayLeaseHeartbeat({
      leaseSeconds: RELAY_EVENT_LEASE_SECONDS,
      renewLease: () => renewOutboundOperationLease(operation),
      assertLease: () => assertOutboundOperationLease(operation),
      work: () => send(markProviderRequestStarted),
      onRenewError: (error) => {
        debugLog("relay_outbound_lease_renew_failed", {
          operationId: operation.operationId,
          code: relayFailureCode(error)
        });
      },
      leaseLostCode: "OUTBOUND_OPERATION_LEASE_LOST",
      leaseLostMessage: "Outbound relay operation lease was lost."
    });
    providerResponseReceived = true;
    const messageIds = extractMessageIds(response);
    const completedMessageIds = await completeOutboundOperation(
      operation,
      sourceIdentity,
      targetPlatform,
      targetChatId,
      messageIds
    );
    if (!completedMessageIds) throw outboundOperationLeaseLostError();
    return response;
  } catch (error) {
    const uncertain = providerResponseReceived
      || outboundFailureMayHaveCommitted(error, providerRequestStarted);
    const updated = uncertain
      ? await markOutboundOperationUncertain(operation, error)
      : await failOutboundOperation(operation, error);
    if (!updated) {
      debugLog("relay_outbound_failure_lease_lost", {
        operationId: operation.operationId,
        code: relayFailureCode(error),
        uncertain
      });
    }
    if (uncertain) throw outboundDeliveryUncertainError(error);
    throw error;
  }
}

async function telegramResponseResult(response, method) {
  let data;
  try {
    data = await response.json();
  } catch (cause) {
    const error = new Error(`Telegram ${method}: ${response.status} invalid JSON response`);
    error.code = response.ok ? "TELEGRAM_AMBIGUOUS_RESPONSE" : "TELEGRAM_HTTP_ERROR";
    error.httpStatus = response.status;
    error.cause = cause;
    throw error;
  }
  if (!response.ok || data.ok === false) {
    const error = new Error(`Telegram ${method}: ${response.status} ${JSON.stringify(data)}`);
    error.code = response.status === 429 ? "TELEGRAM_RATE_LIMIT" : "TELEGRAM_API_ERROR";
    error.httpStatus = response.status;
    error.retryAfterSeconds = response.status === 429
      ? Math.max(
          1,
          Number(data?.parameters?.retry_after || 0),
          retryAfterSecondsFromHeader(response.headers.get("retry-after"))
        )
      : 0;
    throw error;
  }
  return data.result;
}

async function telegramApiAt(apiBase, method, payload, beforeRequest = null) {
  assertPlatformEnabled("telegram");
  const normalizedApiBase = String(apiBase || TELEGRAM_DEFAULT_API_BASE_URL).replace(/\/$/, "");
  const requestBody = JSON.stringify(payload);
  if (beforeRequest) await beforeRequest();
  const response = await fetch(`${normalizedApiBase}/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: requestBody,
    signal: AbortSignal.timeout(API_REQUEST_TIMEOUT_MS)
  });
  return telegramResponseResult(response, method);
}

async function telegramMultipartApiAt(
  apiBase,
  method,
  payload,
  fileField,
  fileContent,
  filename,
  mimeType,
  beforeRequest = null
) {
  assertPlatformEnabled("telegram");
  const normalizedApiBase = String(apiBase || TELEGRAM_DEFAULT_API_BASE_URL).replace(/\/$/, "");
  const fields = Object.fromEntries(Object.entries(payload || {})
    .filter(([key, value]) => key !== fileField && value !== undefined && value !== null)
    .map(([key, value]) => [
      key,
      typeof value === "object" ? JSON.stringify(value) : String(value)
    ]));
  const multipart = createMultipartFileUpload({
    content: fileContent,
    fieldName: fileField,
    filename,
    mimeType,
    fields
  });
  if (beforeRequest) await beforeRequest();
  const response = await fetch(`${normalizedApiBase}/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: {
      "content-type": multipart.contentType,
      "content-length": String(multipart.contentLength)
    },
    body: multipart.body,
    duplex: "half",
    signal: AbortSignal.timeout(MEDIA_TRANSFER_TIMEOUT_MS)
  });
  return telegramResponseResult(response, method);
}

async function tgApi(method, payload, beforeRequest = null) {
  const chatId = payload?.chat_id;
  const isChatWrite = chatId != null && /^(?:send|copy|forward|editMessage|deleteMessage)/.test(method);
  if (!isChatWrite) {
    return telegramApiAt(env.TELEGRAM_API_BASE_URL, method, payload, beforeRequest);
  }
  return withPlatformChatSendLimit(
    "telegram",
    chatId,
    () => telegramApiAt(env.TELEGRAM_API_BASE_URL, method, payload, beforeRequest)
  );
}

async function tgMultipartApi(
  method,
  payload,
  fileField,
  fileContent,
  filename,
  mimeType,
  beforeRequest = null
) {
  const chatId = payload?.chat_id;
  const send = () => telegramMultipartApiAt(
    env.TELEGRAM_API_BASE_URL,
    method,
    payload,
    fileField,
    fileContent,
    filename,
    mimeType,
    beforeRequest
  );
  if (chatId == null) return send();
  return withPlatformChatSendLimit("telegram", chatId, send);
}

let telegramBotIdentity = null;

async function getTelegramBotIdentity() {
  if (!telegramBotIdentity) telegramBotIdentity = await tgApi("getMe", {});
  return telegramBotIdentity;
}

function forwardedTelegramChannel(message) {
  const origin = message?.forward_origin;
  if (origin?.type === "channel" && origin.chat?.id) return origin.chat;
  if (message?.forward_from_chat?.id && message.forward_from_chat.type === "channel") return message.forward_from_chat;
  return null;
}

async function claimForwardedTelegramChannel(userId, forwardedChat) {
  const chatId = String(forwardedChat.id);
  const [bot, userAccess] = await Promise.all([
    getTelegramBotIdentity(),
    accountAccess("telegram", userId)
  ]);
  assertPublicAccountAccess(userAccess, env.PUBLIC_TELEGRAM_ENABLED);
  const adminStatuses = new Set(["creator", "administrator"]);
  let botMember = null;
  let userMember = null;
  try {
    botMember = await tgApi("getChatMember", { chat_id: chatId, user_id: bot.id });
  } catch (error) {
    debugLog("telegram_bot_member_check_unavailable", { chatId, error: error.message });
  }
  try {
    userMember = await tgApi("getChatMember", { chat_id: chatId, user_id: userId });
  } catch (error) {
    debugLog("telegram_user_member_check_unavailable", { chatId, userId: String(userId), error: error.message });
    try {
      const administrators = await tgApi("getChatAdministrators", { chat_id: chatId });
      userMember = administrators.find((member) => String(member?.user?.id) === String(userId)) || null;
    } catch (adminError) {
      debugLog("telegram_administrator_list_unavailable", { chatId, userId: String(userId), error: adminError.message });
    }
  }
  const botCanPost = adminStatuses.has(botMember?.status)
    && (botMember.status === "creator" || botMember.can_post_messages);
  if (!botCanPost) {
    throw new Error("Сначала добавьте @GitRePosted_Bot администратором этого Telegram-канала с правом публикации.");
  }
  if (!userMember || !adminStatuses.has(userMember.status)) {
    throw new Error("Канал не добавлен: ваш Telegram-аккаунт должен быть владельцем или администратором канала.");
  }
  await reconcileTelegramBridgeIds(chatId);
  const owners = await db(
    "SELECT account_id FROM account_channels WHERE platform = 'telegram' AND chat_id = ? AND account_id <> ? LIMIT 1",
    [chatId, userAccess.account.id]
  );
  if (owners[0]) throw new Error("Этот Telegram-канал уже закреплён за другим пользователем GitRePosted.");
  let fullChat = null;
  try {
    fullChat = await tgApi("getChat", { chat_id: chatId });
  } catch (error) {
    debugLog("telegram_get_chat_unavailable", { chatId, error: error.message });
  }
  await upsertTelegramChannel(
    chatId,
    fullChat?.title || forwardedChat.title || chatId,
    fullChat?.username || forwardedChat.username || null,
    botMember.status,
    1
  );
  await grantAccountChannel("telegram", userId, chatId);
  return fullChat?.title || forwardedChat.title || chatId;
}

async function maxApiRequest(path, init = {}, beforeRequest = null) {
  assertPlatformEnabled("max");
  if (beforeRequest) await beforeRequest();
  const response = await fetch(`${env.MAX_API_BASE_URL}${path}`, {
    ...init,
    signal: init.signal || AbortSignal.timeout(API_REQUEST_TIMEOUT_MS),
    headers: {
      Authorization: env.MAX_BOT_TOKEN,
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...(init.headers || {})
    }
  });
  const text = await response.text();
  if (!response.ok) {
    const error = new Error(`MAX ${path}: ${response.status} ${text}`);
    error.code = response.status === 429 ? "MAX_RATE_LIMIT" : "MAX_API_ERROR";
    error.httpStatus = response.status;
    error.retryAfterSeconds = response.status === 429
      ? Math.max(1, retryAfterSecondsFromHeader(response.headers.get("retry-after")))
      : 0;
    throw error;
  }
  if (!text) return {};
  try {
    const data = JSON.parse(text);
    if (data && typeof data === "object" && data.success === false) {
      const error = new Error(
        `MAX ${path}: запрос отклонён${data.message ? `: ${data.message}` : "."}`
      );
      error.code = "MAX_API_REJECTED";
      error.httpStatus = response.status;
      throw error;
    }
    return data;
  } catch (cause) {
    if (cause?.code === "MAX_API_REJECTED") throw cause;
    const error = new Error(`MAX ${path}: ${response.status} invalid JSON response`);
    error.code = "MAX_AMBIGUOUS_RESPONSE";
    error.httpStatus = response.status;
    error.cause = cause;
    throw error;
  }
}

async function maxApi(path, init = {}, beforeRequest = null) {
  let chatId = "";
  try {
    const requestUrl = new URL(String(path), "https://max.invalid");
    if (String(init.method || "GET").toUpperCase() === "POST"
      && requestUrl.pathname === "/messages") {
      chatId = requestUrl.searchParams.get("chat_id") || "";
    }
  } catch {
  }
  if (!chatId) return maxApiRequest(path, init, beforeRequest);
  return withPlatformChatSendLimit(
    "max",
    chatId,
    () => maxApiRequest(path, init, beforeRequest)
  );
}

async function maxUpload(type, content, filename = "upload.bin", mimeType = "application/octet-stream") {
  const meta = await maxApi(`/uploads?type=${encodeURIComponent(type)}`, { method: "POST" });
  const multipart = createMultipartFileUpload({
    content,
    filename,
    mimeType
  });
  const uploadResponse = await fetch(meta.url, {
    method: "POST",
    headers: {
      "content-type": multipart.contentType,
      "content-length": String(multipart.contentLength)
    },
    body: multipart.body,
    duplex: "half",
    signal: AbortSignal.timeout(MEDIA_TRANSFER_TIMEOUT_MS)
  });
  const uploadText = await uploadResponse.text();
  if (!uploadResponse.ok) {
    throw new Error(`MAX upload ${type}: ${uploadResponse.status} ${uploadText}`);
  }
  let uploaded = {};
  try {
    uploaded = uploadText ? JSON.parse(uploadText) : {};
  } catch {
    uploaded = {};
  }
  return extractMaxUploadToken(uploaded) || extractMaxUploadToken(meta);
}

async function telegramFileSource(fileId) {
  const file = await tgApi("getFile", { file_id: fileId });
  if (String(file.file_path || "").startsWith("/")) return { localPath: file.file_path };
  const apiBase = String(env.TELEGRAM_API_BASE_URL || "https://api.telegram.org").replace(/\/$/, "");
  return { url: `${apiBase}/file/bot${env.TELEGRAM_BOT_TOKEN}/${file.file_path}` };
}

async function telegramFileToMaxAttachment(fileId, type, filename, mimeType) {
  debugLog("telegram_file_transfer_started", { type, filename });
  const source = await telegramFileSource(fileId);
  let content;
  if (source.localPath) {
    content = await createTelegramLocalFileContent(source.localPath, {
      containerRoot: TELEGRAM_BOT_API_CONTAINER_DATA_DIR,
      hostRoot: TELEGRAM_BOT_API_HOST_DATA_DIR
    });
  } else {
    const response = await fetch(source.url, {
      signal: AbortSignal.timeout(MEDIA_TRANSFER_TIMEOUT_MS)
    });
    if (!response.ok) throw new Error(`Telegram file download: ${response.status} ${filename}`);
    content = await response.arrayBuffer();
  }
  const byteLength = Number(content?.byteLength || 0);
  debugLog("telegram_file_downloaded", { type, filename, bytes: byteLength });
  const attachment = await uploadMaxAttachmentWithFallbacks({
    upload: maxUpload,
    type,
    bytes: content,
    filename,
    mimeType
  });
  if (attachment.renamedTo) {
    debugLog("telegram_file_renamed_for_max", {
      filename,
      archiveName: attachment.renamedTo,
      bytes: byteLength
    });
  }
  debugLog("telegram_file_uploaded_to_max", { type, filename, bytes: byteLength });
  return attachment;
}

async function telegramImageToMaxAttachment(fileId, filename, mimeType = "image/jpeg") {
  return telegramFileToMaxAttachment(fileId, "image", filename, mimeType);
}

async function telegramMessageToMaxPayload(message) {
  const formatted = telegramMessageTextForMax(message);
  const plainText = typeof message?.text === "string"
    ? message.text
    : typeof message?.caption === "string"
      ? message.caption
      : "";
  const attachments = [];
  if (Array.isArray(message?.photo) && message.photo.length) {
    const best = message.photo[message.photo.length - 1];
    attachments.push(await telegramImageToMaxAttachment(best.file_id, `photo-${message.message_id}.jpg`));
  }
  if (message?.document) {
    const descriptor = telegramDocumentUploadDescriptor(message.document, message.message_id);
    attachments.push(await telegramFileToMaxAttachment(
      descriptor.fileId,
      descriptor.type,
      descriptor.filename,
      descriptor.mimeType
    ));
  }
  const media = message?.video || message?.animation || message?.audio || message?.voice;
  if (media) {
    const type = message.video || message.animation ? "video" : "audio";
    attachments.push(await telegramFileToMaxAttachment(
      media.file_id,
      type,
      media.file_name || `${type}-${message.message_id}.${type === "video" ? "mp4" : "ogg"}`,
      media.mime_type || (type === "video" ? "video/mp4" : "audio/ogg")
    ));
  }
  if (message?.sticker) {
    const sticker = message.sticker;
    const isVideo = Boolean(sticker.is_video);
    attachments.push(await telegramFileToMaxAttachment(
      sticker.file_id,
      isVideo ? "video" : "file",
      `sticker-${message.message_id}.${isVideo ? "webm" : sticker.is_animated ? "tgs" : "webp"}`,
      isVideo ? "video/webm" : sticker.is_animated ? "application/gzip" : "image/webp"
    ));
  }
  attachments.push(...telegramSpecialAttachmentsForMax(message));
  const inlineKeyboard = telegramInlineKeyboardForMax(message?.reply_markup);
  attachments.push(...inlineKeyboard.attachments);
  const renameNotes = attachments
    .flatMap((attachment) => {
      const notes = [];
      if (attachment.renamedFrom && attachment.renamedTo) {
        notes.push(`Примечание: после скачивания файла «${attachment.renamedTo}» удалите окончание .zip, чтобы получить «${attachment.renamedFrom}».`);
      }
      if (attachment.deliveryNote) notes.push(attachment.deliveryNote);
      return notes;
    });
  const cleanAttachments = attachments.map(({
    renamedFrom,
    renamedTo,
    deliveryNote,
    ...attachment
  }) => attachment);
  const formattedNotes = formatted.format === "html"
    ? renameNotes.map((note) => escapeHtml(note))
    : renameNotes;
  return {
    text: [formatted.text, ...formattedNotes].filter(Boolean).join("\n\n"),
    plainText: [plainText, ...renameNotes].filter(Boolean).join("\n\n"),
    format: formatted.format,
    attachments: cleanAttachments,
    supplements: inlineKeyboard.supplements
  };
}

async function relayTargetIsActive(
  routeId,
  sourcePlatform,
  sourceChatId,
  targetPlatform,
  targetChatId,
  expectedTargetId = null
) {
  const sourceBlockColumn = sourcePlatform === "max" ? "max_blocked" : "telegram_blocked";
  const sourceChatIds = sourcePlatform === "telegram"
    ? [...new Set([
        String(sourceChatId),
        normalizeTelegramChatId(sourceChatId),
        legacyTelegramChatId(sourceChatId)
      ].filter(Boolean))]
    : [String(sourceChatId)];
  const targetChatIds = targetPlatform === "telegram"
    ? [...new Set([
        String(targetChatId),
        normalizeTelegramChatId(targetChatId),
        legacyTelegramChatId(targetChatId)
      ].filter(Boolean))]
    : [String(targetChatId)];
  const sourcePlaceholders = sourceChatIds.map(() => "?").join(",");
  const targetPlaceholders = targetChatIds.map(() => "?").join(",");
  const rows = await db(`SELECT r.source_chat_id, t.chat_id AS target_chat_id
    FROM repost_routes r
    JOIN repost_route_targets t ON t.route_id = r.id
      AND t.platform = ? AND t.chat_id IN (${targetPlaceholders})
    JOIN linked_accounts a ON a.id = r.account_id
      AND a.is_blocked = 0 AND a.${sourceBlockColumn} = 0
    JOIN account_channels src ON src.account_id = r.account_id
      AND src.platform = r.source_platform AND src.chat_id = r.source_chat_id
      AND src.is_blocked = 0
    JOIN account_channels dst ON dst.account_id = r.account_id
      AND dst.platform = t.platform AND dst.chat_id = t.chat_id
      AND dst.is_blocked = 0
    WHERE r.id = ? AND r.enabled = 1
      AND r.source_platform = ? AND r.source_chat_id IN (${sourcePlaceholders})
      AND (? IS NULL OR t.id = ?)
    LIMIT 1`, [
    targetPlatform,
    ...targetChatIds,
    String(routeId),
    sourcePlatform,
    ...sourceChatIds,
    expectedTargetId,
    expectedTargetId
  ]);
  if (!rows[0]) return null;
  const resolvedSourceChatId = sourcePlatform === "telegram"
    ? normalizeTelegramChatId(rows[0].source_chat_id)
    : String(rows[0].source_chat_id);
  const resolvedTargetChatId = targetPlatform === "telegram"
    ? normalizeTelegramChatId(rows[0].target_chat_id)
    : String(rows[0].target_chat_id);
  const channels = new Map([
    [`${sourcePlatform}:${resolvedSourceChatId}`, { platform: sourcePlatform, chatId: resolvedSourceChatId }],
    [`${targetPlatform}:${resolvedTargetChatId}`, { platform: targetPlatform, chatId: resolvedTargetChatId }]
  ]);
  for (const channel of channels.values()) {
    if (!(await channelHasPublishingAccess(channel.platform, channel.chatId))) return null;
  }
  return {
    sourceChatId: resolvedSourceChatId,
    targetChatId: resolvedTargetChatId
  };
}

async function deliverTelegramChannelPosts(job, assertOwned) {
  const messages = job.messages;
  const uniqueMessages = [...new Map(
    messages
      .filter(Boolean)
      .map((message) => [String(message.message_id || ""), message])
      .filter(([messageId]) => messageId)
  ).values()].sort((left, right) => Number(left.message_id) - Number(right.message_id));
  const first = uniqueMessages[0];
  const chat = first?.chat || {};
  if (!chat.id) throw new Error("Persisted Telegram relay payload has no chat ID.");
  const sourceIdentity = {
    ...job.identity,
    messageIds: normalizePlatformMessageIds(
      uniqueMessages.map((message) => message.message_id)
    )
  };
  await assertOwned();
  if (await shouldIgnoreOutboundWebhook(
    sourceIdentity.platform,
    sourceIdentity.chatId,
    sourceIdentity.messageIds
  )) {
    debugLog("relay_outbound_webhook_ignored", {
      platform: sourceIdentity.platform,
      chatId: sourceIdentity.chatId,
      messageIds: sourceIdentity.messageIds
    });
    return;
  }

  const rows = Array.isArray(job.routes) ? job.routes : [];
  if (!rows.length) return;
  let maxPayloads = null;
  const targetFailures = [];
  for (const row of rows) {
    await assertOwned();
    try {
      const activeTarget = await relayTargetIsActive(
        row.route_id,
        "telegram",
        chat.id,
        row.platform,
        row.chat_id,
        row.target_id || null
      );
      if (!activeTarget) {
        debugLog("relay_target_no_longer_active", {
          routeId: row.route_id,
          sourcePlatform: "telegram",
          sourceChatId: String(chat.id),
          targetPlatform: row.platform,
          targetChatId: String(row.chat_id)
        });
        continue;
      }
      const deliveryTargetChatId = activeTarget.targetChatId;
      if (await outboundTargetIsCompleted(sourceIdentity, row.platform, deliveryTargetChatId)) {
        continue;
      }
      if (row.platform === "max") {
        if (!maxPayloads) {
          const parts = await mapSequential(uniqueMessages, telegramMessageToMaxPayload);
          maxPayloads = splitMaxPayload(combineTelegramPayloadParts(parts));
        }
        if (!maxPayloads.length) {
          const error = new Error("Telegram relay payload has no MAX-compatible content.");
          error.code = "RELAY_PAYLOAD_EMPTY";
          throw error;
        }
        for (let index = 0; index < maxPayloads.length; index += 1) {
          const maxPayload = maxPayloads[index];
          await sendTrackedOutbound({
            sourceIdentity,
            targetPlatform: "max",
            targetChatId: deliveryTargetChatId,
            operationKey: maxPayloads.length === 1 ? "whole" : `message:${index}`,
            send: (markRequestStarted) => sendMaxPayload(
              deliveryTargetChatId,
              maxPayload,
              markRequestStarted
            ),
            extractMessageIds: extractMaxOutboundMessageIds
          });
        }
      } else if (uniqueMessages.length > 1) {
        await sendTrackedOutbound({
          sourceIdentity,
          targetPlatform: "telegram",
          targetChatId: deliveryTargetChatId,
          send: (markRequestStarted) => {
            return tgApi("copyMessages", {
              chat_id: deliveryTargetChatId,
              from_chat_id: chat.id,
              message_ids: uniqueMessages.map((message) => message.message_id)
            }, markRequestStarted);
          },
          extractMessageIds: extractTelegramOutboundMessageIds
        });
      } else {
        await sendTrackedOutbound({
          sourceIdentity,
          targetPlatform: "telegram",
          targetChatId: deliveryTargetChatId,
          send: (markRequestStarted) => {
            return tgApi("copyMessage", {
              chat_id: deliveryTargetChatId,
              from_chat_id: chat.id,
              message_id: first.message_id
            }, markRequestStarted);
          },
          extractMessageIds: extractTelegramOutboundMessageIds
        });
      }
      await markOutboundTargetCompleted(sourceIdentity, row.platform, deliveryTargetChatId);
      debugLog("telegram_relay_delivered", {
        sourceChatId: String(chat.id),
        sourceMessageIds: sourceIdentity.messageIds,
        targetPlatform: row.platform,
        targetChatId: String(deliveryTargetChatId),
        attachments: row.platform === "max"
          ? (maxPayloads || []).reduce((total, item) => total + item.attachments.length, 0)
          : 0
      });
    } catch (error) {
      if (error?.code === "RELAY_SOURCE_LEASE_LOST") throw error;
      targetFailures.push({ row, error });
      debugLog("telegram_relay_target_failed", {
        routeId: row.route_id,
        targetPlatform: row.platform,
        targetChatId: String(row.chat_id),
        code: relayFailureCode(error)
      });
    }
  }
  throwRelayTargetFailures(targetFailures);
}

let telegramRelayWorkerRunning = false;

async function processTelegramRelayJob(job) {
  try {
    await withRelaySourceHeartbeat(
      job,
      (assertOwned) => deliverTelegramChannelPosts(job, assertOwned),
      "telegram_relay"
    );
    const completed = await finishRelaySourceEvent(
      job.identity,
      "completed",
      null,
      job.leaseToken
    );
    if (!completed) {
      debugLog("telegram_relay_completion_lease_lost", {
        eventId: job.identity.eventId
      });
    }
  } catch (error) {
    const retryAfterSeconds = relayRetryAfterSeconds(error);
    const failure = relayHasFailureCode(error, "OUTBOUND_DELIVERY_UNCERTAIN")
      ? await terminalizeRelayJobWithCode(job, "OUTBOUND_DELIVERY_UNCERTAIN")
      : error?.code === "OUTBOUND_ECHO_UNCERTAIN"
      ? await terminalizeRelayJobWithCode(job, "OUTBOUND_ECHO_UNCERTAIN")
      : error?.code === "OUTBOUND_ECHO_PENDING"
      ? await deferRelayJobWithoutAttempt(job, error)
      : retryAfterSeconds > 0
        ? await deferRelayJobWithoutAttempt(job, error, retryAfterSeconds)
      : await failRelayJob(job, error);
    debugLog(
      failure.uncertain
        ? "telegram_relay_delivery_uncertain"
        : failure.deferred
        ? "telegram_relay_deferred"
        : failure.terminal ? "telegram_relay_terminal" : "telegram_relay_retry_scheduled",
      {
      eventId: job.identity.eventId,
      attempt: job.attemptCount,
      retryDelaySeconds: failure.retryDelay,
      leaseOwned: failure.updated,
      code: relayFailureCode(error),
      causeCode: error?.cause ? relayFailureCode(error.cause) : null
      }
    );
  }
}

async function runTelegramRelayWorker() {
  if (!workersEnabled(env) || !platformEnabled(env, "telegram")) return;
  if (telegramRelayWorkerRunning) return;
  telegramRelayWorkerRunning = true;
  try {
    for (let processed = 0; processed < 25; processed += 1) {
      const job = await claimNextRelayJob("telegram");
      if (!job) break;
      if (job.terminalized) {
        debugLog("telegram_relay_terminal", {
          eventId: job.eventId,
          attempt: job.attemptCount,
          code: job.code || "retry_limit_exhausted"
        });
        continue;
      }
      await processTelegramRelayJob(job);
    }
  } catch (error) {
    debugLog("telegram_relay_worker_failed", {
      code: relayFailureCode(error)
    });
  } finally {
    telegramRelayWorkerRunning = false;
  }
}

function startTelegramRelayWorker() {
  if (!workersEnabled(env) || !platformEnabled(env, "telegram")) return;
  void runTelegramRelayWorker();
  const timer = setInterval(
    () => void runTelegramRelayWorker(),
    RELAY_RETRY_POLICY.pollMilliseconds
  );
  timer.unref?.();
}

async function queueTelegramUpdate(update) {
  const updateId = String(update?.update_id ?? "");
  const existing = updateId ? telegramUpdateIds.get(updateId) : null;
  if (existing) {
    await existing;
    return;
  }
  const eventType = telegramIngressEventType(update);
  const processing = (async () => {
    const receipt = await claimBotEventReceipt("telegram", eventType, updateId);
    if (!receipt.claimed) {
      debugLog("telegram_update_duplicate", { updateId: updateId || null, eventType });
      if (receipt.disposition === "in_progress") {
        const error = new Error("Telegram update is already being processed.");
        error.code = "BOT_EVENT_IN_PROGRESS";
        throw error;
      }
      return;
    }
    try {
      await withBotEventReceiptHeartbeat(receipt, async (assertReceipt) => {
        await assertReceipt();
        const replayed = await replayTelegramBotAction(update, receipt);
        if (!replayed) {
          if (update.my_chat_member) {
            await assertReceipt();
            await handleTelegramMyChatMember(update.my_chat_member);
          }
          if (update.callback_query) {
            await assertReceipt();
            await handleTelegramCallback(update.callback_query, receipt);
          }
          if (update.message) {
            await assertReceipt();
            await handleTelegramMessage(update.message, receipt);
          }
          if (update.channel_post || update.edited_channel_post) {
            await assertReceipt();
            await handleTelegramChannelPost(update.channel_post || update.edited_channel_post);
          }
        }
        await assertReceipt();
      });
      const finished = await finishBotEventReceipt(receipt, "telegram", "completed");
      if (!finished) {
        const error = new Error("Telegram update receipt lease was lost.");
        error.code = "BOT_EVENT_LEASE_LOST";
        throw error;
      }
    } catch (error) {
      try {
        await finishBotEventReceipt(receipt, "telegram", "failed", error);
      } catch (receiptError) {
        debugLog("telegram_update_receipt_finish_failed", {
          updateId: updateId || null,
          code: relayFailureCode(receiptError)
        });
      }
      throw error;
    }
  })();
  if (updateId) {
    telegramUpdateIds.set(updateId, processing);
    while (telegramUpdateIds.size > 2000) {
      const oldest = telegramUpdateIds.keys().next().value;
      if (oldest === undefined) break;
      telegramUpdateIds.delete(oldest);
    }
  }
  try {
    await processing;
  } catch (error) {
    if (updateId && telegramUpdateIds.get(updateId) === processing) {
      telegramUpdateIds.delete(updateId);
    }
    debugLog("telegram_update_failed", {
      updateId: updateId || null,
      messageId: update?.channel_post?.message_id || update?.edited_channel_post?.message_id || null,
      message: error.message
    });
    throw error;
  }
}

async function replayTelegramBotAction(update, receipt) {
  const result = receipt?.result;
  const retryGuaranteedResponseFailure = receipt?.lastError === "TELEGRAM_RATE_LIMIT";
  if (result?.action === "telegram_reply_state") {
    if (retryGuaranteedResponseFailure && update?.message?.chat?.id && update?.message?.from?.id) {
      const chatId = update.message.chat.id;
      const userId = update.message.from.id;
      const payload = parseStatePayload(result.state_payload);
      if (result.state === "route_source_reply") {
        await sendTelegramRouteSourceKeyboard(
          chatId,
          userId,
          Number(payload.page || 0),
          { persistState: false }
        );
      } else if (result.state === "route_targets_reply") {
        await sendTelegramRouteTargetKeyboard(
          chatId,
          userId,
          payload,
          Number(payload.page || 0),
          { persistState: false }
        );
      } else {
        await sendTelegramMenu(chatId);
      }
    }
    debugLog("telegram_reply_state_replayed_without_duplicate_send", {
      updateId: String(update?.update_id || ""),
      state: result.state || null,
      responseRetried: retryGuaranteedResponseFailure
    });
    return true;
  }
  if (result?.action === "consume_link_code") {
    if (retryGuaranteedResponseFailure && update?.message?.chat?.id) {
      await tgApi("sendMessage", {
        chat_id: update.message.chat.id,
        text: result.message || "Аккаунты Telegram и МАКС успешно связаны."
      });
    }
    debugLog("telegram_link_result_replayed_without_duplicate_send", {
      updateId: String(update?.update_id || ""),
      responseRetried: retryGuaranteedResponseFailure
    });
    return true;
  }
  if (result?.action !== "save_route") return false;
  const count = Number(result.target_count || 0);
  if (result.response_kind === "callback" && update?.callback_query?.message) {
    const message = update.callback_query.message;
    await editTelegramMenu(
      message.chat.id,
      message.message_id,
      `Пересылка сохранена. Получателей: ${count}.`,
      [[{ text: "← В меню", callback_data: "tg:menu" }]]
    );
  } else if (result.response_kind === "message"
    && retryGuaranteedResponseFailure
    && update?.message?.chat?.id) {
    await sendTelegramMenu(update.message.chat.id, "Пересылка сохранена.");
  }
  // For reply-keyboard messages, retrying a completed provider send could create
  // a duplicate confirmation. The route and cleared state are already durable.
  return true;
}

function maxAttachmentList(message) {
  if (Array.isArray(message?.body?.attachments)) return message.body.attachments;
  return Array.isArray(message?.attachments) ? message.attachments : [];
}

function maxInlineKeyboardToTelegram(attList, messageText = "") {
  const attachments = Array.isArray(attList) ? attList : [];
  const kb = attachments.find((item) => item?.type === "inline_keyboard")?.payload?.buttons;
  const rows = maxInlineKeyboardRowsForTelegram(kb);
  const shareUrls = new Set();
  for (const item of attachments) {
    if (item?.type !== "share") continue;
    const url = telegramCompatibleUrl(item?.payload?.url);
    if (!url || !/^https?:/i.test(url)
      || String(messageText || "").includes(url) || shareUrls.has(url)) {
      continue;
    }
    shareUrls.add(url);
    rows.push([{
      text: compactUnicodeText(item?.title, 64, "Открыть ссылку"),
      url
    }]);
  }
  return rows.length ? { inline_keyboard: rows } : null;
}

async function fetchMaxMessage(messageId) {
  if (!messageId) return null;
  try {
    const response = await maxApi(`/messages?message_ids=${encodeURIComponent(String(messageId))}`);
    if (Array.isArray(response?.messages) && response.messages.length) return response.messages[0];
    if (Array.isArray(response) && response.length) return response[0];
    if (response?.message) return response.message;
    return response;
  } catch (error) {
    debugLog("max_fetch_message_failed", { messageId: String(messageId), message: error.message });
    return null;
  }
}

async function sendMaxPayload(chatId, payload, markRequestStarted = () => {}) {
  return maxApi(`/messages?chat_id=${encodeURIComponent(String(chatId))}`, {
    method: "POST",
    body: JSON.stringify({
      text: payload.text || "",
      attachments: payload.attachments || [],
      ...(payload.format ? { format: payload.format } : {})
    })
  }, markRequestStarted);
}

async function sendTelegramBridgeMessage(
  chatId,
  payload,
  sendPart = async (_operationKey, send) => send(() => {})
) {
  const text = payload.text || "";
  const supplementalTexts = (Array.isArray(payload.supplemental_texts)
    ? payload.supplemental_texts
    : [])
    .filter((value) => typeof value === "string" && value.length);
  const replyMarkup = payload.reply_markup || undefined;
  const entities = Array.isArray(payload.entities) && payload.entities.length
    ? payload.entities
    : undefined;
  const media = Array.isArray(payload.media)
    ? payload.media.filter((item) => item?.source
      || item?.kind === "location"
      || item?.kind === "contact")
    : [];
  if (!media.length) {
    const textParts = [text || (supplementalTexts.length ? "" : "(пустое сообщение)"), ...supplementalTexts]
      .filter(Boolean);
    const results = [];
    for (let index = 0; index < textParts.length; index += 1) {
      const result = await sendPart(index === 0 ? "text" : `supplement:${index - 1}`, (markRequestStarted) => {
        return tgApi("sendMessage", {
          chat_id: chatId,
          text: textParts[index],
          ...(index === 0 && entities ? { entities } : {}),
          ...(replyMarkup && index === textParts.length - 1
            ? { reply_markup: replyMarkup }
            : {})
        }, markRequestStarted);
      });
      if (result) results.push(...(Array.isArray(result) ? result : [result]));
    }
    return results;
  }

  const sentMessages = [];
  const rememberResponse = (response) => {
    if (!response) return;
    sentMessages.push(...(Array.isArray(response) ? response : [response]));
  };
  const captionFits = text.length <= 1024;
  let captionSent = false;
  // MAX CDN URLs are first downloaded and then uploaded to Telegram. Telegram's
  // cloud API only fetches a narrow set of document URLs itself, and MAX accepts
  // more media formats than Telegram. Individual uploads preserve every file
  // without a provider-side remote-fetch or album-format rejection.
  const standalone = [...media];

  for (let index = 0; index < standalone.length; index += 1) {
    const item = standalone[index];
    const attachCaption = !captionSent && text && captionFits
      && item.kind !== "location" && item.kind !== "contact";
    const textRemains = Boolean(text && !captionSent && !attachCaption);
    const attachReplyMarkup = Boolean(
      replyMarkup
      && index === standalone.length - 1
      && !textRemains
      && supplementalTexts.length === 0
    );
    if (item.kind === "location" || item.kind === "contact") {
      const method = item.kind === "location" ? "sendLocation" : "sendContact";
      const specialPayload = item.kind === "location"
        ? { latitude: item.latitude, longitude: item.longitude }
        : {
            phone_number: item.phoneNumber,
            first_name: item.firstName,
            ...(item.vcard ? { vcard: item.vcard } : {})
          };
      rememberResponse(await sendPart(`media:${index}:${item.kind}`, (markRequestStarted) => {
        return tgApi(method, {
          chat_id: chatId,
          ...specialPayload,
          ...(attachReplyMarkup ? { reply_markup: replyMarkup } : {})
        }, markRequestStarted);
      }));
      continue;
    }
    const methodMap = {
      photo: ["sendPhoto", "photo"],
      video: ["sendVideo", "video"],
      audio: ["sendAudio", "audio"],
      document: ["sendDocument", "document"]
    };
    const localMode = telegramLocalFileModeEnabled();
    const uploadLimitBytes = localMode
      ? TELEGRAM_LOCAL_UPLOAD_LIMIT_BYTES
      : TELEGRAM_CLOUD_UPLOAD_LIMIT_BYTES;
    const fallbackText = `Вложение «${item.filename || "файл"}» слишком большое для загрузки в Telegram.\n${item.source}`;
    const sendSizeFallback = async (markRequestStarted) => {
      const withOriginalText = attachCaption
        ? `${text}\n\n${fallbackText}`
        : fallbackText;
      const includesOriginalText = Boolean(
        attachCaption && withOriginalText.length <= 4096
      );
      const result = await tgApi("sendMessage", {
        chat_id: chatId,
        text: includesOriginalText ? withOriginalText : fallbackText,
        ...(includesOriginalText && entities ? { entities } : {}),
        ...(replyMarkup
          && index === standalone.length - 1
          && supplementalTexts.length === 0
          && (includesOriginalText || !text || captionSent)
          ? { reply_markup: replyMarkup }
          : {})
      }, markRequestStarted);
      return result;
    };

    const mediaResponse = await sendPart(`media:${index}:${item.kind}`, async (markRequestStarted) => {
      if (Number.isFinite(item.byteLength) && item.byteLength > uploadLimitBytes) {
        return sendSizeFallback(markRequestStarted);
      }
      let temporaryFile;
      try {
        temporaryFile = await downloadMaxFileToTelegramRelay({
          url: item.source,
          filename: item.filename,
          hostRoot: TELEGRAM_BOT_API_HOST_DATA_DIR,
          containerRoot: TELEGRAM_BOT_API_CONTAINER_DATA_DIR,
          tempSubdir: TELEGRAM_RELAY_TEMP_SUBDIR,
          maxBytes: uploadLimitBytes,
          timeoutMs: MEDIA_TRANSFER_TIMEOUT_MS
        });
      } catch (error) {
        if (error?.code === "MAX_FILE_DOWNLOAD_FAILED" && error?.reasonCode === "FILE_TOO_LARGE") {
          return sendSizeFallback(markRequestStarted);
        }
        throw error;
      }
      try {
        const actualKind = item.kind === "photo"
          && temporaryFile.byteLength > TELEGRAM_PHOTO_UPLOAD_LIMIT_BYTES
          ? "document"
          : item.kind;
        const [method, field] = methodMap[actualKind] || methodMap.document;
        const requestPayload = {
          chat_id: chatId,
          ...(attachCaption ? {
            caption: text,
            ...(entities ? { caption_entities: entities } : {})
          } : {}),
          ...(attachReplyMarkup ? { reply_markup: replyMarkup } : {})
        };
        const upload = (uploadMethod, uploadField) => localMode
          ? tgApi(uploadMethod, {
              ...requestPayload,
              [uploadField]: temporaryFile.containerPath
            }, markRequestStarted)
          : tgMultipartApi(
              uploadMethod,
              requestPayload,
              uploadField,
              temporaryFile,
              temporaryFile.filename,
              item.mimeType,
              markRequestStarted
            );
        try {
          return await upload(method, field);
        } catch (error) {
          const definitelyRejectedMedia = actualKind !== "document"
            && error?.code === "TELEGRAM_API_ERROR"
            && Number(error?.httpStatus) === 400;
          if (!definitelyRejectedMedia) throw error;
          debugLog("telegram_media_degraded_to_document", {
            sourceKind: actualKind,
            filename: temporaryFile.filename
          });
          return upload("sendDocument", "document");
        }
      } finally {
        try {
          await temporaryFile.cleanup();
        } catch (error) {
          debugLog("telegram_relay_temp_cleanup_failed", {
            code: relayFailureCode(error)
          });
        }
      }
    });
    rememberResponse(mediaResponse);
    captionSent ||= Boolean(attachCaption);
  }

  if (text && !captionSent) {
    rememberResponse(await sendPart("text", (markRequestStarted) => {
      return tgApi("sendMessage", {
        chat_id: chatId,
        text,
        ...(entities ? { entities } : {}),
        ...(replyMarkup && supplementalTexts.length === 0
          ? { reply_markup: replyMarkup }
          : {})
      }, markRequestStarted);
    }));
  }
  for (let index = 0; index < supplementalTexts.length; index += 1) {
    rememberResponse(await sendPart(`supplement:${index}`, (markRequestStarted) => {
      return tgApi("sendMessage", {
        chat_id: chatId,
        text: supplementalTexts[index],
        ...(replyMarkup && index === supplementalTexts.length - 1
          ? { reply_markup: replyMarkup }
          : {})
      }, markRequestStarted);
    }));
  }
  return sentMessages;
}

function telegramLocalFileModeEnabled() {
  if (env.TELEGRAM_LOCAL_FILE_MODE === "1") return true;
  if (env.TELEGRAM_LOCAL_FILE_MODE === "0") return false;
  try {
    const apiUrl = new URL(String(env.TELEGRAM_API_BASE_URL || ""));
    return ["127.0.0.1", "localhost", "::1"].includes(apiUrl.hostname);
  } catch {
    return false;
  }
}

function firstHttpUrl(...values) {
  for (const value of values) {
    if (typeof value !== "string" || value.length > 2048
      || /[\u0000-\u001f\u007f]/.test(value)) {
      continue;
    }
    try {
      const parsed = new URL(value);
      if (["http:", "https:"].includes(parsed.protocol)
        && parsed.hostname
        && !parsed.username
        && !parsed.password
        && parsed.href.length <= 2048) {
        return parsed.href;
      }
    } catch {
    }
  }
  return null;
}

function maxAttachmentMimeType(item, kind, filename) {
  const payload = item?.payload && typeof item.payload === "object" ? item.payload : {};
  const declared = [
    payload.mime_type,
    payload.content_type,
    item?.mime_type,
    item?.content_type
  ].find((value) => typeof value === "string"
    && /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(value));
  if (declared) return declared;
  const lowerFilename = String(filename || "").toLowerCase();
  if (lowerFilename.endsWith(".png")) return "image/png";
  if (lowerFilename.endsWith(".webp")) return "image/webp";
  if (lowerFilename.endsWith(".jpg") || lowerFilename.endsWith(".jpeg")) return "image/jpeg";
  if (lowerFilename.endsWith(".mp4")) return "video/mp4";
  if (lowerFilename.endsWith(".mp3")) return "audio/mpeg";
  if (lowerFilename.endsWith(".m4a")) return "audio/mp4";
  return kind === "photo" ? "image/jpeg" : "application/octet-stream";
}

function maxAttachmentsToTelegram(attList) {
  return attList.flatMap((item, index) => {
    const type = String(item?.type || "").toLowerCase();
    if (type === "inline_keyboard" || type === "share") return [];
    const special = maxSpecialAttachmentForTelegram(item);
    if (special) return [special];
    const payload = item?.payload || {};
    const source = firstHttpUrl(
      payload.url,
      payload.image_url,
      payload.video_url,
      payload.audio_url,
      payload.file_url,
      payload?.urls?.mp4,
      payload?.urls?.download,
      item?.url,
      item?.image_url
    );
    if (!source) return [];
    const filename = maxAttachmentFilename(item, index);
    const kind = telegramKindForMaxAttachment(item, source);
    const declaredSize = Number(payload.size ?? item?.size);
    return [{
      kind,
      source,
      filename,
      mimeType: maxAttachmentMimeType(item, kind, filename),
      ...(Number.isFinite(declaredSize) && declaredSize >= 0
        ? { byteLength: declaredSize }
        : {})
    }];
  });
}

function tgInline(rows) {
  return { inline_keyboard: rows };
}

function tgReplyKeyboard(rows) {
  return {
    keyboard: rows.map((row) => row.map((button) => typeof button === "string" ? { text: button } : button)),
    resize_keyboard: true,
    is_persistent: true,
    input_field_placeholder: "Выберите действие"
  };
}

function tgRemoveKeyboard() {
  return { remove_keyboard: true };
}

function parsePositiveInt(value, fallback = 1) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parsePageZeroBased(value) {
  return Math.max(0, parsePositiveInt(value, 1) - 1);
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function paginateRows(rows, page = 0, perPage = 10) {
  const safePerPage = Math.max(1, perPage);
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / safePerPage));
  const safePage = clamp(page, 0, totalPages - 1);
  const start = safePage * safePerPage;
  return {
    page: safePage,
    perPage: safePerPage,
    total,
    totalPages,
    start,
    items: rows.slice(start, start + safePerPage)
  };
}

function makePageNav(currentPage, totalPages, prefix, backTarget) {
  if (totalPages <= 1) {
    return [[{ text: "← Назад", callback_data: backTarget }]];
  }
  const row = [];
  if (currentPage > 0) {
    row.push({ text: "←", callback_data: `${prefix}:${currentPage}` });
  }
  row.push({ text: `${currentPage + 1}/${totalPages}`, callback_data: "tg:noop" });
  if (currentPage + 1 < totalPages) {
    row.push({ text: "→", callback_data: `${prefix}:${currentPage + 2}` });
  }
  if (row.length > 0) {
    return [row, [{ text: "← Назад", callback_data: backTarget }]];
  }
  return [[{ text: "← Назад", callback_data: backTarget }]];
}

function makeMaxPageNav(currentPage, totalPages, prefix, backTarget) {
  if (totalPages <= 1) {
    return [[maxCallbackButton("← Назад", backTarget)]];
  }
  const row = [];
  if (currentPage > 0) {
    row.push(maxCallbackButton("←", `${prefix}:${currentPage}`));
  }
  row.push(maxCallbackButton(`${currentPage + 1}/${totalPages}`, "max:noop"));
  if (currentPage + 1 < totalPages) {
    row.push(maxCallbackButton("→", `${prefix}:${currentPage + 2}`));
  }
  if (row.length > 0) {
    return [row, [maxCallbackButton("← Назад", backTarget)]];
  }
  return [[maxCallbackButton("← Назад", backTarget)]];
}

function sendText(res, code, text, contentType = "text/plain; charset=utf-8") {
  res.writeHead(code, {
    "content-type": contentType,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()"
  });
  res.end(text);
}

function requestPublicBaseUrl(_req) {
  try {
    return publicBaseInfo(env.PUBLIC_BASE_URL).baseUrl;
  } catch {
    const error = new Error("PUBLIC_BASE_URL должен быть корректным HTTP(S)-адресом без query и fragment.");
    error.statusCode = 400;
    throw error;
  }
}

function unauthorized(res) {
  return json(res, 401, { error: "unauthorized" });
}

function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map((part) => {
    const index = part.indexOf("=");
    if (index < 0) return ["", ""];
    return [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())];
  }).filter(([key]) => key));
}

function secureEqual(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function adminSessionSignature(payload) {
  if (!adminApiKeyConfigured()) {
    throw new Error("ADMIN_API_KEY is not configured.");
  }
  return crypto.createHmac("sha256", String(env.ADMIN_API_KEY || ""))
    .update(payload)
    .digest("base64url");
}

function verifyAdminSession(sessionId) {
  if (!adminApiKeyConfigured()) return false;
  const parts = String(sessionId || "").split(".");
  if (parts.length !== 3) return false;
  const [expiresAt, nonce, signature] = parts;
  if (!/^\d+$/.test(expiresAt) || Number(expiresAt) <= Date.now() || !nonce) return false;
  if (!secureEqual(signature, adminSessionSignature(`${expiresAt}.${nonce}`))) return false;
  return adminSessions.has(sessionId, Number(expiresAt));
}

function ensureAdmin(req, url) {
  if (!adminApiKeyConfigured()) return false;
  const sessionId = parseCookies(req).reposted_admin_session;
  if (verifyAdminSession(sessionId)) return true;
  const auth = req.headers.authorization || "";
  return secureEqual(auth, `Bearer ${env.ADMIN_API_KEY}`);
}

function adminLoginBlocked(ip) {
  const state = adminLoginAttempts.get(ip);
  if (!state) return 0;
  if (state.blockedUntil > Date.now()) return Math.ceil((state.blockedUntil - Date.now()) / 60000);
  if (Date.now() - state.startedAt > 15 * 60 * 1000) adminLoginAttempts.delete(ip);
  return 0;
}

function recordAdminLoginFailure(ip) {
  const now = Date.now();
  const previous = adminLoginAttempts.get(ip);
  const state = previous && now - previous.startedAt < 15 * 60 * 1000
    ? previous
    : { count: 0, startedAt: now, blockedUntil: 0 };
  state.count += 1;
  if (state.count >= 5) state.blockedUntil = now + 15 * 60 * 1000;
  adminLoginAttempts.set(ip, state);
}

function createAdminSession(res) {
  const expiresAt = Date.now() + ADMIN_SESSION_TTL_MS;
  const payload = `${expiresAt}.${crypto.randomBytes(24).toString("base64url")}`;
  const sessionId = `${payload}.${adminSessionSignature(payload)}`;
  if (!adminSessions.register(sessionId, expiresAt)) {
    throw new Error("Не удалось создать административную сессию.");
  }
  res.setHeader("set-cookie", `reposted_admin_session=${sessionId}; Path=${publicLocalPath(env.PUBLIC_BASE_URL, "/")}; HttpOnly; Secure; SameSite=Strict; Max-Age=${ADMIN_SESSION_TTL_MS / 1000}`);
}

function clearAdminSession(req, res) {
  const sessionId = parseCookies(req).reposted_admin_session;
  if (sessionId) adminSessions.revoke(sessionId);
  res.setHeader("set-cookie", `reposted_admin_session=; Path=${publicLocalPath(env.PUBLIC_BASE_URL, "/")}; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
}

async function verifyHcaptcha(req, token) {
  if (env.HCAPTCHA_ENABLED === "0") return true;
  if (!env.HCAPTCHA_SECRET || !env.HCAPTCHA_SITEKEY) return false;
  if (!String(token || "").trim()) return false;
  const form = new URLSearchParams({
    secret: env.HCAPTCHA_SECRET,
    response: String(token),
    remoteip: requestIp(req),
    sitekey: env.HCAPTCHA_SITEKEY
  });
  const response = await fetch("https://api.hcaptcha.com/siteverify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form,
    signal: AbortSignal.timeout(API_REQUEST_TIMEOUT_MS)
  });
  if (!response.ok) return false;
  const result = await response.json();
  return result.success === true;
}

function changeAdminPassword(currentPassword, newPassword, req, res) {
  if (!adminApiKeyConfigured()) throw new Error("ADMIN_API_KEY не настроен.");
  if (!verifyAdminPassword(env, currentPassword)) throw new Error("Текущий пароль указан неверно.");
  const nextPassword = String(newPassword || "");
  if (nextPassword.length < 12 || nextPassword.length > 4096 || /^(?:REPLACE_|CHANGE_ME|CHANGEME|EXAMPLE|TODO)/i.test(nextPassword)) {
    throw new Error("Новый пароль должен содержать не менее 12 символов и не быть шаблонным.");
  }
  const nextEnv = readEnvFile();
  if (env.ADMIN_PASSWORD_HASH || jsonConfiguration(ENV_FILE_PATH)) {
    nextEnv.ADMIN_PASSWORD_HASH = createAdminPasswordHash(nextPassword);
    nextEnv.ADMIN_API_KEY = crypto.randomBytes(32).toString("hex");
  } else {
    nextEnv.ADMIN_API_KEY = nextPassword;
  }
  writeEnvFile(nextEnv);
  env.ADMIN_API_KEY = nextEnv.ADMIN_API_KEY;
  if (nextEnv.ADMIN_PASSWORD_HASH) env.ADMIN_PASSWORD_HASH = nextEnv.ADMIN_PASSWORD_HASH;
  adminSessions.clear();
  createAdminSession(res);
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value) {
  return Buffer.from(String(value || ""), "base64url");
}

function webauthnConfig() {
  const publicUrl = new URL(env.PUBLIC_BASE_URL);
  return {
    origin: publicUrl.origin,
    rpId: publicUrl.hostname,
    rpName: "GitRePosted"
  };
}

function issuePasskeyChallenge(type, sessionId = "") {
  const challenge = base64UrlEncode(crypto.randomBytes(32));
  passkeyChallenges.set(challenge, {
    type,
    sessionId: String(sessionId || "")
  });
  return challenge;
}

function consumePasskeyChallenge(challenge, type, sessionId = "") {
  const stored = passkeyChallenges.take(String(challenge || ""));
  if (!stored || stored.type !== type) {
    throw new Error("Запрос ключа доступа устарел. Повторите операцию.");
  }
  if (type === "register" && !secureEqual(stored.sessionId, String(sessionId || ""))) {
    throw new Error("Сессия регистрации ключа доступа изменилась.");
  }
}

function passkeyAuthenticationRateLimited(req, res) {
  const decision = passkeyAuthenticationRateLimiter.consume(requestIp(req));
  if (decision.allowed) return false;
  res.setHeader("retry-after", String(decision.retryAfterSeconds));
  json(res, 429, {
    error: "too_many_attempts",
    message: `Слишком много запросов входа по ключу доступа. Повторите через ${decision.retryAfterSeconds} сек.`
  });
  return true;
}

function verifyPasskeyClientData(encodedClientData, expectedType, expectedChallenge) {
  const raw = base64UrlDecode(encodedClientData);
  const data = JSON.parse(raw.toString("utf8"));
  const { origin } = webauthnConfig();
  if (data.type !== expectedType) throw new Error("Неверный тип операции WebAuthn.");
  if (!secureEqual(String(data.challenge || ""), String(expectedChallenge || ""))) {
    throw new Error("Неверный challenge ключа доступа.");
  }
  if (!secureEqual(String(data.origin || ""), origin)) throw new Error("Неверный источник ключа доступа.");
  return raw;
}

function verifyPasskeyAuthenticatorData(encodedAuthenticatorData) {
  const authenticatorData = base64UrlDecode(encodedAuthenticatorData);
  if (authenticatorData.length < 37) throw new Error("Некорректные данные аутентификатора.");
  const { rpId } = webauthnConfig();
  const expectedRpIdHash = crypto.createHash("sha256").update(rpId).digest();
  if (!crypto.timingSafeEqual(authenticatorData.subarray(0, 32), expectedRpIdHash)) {
    throw new Error("Ключ доступа зарегистрирован для другого домена.");
  }
  const flags = authenticatorData[32];
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0) {
    throw new Error("Ключ доступа не подтвердил присутствие и проверку пользователя.");
  }
  return {
    raw: authenticatorData,
    signCount: authenticatorData.readUInt32BE(33)
  };
}

async function adminPasskeysState() {
  const rows = await db(
    `SELECT id, name, credential_id, transports, created_at, last_used_at
     FROM admin_passkeys ORDER BY created_at DESC`
  );
  return rows.map((row) => ({
    ...row,
    transports: parseJsonArray(row.transports)
  }));
}

async function passkeyRegistrationOptions(req) {
  const countRows = await db("SELECT COUNT(*) AS total FROM admin_passkeys");
  if (Number(countRows[0]?.total || 0) >= 3) throw new Error("Можно добавить не более трёх ключей доступа.");
  const sessionId = parseCookies(req).reposted_admin_session || "";
  const challenge = issuePasskeyChallenge("register", sessionId);
  const existing = await db("SELECT credential_id FROM admin_passkeys");
  const { rpId, rpName } = webauthnConfig();
  return {
    challenge,
    rp: { id: rpId, name: rpName },
    user: {
      id: base64UrlEncode(crypto.createHash("sha256").update("gitreposted-admin").digest()),
      name: env.ADMIN_USERNAME || "admin",
      displayName: env.ADMIN_USERNAME || "admin"
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
      { type: "public-key", alg: -8 }
    ],
    timeout: 60000,
    attestation: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required"
    },
    excludeCredentials: existing.map((row) => ({
      type: "public-key",
      id: row.credential_id
    }))
  };
}

async function registerAdminPasskey(req, payload) {
  const response = payload.response || {};
  const clientData = JSON.parse(base64UrlDecode(response.clientDataJSON).toString("utf8"));
  const sessionId = parseCookies(req).reposted_admin_session || "";
  consumePasskeyChallenge(clientData.challenge, "register", sessionId);
  verifyPasskeyClientData(response.clientDataJSON, "webauthn.create", clientData.challenge);
  const auth = verifyPasskeyAuthenticatorData(response.authenticatorData);
  const credentialId = String(payload.credential_id || "");
  const publicKeySpki = String(response.publicKey || "");
  const algorithm = Number(response.publicKeyAlgorithm);
  if (!credentialId || !publicKeySpki) throw new Error("Браузер не вернул открытый ключ.");
  if (![-7, -257, -8].includes(algorithm)) throw new Error("Алгоритм ключа доступа не поддерживается.");
  crypto.createPublicKey({ key: base64UrlDecode(publicKeySpki), format: "der", type: "spki" });
  const name = String(payload.name || "").trim().slice(0, 100) || `Ключ ${new Date().toLocaleDateString("ru-RU")}`;
  const transports = Array.isArray(response.transports) ? response.transports.map(String).slice(0, 8) : [];
  const countRows = await db("SELECT COUNT(*) AS total FROM admin_passkeys");
  if (Number(countRows[0]?.total || 0) >= 3) throw new Error("Можно добавить не более трёх ключей доступа.");
  await db(
    `INSERT INTO admin_passkeys (credential_id, name, public_key_spki, algorithm, sign_count, transports)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [credentialId, name, publicKeySpki, algorithm, auth.signCount, JSON.stringify(transports)]
  );
  return adminPasskeysState();
}

async function passkeyAuthenticationOptions() {
  const rows = await db("SELECT credential_id, transports FROM admin_passkeys ORDER BY id");
  if (!rows.length) throw new Error("Ключи доступа ещё не добавлены.");
  const challenge = issuePasskeyChallenge("authenticate");
  const { rpId } = webauthnConfig();
  return {
    challenge,
    rpId,
    timeout: 60000,
    userVerification: "required",
    allowCredentials: rows.map((row) => ({
      type: "public-key",
      id: row.credential_id,
      transports: parseJsonArray(row.transports)
    }))
  };
}

async function authenticateAdminPasskey(payload, res) {
  const response = payload.response || {};
  const clientData = JSON.parse(base64UrlDecode(response.clientDataJSON).toString("utf8"));
  consumePasskeyChallenge(clientData.challenge, "authenticate");
  const clientDataRaw = verifyPasskeyClientData(response.clientDataJSON, "webauthn.get", clientData.challenge);
  const auth = verifyPasskeyAuthenticatorData(response.authenticatorData);
  const credentialId = String(payload.credential_id || "");
  const rows = await db("SELECT * FROM admin_passkeys WHERE credential_id = ? LIMIT 1", [credentialId]);
  const passkey = rows[0];
  if (!passkey) throw new Error("Ключ доступа не найден.");
  const signedData = Buffer.concat([
    auth.raw,
    crypto.createHash("sha256").update(clientDataRaw).digest()
  ]);
  const publicKey = crypto.createPublicKey({
    key: base64UrlDecode(passkey.public_key_spki),
    format: "der",
    type: "spki"
  });
  const algorithm = Number(passkey.algorithm) === -8 ? null : "sha256";
  const verified = crypto.verify(algorithm, signedData, publicKey, base64UrlDecode(response.signature));
  if (!verified) throw new Error("Подпись ключа доступа недействительна.");
  const previousCount = Number(passkey.sign_count || 0);
  if (previousCount > 0 && auth.signCount > 0 && auth.signCount <= previousCount) {
    throw new Error("Счётчик ключа доступа недействителен.");
  }
  await db(
    "UPDATE admin_passkeys SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
    [auth.signCount, passkey.id]
  );
  createAdminSession(res);
}

async function readStaticFile(name) {
  return fs.promises.readFile(new URL(`./public/${name}`, import.meta.url));
}

async function sendTelegramMenu(chatId, text = MAIN_MENU_TEXT) {
  return tgApi("sendMessage", {
    chat_id: chatId,
    text,
    reply_markup: tgReplyKeyboard([
      ["Создать пересылку", "Настроенные пересылки"],
      ["Добавить канал", "Связь аккаунтов"]
    ])
  });
}

async function sendTelegramLinkStatus(chatId, userId) {
  const account = await linkedAccountStatus("telegram", userId);
  const action = account.max_user_id ? "Заменить аккаунт МАКС" : "Связать аккаунт МАКС";
  const buttons = [[{ text: action, callback_data: "tg:linkcode" }]];
  if (account.max_user_id) buttons.push([{ text: "Отвязать аккаунт МАКС", callback_data: "tg:unlinkmax" }]);
  return tgApi("sendMessage", {
    chat_id: chatId,
    text: accountLinkStatusText(account, true),
    parse_mode: "HTML",
    reply_markup: tgInline(buttons)
  });
}

async function editTelegramMenu(chatId, messageId, text, rows, parseMode = "HTML") {
  try {
    const payload = {
      chat_id: chatId,
      message_id: messageId,
      text,
      reply_markup: tgInline(rows)
    };
    if (parseMode) payload.parse_mode = parseMode;
    return await tgApi("editMessageText", payload);
  } catch (error) {
    if (/message is not modified/i.test(String(error?.message || ""))) return null;
    throw error;
  }
}

async function answerTelegramCallback(id, text = "") {
  try {
    await tgApi("answerCallbackQuery", { callback_query_id: id, text, show_alert: false });
  } catch {
  }
}

function maxKeyboard(buttonRows) {
  return [{
    type: "inline_keyboard",
    payload: { buttons: buttonRows }
  }];
}

function maxLinkButton(text, url) {
  return {
    type: "link",
    text: compactUnicodeText(text, 128, "Открыть"),
    url
  };
}

async function sendMaxChat(chatId, text, attachments = []) {
  return maxApi(`/messages?chat_id=${encodeURIComponent(String(chatId))}`, {
    method: "POST",
    body: JSON.stringify({ text, attachments })
  });
}

async function answerMaxCallback(callbackId, text, buttonRows = []) {
  const normalizedText = Array.from(String(text || "Действие обработано."))
    .slice(0, 4000)
    .join("");
  const body = {
    message: {
      text: normalizedText,
      ...(Array.isArray(buttonRows) && buttonRows.length
        ? { attachments: maxKeyboard(buttonRows) }
        : {})
    }
  };
  return maxApi(`/answers?callback_id=${encodeURIComponent(String(callbackId))}`, {
    method: "POST",
    body: JSON.stringify(body)
  });
}

function maxCallbackRowsFromMessage(message) {
  const keyboard = maxAttachmentList(message)
    .find((attachment) => attachment?.type === "inline_keyboard")
    ?.payload?.buttons;
  if (!Array.isArray(keyboard)) return [];
  return keyboard.slice(0, 30)
    .map((row) => (Array.isArray(row) ? row : []).slice(0, 7)
      .map((button) => {
        if (button?.type === "callback" && button?.payload) {
          return maxCallbackButton(button.text, button.payload);
        }
        if (button?.type === "link") {
          const url = firstHttpUrl(button.url);
          return url ? maxLinkButton(button.text, url) : null;
        }
        return null;
      })
      .filter(Boolean))
    .filter((row) => row.length);
}

function maxMainButtons() {
  return [
    [maxCallbackButton("Создать пересылку", "max:create"), maxCallbackButton("Настроенные пересылки", "max:bridges")],
    [maxCallbackButton("Добавить канал", "max:addchannel"), maxCallbackButton("Связь аккаунтов", "max:link")]
  ];
}

function formatBridgeDirection(direction) {
  if (direction === "tg_to_max") return "из Telegram в МАКС";
  if (direction === "max_to_tg") return "из МАКС в Telegram";
  if (direction === "both") return "в обе стороны";
  return direction;
}

function isMaxDirectChat(chatType) {
  return chatType === "private" || chatType === "dialog";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;");
}

function formatBridgeList(rows) {
  if (rows.length === 0) {
    return "Связок пока нет.";
  }
  return rows.map((row, index) => {
    const telegramTitle = row.telegram_title || row.title || row.telegram_chat_id;
    const maxTitle = row.max_title || row.title || row.max_chat_id;
    return `из 💬 ${row._index || index + 1}. ${telegramTitle} в 💬 ${row._index || index + 1}. ${maxTitle}`;
  }).join("\n\n");
}

function formatTelegramBridgeList(rows) {
  if (rows.length === 0) {
    return "Связок пока нет.";
  }
  return rows.map((row, index) => {
    const telegramTitle = escapeHtml(row.telegram_title || row.title || row.telegram_chat_id);
    const maxTitle = escapeHtml(row.max_title || row.title || row.max_chat_id);
    return `из <tg-emoji emoji-id="5285350148451344065">💬</tg-emoji> ${row._index || index + 1}. ${telegramTitle} в <tg-emoji emoji-id="5456166744479533085">💬</tg-emoji> ${row._index || index + 1}. ${maxTitle}`;
  }).join("\n");
}

function formatBridgeButtonLabel(row) {
  const telegramTitle = row.telegram_title || row.title || row.telegram_chat_id;
  const maxTitle = row.max_title || row.title || row.max_chat_id;
  return `${telegramTitle} -> ${maxTitle}`;
}

function bridgeTelegramTitle(row) {
  return row.telegram_title || row.title || row.telegram_chat_id;
}

function bridgeMaxTitle(row) {
  return row.max_title || row.title || row.max_chat_id;
}

function compactButtonLabel(text, limit = 18) {
  const value = String(text || "").trim();
  if (value.length <= limit) return value;
  return `${value.slice(0, Math.max(1, limit - 1))}…`;
}

function telegramToggleButton(row) {
  return row.enabled
    ? {
      text: " ",
      callback_data: `tg:toggle:${row.id}:0`,
      icon_custom_emoji_id: "5974076810386738645"
    }
    : {
      text: " ",
      callback_data: `tg:toggle:${row.id}:1`,
      icon_custom_emoji_id: "5974565736578813237"
    };
}

function maxToggleLabel(row) {
  return row.enabled ? "🔔" : "🔕";
}

function bridgeLinkLabel(row, limit = 34) {
  return `💬 ${compactButtonLabel(bridgeTelegramTitle(row), limit)} > 💬 ${compactButtonLabel(bridgeMaxTitle(row), limit)}`;
}

function telegramChannelButton(row) {
  return {
    text: `${row._index}. ${compactButtonLabel(bridgeTelegramTitle(row), 14)}`,
    callback_data: `tg:edittg:${row.id}`,
    icon_custom_emoji_id: "5285350148451344065"
  };
}

function maxChannelButton(row) {
  return {
    text: `${row._index}. ${compactButtonLabel(bridgeMaxTitle(row), 14)}`,
    callback_data: `tg:editmax:${row.id}`,
    icon_custom_emoji_id: "5456166744479533085"
  };
}

async function renderTelegramBridges(chatId, messageId = null, page = 0) {
  const allRows = (await routesForAccount("telegram", chatId)).map((row, index) => ({ ...row, _index: index + 1 }));
  const paged = paginateRows(allRows, page, BOT_PAGE_SIZE);
  const keyboard = paged.items.flatMap((row) => [[
      {
        text: `Пересылка №${row._index}`,
        callback_data: "tg:noop"
      },
      telegramToggleButton(row),
      {
        text: " ",
        callback_data: `tg:delete:${row.id}`,
        icon_custom_emoji_id: "5974518878485615140"
      }
    ]]);
  keyboard.push(...makePageNav(paged.page, paged.totalPages, "tg:bridges", "tg:menu"));
  const text = bridgeSummaryText(paged.items, 4096);
  if (messageId) return editTelegramMenu(chatId, messageId, text, keyboard, null);
  return tgApi("sendMessage", { chat_id: chatId, text, reply_markup: tgInline(keyboard) });
}

async function renderTelegramChannelPicker(chatId, messageId, source, state, rows) {
  const keyboard = rows.map((row) => [{
    text: compactUnicodeText(row.title, 64, "Канал"),
    callback_data: `tg:${source}:${row.chat_id}`
  }]);
  keyboard.push([{ text: "← Назад", callback_data: "tg:menu" }]);
  await editTelegramMenu(chatId, messageId, state, keyboard);
}

function channelPlatformCode(platform) { return platform === "max" ? "m" : "t"; }
function channelPlatformFromCode(code) { return code === "m" ? "max" : "telegram"; }
function channelChoiceLabel(row, selected = false) {
  return `${selected ? "✅ " : ""}${row.platform === "max" ? "МАКС" : "Telegram"}: ${row.title}`;
}

function telegramChannelChoiceButton(row, callbackData, selected = false) {
  return {
    text: compactUnicodeText(`${selected ? "✅ " : ""}${row.title}`, 64, "Канал"),
    callback_data: callbackData,
    icon_custom_emoji_id: row.platform === "max" ? "5456166744479533085" : "5285350148451344065"
  };
}

function telegramReplyChannelButton(row, index, selected = false) {
  return {
    text: compactUnicodeText(`${selected ? "➖" : "➕"} ${index}. ${row.title}`, 64, "Канал"),
    icon_custom_emoji_id: row.platform === "max" ? "5456166744479533085" : "5285350148451344065"
  };
}

function telegramReplyPageNavigation(page, totalPages) {
  const row = [];
  if (page > 0) row.push("← Пред.");
  row.push(`${page + 1}/${totalPages}`);
  if (page + 1 < totalPages) row.push("След. →");
  return row;
}

async function sendTelegramRouteSourceKeyboard(
  chatId,
  userId,
  page = 0,
  { persistState = true } = {}
) {
  const rows = await channelChoicesForAccount("telegram", userId);
  const paged = paginateRows(rows, page, BOT_PAGE_SIZE);
  if (persistState) {
    await setTelegramState(userId, "route_source_reply", { page: paged.page });
  }
  const keyboard = paged.items.map((row, offset) => [telegramReplyChannelButton(row, paged.page * BOT_PAGE_SIZE + offset + 1)]);
  keyboard.push(telegramReplyPageNavigation(paged.page, paged.totalPages));
  keyboard.push(["← В меню"]);
  return tgApi("sendMessage", {
    chat_id: chatId,
    text: rows.length ? "Выберите канал, откуда берём публикации." : "Каналов пока нет. Добавьте бота администратором канала и подтвердите канал пересланным сообщением.",
    reply_markup: tgReplyKeyboard(keyboard)
  });
}

async function sendTelegramRouteTargetKeyboard(
  chatId,
  userId,
  statePayload,
  page = 0,
  { persistState = true } = {}
) {
  const sourceKey = `${statePayload.source_platform}:${statePayload.source_chat_id}`;
  const rows = (await channelChoicesForAccount("telegram", userId)).filter((row) => `${row.platform}:${row.chat_id}` !== sourceKey);
  const paged = paginateRows(rows, page, BOT_PAGE_SIZE);
  const selected = new Set(statePayload.targets || []);
  if (persistState) {
    await setTelegramState(userId, "route_targets_reply", {
      ...statePayload,
      page: paged.page,
      targets: [...selected]
    });
  }
  const keyboard = paged.items.map((row, offset) => {
    const index = paged.page * BOT_PAGE_SIZE + offset + 1;
    return [telegramReplyChannelButton(row, index, selected.has(`${row.platform}:${row.chat_id}`))];
  });
  keyboard.push(telegramReplyPageNavigation(paged.page, paged.totalPages));
  keyboard.push([`Сохранить пересылку (${selected.size})`, "← К источнику"]);
  return tgApi("sendMessage", {
    chat_id: chatId,
    text: "Выберите один или несколько каналов, куда отправлять публикации.",
    reply_markup: tgReplyKeyboard(keyboard)
  });
}

async function renderTelegramRouteSourcePicker(chatId, messageId, userId, page = 0) {
  const rows = await channelChoicesForAccount("telegram", userId);
  const paged = paginateRows(rows, page, BOT_PAGE_SIZE);
  const keyboard = paged.items.map((row) => [telegramChannelChoiceButton(row, `tg:rsrc:${channelPlatformCode(row.platform)}:${row.chat_id}`)]);
  keyboard.push(...makePageNav(paged.page, paged.totalPages, "tg:rsourcepage", "tg:menu"));
  return editTelegramMenu(chatId, messageId, "Откуда берём публикации?", keyboard);
}

async function renderTelegramRouteTargetPicker(chatId, messageId, userId, page = 0) {
  const user = await getTelegramUser(userId);
  const payload = parseStatePayload(user?.state_payload);
  const selected = new Set(payload.targets || []);
  const sourceKey = `${payload.source_platform}:${payload.source_chat_id}`;
  const rows = (await channelChoicesForAccount("telegram", userId)).filter((row) => `${row.platform}:${row.chat_id}` !== sourceKey);
  const paged = paginateRows(rows, page, BOT_PAGE_SIZE);
  const keyboard = paged.items.map((row) => {
    const key = `${row.platform}:${row.chat_id}`;
    const action = selected.has(key) ? "remove" : "add";
    return [telegramChannelChoiceButton(
      row,
      `tg:rtgt:${action}:${channelPlatformCode(row.platform)}:${row.chat_id}`,
      selected.has(key)
    )];
  });
  keyboard.push([{ text: `Сохранить (${selected.size})`, callback_data: "tg:rsave" }]);
  keyboard.push(...makePageNav(paged.page, paged.totalPages, "tg:rtargetpage", "tg:create"));
  return editTelegramMenu(chatId, messageId, "Куда отправляем? Отметьте один или несколько каналов.", keyboard);
}

async function renderMaxBridges(chatId, callbackId = null, page = 0, userId = null) {
  const allRows = (userId ? await routesForAccount("max", userId) : []).map((row, index) => ({ ...row, _index: index + 1 }));
  const paged = paginateRows(allRows, page, BOT_PAGE_SIZE);
  const buttons = paged.items.flatMap((row) => [[
      maxCallbackButton(`Пересылка №${row._index}`, "max:noop"),
      maxCallbackButton(maxToggleLabel(row), `max:toggle:${row.id}:${row.enabled ? 0 : 1}`),
      maxCallbackButton("🗑", `max:delete:${row.id}`)
    ]]);
  buttons.push(...makeMaxPageNav(paged.page, paged.totalPages, "max:bridges", "max:menu"));
  const text = bridgeSummaryText(paged.items, 4000);
  if (callbackId) return answerMaxCallback(callbackId, text, buttons);
  return sendMaxChat(chatId, text, maxKeyboard(buttons));
}

async function renderMaxRouteSourcePicker(callbackId, userId, page = 0) {
  const rows = await channelChoicesForAccount("max", userId);
  const paged = paginateRows(rows, page, BOT_PAGE_SIZE);
  const buttons = paged.items.map((row) => [maxCallbackButton(channelChoiceLabel(row), `max:rsrc:${channelPlatformCode(row.platform)}:${row.chat_id}`)]);
  buttons.push(...makeMaxPageNav(paged.page, paged.totalPages, "max:rsourcepage", "max:menu"));
  return answerMaxCallback(callbackId, "Откуда берём публикации?", buttons);
}

async function renderMaxRouteTargetPicker(callbackId, userId, page = 0) {
  const user = await getMaxUser(userId);
  const payload = parseStatePayload(user?.state_payload);
  const selected = new Set(payload.targets || []);
  const sourceKey = `${payload.source_platform}:${payload.source_chat_id}`;
  const rows = (await channelChoicesForAccount("max", userId)).filter((row) => `${row.platform}:${row.chat_id}` !== sourceKey);
  const paged = paginateRows(rows, page, BOT_PAGE_SIZE);
  const buttons = paged.items.map((row) => {
    const key = `${row.platform}:${row.chat_id}`;
    const action = selected.has(key) ? "remove" : "add";
    return [maxCallbackButton(
      channelChoiceLabel(row, selected.has(key)),
      `max:rtgt:${action}:${channelPlatformCode(row.platform)}:${row.chat_id}`
    )];
  });
  buttons.push([maxCallbackButton(`Сохранить (${selected.size})`, "max:rsave")]);
  buttons.push(...makeMaxPageNav(paged.page, paged.totalPages, "max:rtargetpage", "max:create"));
  return answerMaxCallback(callbackId, "Куда отправляем? Отметьте один или несколько каналов.", buttons);
}

function assertWebhookSettingsApplied() {
  if (editableConfigState().restart_required) {
    const error = new Error("Сначала примените сохранённые настройки перезапуском службы.");
    error.statusCode = 409;
    error.code = "RESTART_REQUIRED";
    throw error;
  }
}

function requireWebhookTakeover(foreign, takeover) {
  if (foreign.length && takeover !== true) {
    const error = new Error("У бота уже есть webhook другого приложения. Подтвердите переключение.");
    error.statusCode = 409;
    error.code = "TAKEOVER_REQUIRED";
    throw error;
  }
}

function confirmWebhookEvents(rows, webhookUrl, platform) {
  const expected = (platform === "telegram"
    ? ["message", "edited_message", "channel_post", "edited_channel_post", "callback_query", "my_chat_member"]
    : ["message_created", "message_callback", "bot_added", "bot_removed", "bot_started"]).sort().join("|");
  if (!rows.length || rows.some((row) => row?.url !== webhookUrl)
    || !rows.some((row) => Array.isArray(row?.[platform === "telegram" ? "allowed_updates" : "update_types"])
      && [...new Set(row[platform === "telegram" ? "allowed_updates" : "update_types"])].sort().join("|") === expected)) {
    throw new Error("Webhook registration was not confirmed.");
  }
}

function safeWebhookFailure(error) {
  if (["TAKEOVER_REQUIRED", "RESTART_REQUIRED", "PLATFORM_DISABLED"].includes(error?.code)) return error;
  const safe = new Error("Платформа не подтвердила подключение webhook. Проверьте токен и повторите.");
  safe.statusCode = 502;
  return safe;
}

function startBotCommandMatches(commands, platform) {
  if (!Array.isArray(commands) || commands.length !== 1) return false;
  const command = commands[0];
  const name = command?.[platform === "telegram" ? "command" : "name"];
  const description = command?.description;
  if (typeof name !== "string" || typeof description !== "string") return false;
  return (platform === "max" ? name.trim().replace(/^\/+/, "") : name) === "start"
    && (platform === "max" ? description.trim() : description) === "Открыть главное меню";
}

async function reconcileBotMenuSetting(readSetting, writeSetting, matches) {
  if (matches(await readSetting())) return;
  try { await writeSetting(); }
  catch { /* A lost control response is reconciled by reading the desired state. */ }
  if (!matches(await readSetting())) throw new Error("Bot command menu was not confirmed.");
}

async function registerTelegramBotMenu() {
  const commands = [{ command: "start", description: "Открыть главное меню" }];
  for (const languageCode of ["", "ru"]) {
    const language = languageCode ? { language_code: languageCode } : {};
    await reconcileBotMenuSetting(
      () => tgApi("getMyCommands", language),
      async () => {
        if (await tgApi("setMyCommands", { ...language, commands }) !== true) throw new Error("Commands were not registered.");
      },
      (value) => startBotCommandMatches(value, "telegram")
    );
  }
  await reconcileBotMenuSetting(
    () => tgApi("getChatMenuButton", {}),
    async () => {
      if (await tgApi("setChatMenuButton", { menu_button: { type: "commands" } }) !== true) throw new Error("Menu button was not registered.");
    },
    (value) => value?.type === "commands"
  );
}

async function registerMaxBotMenu() {
  await reconcileBotMenuSetting(
    () => maxApi("/me"),
    async () => {
      const response = await maxApi("/me/commands", {
        method: "PATCH",
        body: JSON.stringify({ commands: [{ name: "start", description: "Открыть главное меню" }] })
      });
      if (!startBotCommandMatches(response?.commands, "max")) throw new Error("Commands were not registered.");
    },
    (value) => startBotCommandMatches(value?.commands, "max")
  );
}

async function replaceTelegramWebhookSubscription(webhookUrl, takeover = false) {
  assertPlatformEnabled("telegram");
  try {
    const existing = await tgApi("getWebhookInfo", {});
    if (!existing || typeof existing.url !== "string") throw new Error("Invalid webhook response");
    requireWebhookTakeover(existing.url && existing.url !== webhookUrl ? [existing] : [], takeover);
    const registered = await tgApi("setWebhook", {
      url: webhookUrl,
      secret_token: env.TELEGRAM_WEBHOOK_SECRET,
      allowed_updates: ["message", "edited_message", "channel_post", "edited_channel_post", "callback_query", "my_chat_member"],
      drop_pending_updates: false
    });
    if (registered !== true) throw new Error("Webhook was not registered");
    confirmWebhookEvents([await tgApi("getWebhookInfo", {})], webhookUrl, "telegram");
    await registerTelegramBotMenu();
  } catch (error) { throw safeWebhookFailure(error); }
}

async function setWebhooks(takeover = false) {
  assertWebhookSettingsApplied();
  const publicBaseUrl = requestPublicBaseUrl();
  if (platformEnabled(env, "telegram")) await replaceTelegramWebhookSubscription(`${publicBaseUrl}/webhooks/telegram`, takeover);
  if (platformEnabled(env, "max")) await replaceMaxWebhookSubscription(`${publicBaseUrl}/webhooks/max`, takeover);
}

function maxSubscriptionItems(value) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.subscriptions)) return value.subscriptions;
  if (Array.isArray(value?.items)) return value.items;
  return [];
}

async function replaceMaxWebhookSubscription(webhookUrl, takeover = false) {
  assertPlatformEnabled("max");
  try {
    const readSubscriptions = async () => {
      const response = await maxApi("/subscriptions");
      if (!Array.isArray(response) && !Array.isArray(response?.subscriptions) && !Array.isArray(response?.items)) throw new Error("Invalid subscriptions response");
      const rows = maxSubscriptionItems(response);
      if (rows.some((row) => !row || typeof row.url !== "string" || !row.url)) throw new Error("Invalid subscription URL");
      return rows;
    };
    const existing = await readSubscriptions();
    const foreign = existing.filter((row) => row.url !== webhookUrl);
    requireWebhookTakeover(foreign, takeover);
    await maxApi("/subscriptions", {
      method: "POST",
      body: JSON.stringify({
        url: webhookUrl, secret: env.MAX_WEBHOOK_SECRET,
        update_types: ["message_created", "message_callback", "bot_added", "bot_removed", "bot_started"]
      })
    });
    confirmWebhookEvents((await readSubscriptions()).filter((row) => row.url === webhookUrl), webhookUrl, "max");
    await registerMaxBotMenu();
    for (const oldUrl of new Set(foreign.map((row) => row.url))) {
      await maxApi(`/subscriptions?url=${encodeURIComponent(oldUrl)}`, { method: "DELETE" });
    }
    confirmWebhookEvents(await readSubscriptions(), webhookUrl, "max");
  } catch (error) { throw safeWebhookFailure(error); }
}

async function handleTelegramMyChatMember(update) {
  const chat = update.chat || {};
  if (!chat.id) return;
  if (chat.type === "private") return;
  const newMember = update.new_chat_member || {};
  const status = newMember.status || null;
  const canPost = status === "creator" || (status === "administrator" && newMember.can_post_messages) ? 1 : 0;
  debugLog("telegram_my_chat_member", {
    chatId: String(chat.id),
    title: chat.title || null,
    username: chat.username || null,
    status,
    canPost
  });
  await rememberInboundEvent("telegram", "my_chat_member", chat.id, update.from?.id || null, update);
  await upsertTelegramChannel(chat.id, chat.title || String(chat.id), chat.username || null, status, canPost);
  await reconcileTelegramBridgeIds(chat.id);
}

async function handleTelegramMessage(message, receipt = null) {
  const chat = message.chat || {};
  debugLog("telegram_message", {
    chatId: chat.id ? String(chat.id) : null,
    chatType: chat.type || null,
    fromId: message.from?.id ? String(message.from.id) : null,
    text: message.text || ""
  });
  await rememberInboundEvent("telegram", "message", chat.id || null, message.from?.id || null, message);
  if (chat.type === "private") {
    const from = message.from || {};
    const text = String(message.text || "").trim();
    await rememberTelegramUser(from.id, from.username || "", from.first_name || "");
    const access = await accountAccess("telegram", from.id);
    if (access.blocked) {
      await tgApi("sendMessage", { chat_id: chat.id, text: access.reason });
      return;
    }
    if (env.PUBLIC_TELEGRAM_ENABLED !== "1") {
      await tgApi("sendMessage", { chat_id: chat.id, text: "Публичный доступ сейчас выключен владельцем сервиса." });
      return;
    }
    if (/^\d{6}$/.test(text)) {
      const result = await consumeAccountLinkCode("telegram", from.id, text, { receipt });
      await tgApi("sendMessage", { chat_id: chat.id, text: result.message });
      return;
    }
    if (/^(связать аккаунты|связь аккаунтов|связь аккаунтов Telegram и МАКС)$/i.test(text) || text === "/link") {
      await sendTelegramLinkStatus(chat.id, from.id);
      return;
    }
    const forwardedChannel = forwardedTelegramChannel(message);
    if (forwardedChannel) {
      try {
        const title = await claimForwardedTelegramChannel(from.id, forwardedChannel);
        await tgApi("sendMessage", {
          chat_id: chat.id,
          text: `Канал «${title}» добавлен в ваш список. Теперь его можно использовать в пересылках.`
        });
      } catch (error) {
        await tgApi("sendMessage", { chat_id: chat.id, text: error.message || "Не удалось добавить канал." });
      }
      return;
    }
    if (text === "/start" || /^меню$/i.test(text) || text === "/menu") {
      await setTelegramState(from.id, null, null);
      await sendTelegramMenu(chat.id);
      return;
    }
    const telegramUser = await getTelegramUser(from.id);
    const statePayload = parseStatePayload(telegramUser?.state_payload);
    if (telegramUser?.state === "route_source_reply") {
      if (text === "← В меню") {
        await mutateTelegramReplyState(from.id, "route_source_reply", () => ({
          state: null,
          payload: null
        }), { receipt });
        await sendTelegramMenu(chat.id);
        return;
      }
      if (text === "← Пред." || text === "След. →") {
        const changed = await mutateTelegramReplyState(
          from.id,
          "route_source_reply",
          (payload) => ({
            state: "route_source_reply",
            payload: {
              ...payload,
              page: Math.max(0, Number(payload.page || 0) + (text === "След. →" ? 1 : -1))
            }
          }),
          { receipt }
        );
        await sendTelegramRouteSourceKeyboard(
          chat.id,
          from.id,
          changed.payload.page,
          { persistState: false }
        );
        return;
      }
      const selectedIndex = Number(text.match(/^(?:➕ )?(\d+)\./)?.[1] || 0);
      if (selectedIndex) {
        const rows = await channelChoicesForAccount("telegram", from.id);
        const selected = rows[selectedIndex - 1];
        if (selected) {
          const changed = await mutateTelegramReplyState(
            from.id,
            "route_source_reply",
            () => ({
              state: "route_targets_reply",
              payload: {
                source_platform: selected.platform,
                source_chat_id: selected.chat_id,
                targets: [],
                page: 0
              }
            }),
            { receipt }
          );
          await sendTelegramRouteTargetKeyboard(
            chat.id,
            from.id,
            changed.payload,
            0,
            { persistState: false }
          );
          return;
        }
      }
      return;
    }
    if (telegramUser?.state === "route_targets_reply") {
      if (text === "← К источнику") {
        await mutateTelegramReplyState(from.id, "route_targets_reply", () => ({
          state: "route_source_reply",
          payload: { page: 0 }
        }), { receipt });
        await sendTelegramRouteSourceKeyboard(chat.id, from.id, 0, { persistState: false });
        return;
      }
      if (text === "← Пред." || text === "След. →") {
        const changed = await mutateTelegramReplyState(
          from.id,
          "route_targets_reply",
          (payload) => ({
            state: "route_targets_reply",
            payload: {
              ...payload,
              page: Math.max(0, Number(payload.page || 0) + (text === "След. →" ? 1 : -1))
            }
          }),
          { receipt }
        );
        await sendTelegramRouteTargetKeyboard(
          chat.id,
          from.id,
          changed.payload,
          changed.payload.page,
          { persistState: false }
        );
        return;
      }
      if (/^Сохранить пересылку/.test(text)) {
        try {
          await saveUniversalRouteForUser(
            "telegram",
            from.id,
            statePayload.source_platform,
            statePayload.source_chat_id,
            [],
            { receipt, responseKind: "message" }
          );
        } catch (error) {
          if (error?.code !== "ROUTE_SELECTION_INVALID") throw error;
          await tgApi("sendMessage", { chat_id: chat.id, text: error.message });
          return;
        }
        await sendTelegramMenu(chat.id, "Пересылка сохранена.");
        return;
      }
      const targetChoice = text.match(/^(➕|➖) (\d+)\./);
      const selectedIndex = Number(targetChoice?.[2] || 0);
      if (selectedIndex) {
        const choices = await channelChoicesForAccount("telegram", from.id);
        let matched = false;
        const changed = await mutateTelegramReplyState(
          from.id,
          "route_targets_reply",
          (payload) => {
            const sourceKey = `${payload.source_platform}:${payload.source_chat_id}`;
            const rows = choices.filter((row) => `${row.platform}:${row.chat_id}` !== sourceKey);
            const selected = rows[selectedIndex - 1];
            if (!selected) return { state: "route_targets_reply", payload };
            matched = true;
            const targets = new Set(payload.targets || []);
            const key = `${selected.platform}:${selected.chat_id}`;
            if (targetChoice[1] === "➕") targets.add(key);
            else targets.delete(key);
            return {
              state: "route_targets_reply",
              payload: { ...payload, targets: [...targets] }
            };
          },
          { receipt }
        );
        if (matched) {
          await sendTelegramRouteTargetKeyboard(
            chat.id,
            from.id,
            changed.payload,
            Number(changed.payload.page || 0),
            { persistState: false }
          );
          return;
        }
      }
      return;
    }
    if (text === "Настроенные пересылки" || text === "Пересылки" || text === "Связки") {
      await renderTelegramBridges(chat.id, null);
      return;
    }
    if (text === "Добавить канал" || text === "/addchannel") {
      await tgApi("sendMessage", {
        chat_id: chat.id,
        text: "Чтобы добавить Telegram-канал:\n\n1. Добавьте GitRePosted в канал администратором с правом публикации.\n2. Перешлите сюда любое сообщение из этого канала.\n\nПосле проверки канал автоматически появится в списке при создании пересылки."
      });
      return;
    }
    if (text === "Telegram каналы") {
      await sendTelegramMenu(chat.id, "Список каналов доступен при создании пересылки.");
      return;
    }
    if (text === "МАКС каналы") {
      await sendTelegramMenu(chat.id, "Список каналов доступен при создании пересылки.");
      return;
    }
    if (text === "Создать пересылку" || text === "Создать") {
      await sendTelegramRouteSourceKeyboard(chat.id, from.id, 0);
      return;
    }
    await tgApi("sendMessage", { chat_id: chat.id, text: "Используйте /start для открытия меню." });
    return;
  }

  if (chat.id) {
    await rememberTelegramChannelActivity(chat.id, chat.title || String(chat.id), chat.username || null);
    await reconcileTelegramBridgeIds(chat.id);
  }
}

async function handleTelegramChannelPost(message) {
  const chat = message.chat || {};
  if (!chat.id) return;
  debugLog("telegram_channel_post", {
    chatId: String(chat.id),
    title: chat.title || null,
    username: chat.username || null,
    text: message.text || message.caption || ""
  });
  await rememberInboundEvent("telegram", "channel_post", chat.id, message.sender_chat?.id || null, message);
  await rememberTelegramChannelActivity(chat.id, chat.title || String(chat.id), chat.username || null);
  await reconcileTelegramBridgeIds(chat.id);
}

async function handleTelegramCallback(callback, receipt = null) {
  const from = callback.from || {};
  const user = await getTelegramUser(from.id);
  const chatId = callback.message?.chat?.id;
  const messageId = callback.message?.message_id;
  const data = String(callback.data || "");
  debugLog("telegram_callback", {
    fromId: String(from.id || ""),
    data,
    chatId: chatId ? String(chatId) : null
  });
  await rememberInboundEvent("telegram", "callback_query", chatId || null, from.id || null, callback);
  await answerTelegramCallback(callback.id);
  const access = await accountAccess("telegram", from.id);
  if (access.blocked || env.PUBLIC_TELEGRAM_ENABLED !== "1") {
    if (chatId) await tgApi("sendMessage", { chat_id: chatId, text: access.blocked ? access.reason : "Публичный доступ сейчас выключен владельцем сервиса." });
    return;
  }
  if (!chatId || !messageId) return;

  if (data === "tg:menu") {
    await setTelegramState(from.id, null, null);
    try {
      await tgApi("deleteMessage", { chat_id: chatId, message_id: messageId });
    } catch {
    }
    await sendTelegramMenu(chatId);
    return;
  }
  if (data === "tg:noop") return;
  if (data === "tg:linkcode") {
    const code = await createAccountLinkCode("telegram", from.id);
    const keyboard = [];
    if (env.MAX_BOT_URL) keyboard.push([{ text: "Открыть МАКС-бота", url: env.MAX_BOT_URL }]);
    keyboard.push([{ text: "← В меню", callback_data: "tg:menu" }]);
    return editTelegramMenu(chatId, messageId, `Код замены связи: ${code}\n\nОтправьте этот код с нужного аккаунта МАКС в течение 10 минут.`, keyboard);
  }
  if (data === "tg:unlinkmax") {
    const account = await linkedAccountStatus("telegram", from.id);
    if (!account.max_user_id) {
      return editTelegramMenu(chatId, messageId, `${accountLinkStatusText(account, true)}\n\nАккаунт МАКС уже не связан.`, [
        [{ text: "Связать аккаунт МАКС", callback_data: "tg:linkcode" }],
        [{ text: "← В меню", callback_data: "tg:menu" }]
      ]);
    }
    return editTelegramMenu(chatId, messageId, "Отвязать аккаунт МАКС?\n\nТекущие каналы и настроенные пересылки этой связки будут удалены.", [
      [{ text: "Да, отвязать МАКС", callback_data: `tg:unlinkmaxconfirm:${account.max_user_id}` }],
      [{ text: "Отмена", callback_data: "tg:menu" }]
    ]);
  }
  if (data === "tg:unlinkmaxconfirm") {
    return editTelegramMenu(chatId, messageId, "Это подтверждение устарело. Откройте раздел связи аккаунтов ещё раз.", [
      [{ text: "← К связи аккаунтов", callback_data: "tg:link" }],
      [{ text: "← В меню", callback_data: "tg:menu" }]
    ]);
  }
  if (data.startsWith("tg:unlinkmaxconfirm:")) {
    const expectedMaxUserId = data.slice("tg:unlinkmaxconfirm:".length);
    const unlinked = await unlinkMaxAccountFromTelegram(from.id, expectedMaxUserId);
    const account = await linkedAccountStatus("telegram", from.id);
    const outcome = unlinked === null
      ? "Связь аккаунтов уже изменилась; старое подтверждение отменено.\n\n"
      : unlinked
        ? "Аккаунт МАКС отвязан. Теперь его можно связать с другим аккаунтом Telegram.\n\n"
        : "Аккаунт МАКС уже не связан.\n\n";
    return editTelegramMenu(
      chatId,
      messageId,
      `${outcome}${accountLinkStatusText(account, true)}`,
      [[{ text: "Связать аккаунт МАКС", callback_data: "tg:linkcode" }], [{ text: "← В меню", callback_data: "tg:menu" }]]
    );
  }
  if (data === "tg:bridges") return renderTelegramBridges(chatId, messageId, 0);
  if (data.startsWith("tg:bridges:")) {
    return renderTelegramBridges(chatId, messageId, parsePageZeroBased(data.split(":")[2]));
  }
  if (data === "tg:channels") {
    const rows = await channelsForAccount("telegram", from.id, "telegram");
    const text = rows.length ? rows.map((row, i) => `${i + 1}. ${escapeHtml(row.title)}`).join("\n") : "Telegram-каналы ещё не добавлены.\n\nДобавьте GitRePosted администратором канала, затем перешлите сюда любую публикацию из него.";
    return editTelegramMenu(chatId, messageId, text, [[{ text: "← Назад", callback_data: "tg:menu" }]]);
  }
  if (data === "tg:maxchannels") {
    const rows = await channelsForAccount("telegram", from.id, "max");
    const text = rows.length ? rows.map((row, i) => `${i + 1}. ${escapeHtml(row.title)}`).join("\n") : "MAX-каналы ещё не добавлены.\n\nДобавьте бота администратором MAX-канала и перешлите публикацию из него в MAX-бота.";
    return editTelegramMenu(chatId, messageId, text, [[{ text: "← Назад", callback_data: "tg:menu" }]]);
  }
  if (data === "tg:create") {
    await setTelegramState(from.id, "route_source", {});
    return renderTelegramRouteSourcePicker(chatId, messageId, from.id);
  }
  if (data.startsWith("tg:rsourcepage:")) {
    return renderTelegramRouteSourcePicker(chatId, messageId, from.id, parsePageZeroBased(data.split(":")[2]));
  }
  if (data.startsWith("tg:rsrc:")) {
    const [, , platformCode, ...chatIdParts] = data.split(":");
    await setTelegramState(from.id, "route_targets", { source_platform: channelPlatformFromCode(platformCode), source_chat_id: chatIdParts.join(":"), targets: [] });
    return renderTelegramRouteTargetPicker(chatId, messageId, from.id);
  }
  if (data.startsWith("tg:rtgt:")) {
    const [, , action, platformCode, ...chatIdParts] = data.split(":");
    if (!new Set(["add", "remove"]).has(action)) {
      return renderTelegramRouteTargetPicker(chatId, messageId, from.id);
    }
    const key = `${channelPlatformFromCode(platformCode)}:${chatIdParts.join(":")}`;
    await mutateRouteTargetState("telegram", from.id, key, action);
    return renderTelegramRouteTargetPicker(chatId, messageId, from.id);
  }
  if (data.startsWith("tg:rtargetpage:")) {
    return renderTelegramRouteTargetPicker(chatId, messageId, from.id, parsePageZeroBased(data.split(":")[2]));
  }
  if (data === "tg:rsave") {
    const current = await getTelegramUser(from.id);
    const payload = parseStatePayload(current?.state_payload);
    const targets = (payload.targets || []).map((key) => {
      const [platform, ...chatIdParts] = key.split(":");
      return { platform, chat_id: chatIdParts.join(":") };
    });
    const saved = await saveUniversalRouteForUser(
      "telegram",
      from.id,
      payload.source_platform,
      payload.source_chat_id,
      targets,
      { receipt, responseKind: "callback" }
    );
    await editTelegramMenu(chatId, messageId, `Пересылка сохранена. Получателей: ${saved.targetCount}.`, [[{ text: "← В меню", callback_data: "tg:menu" }]]);
    return;
  }
  if (/^tg:(?:(?:editbridge|edittg|editmax|retg|remax|editdir|redir|picktg|pickmax|save)(?::|$)|(?:toggle|delete):bridge_)/.test(data)) {
    await setTelegramState(from.id, null, null);
    return editTelegramMenu(
      chatId,
      messageId,
      "Эта кнопка относится к прежней версии настройки. Откройте меню и создайте пересылку заново.",
      [[{ text: "← В меню", callback_data: "tg:menu" }]]
    );
  }
  if (data.startsWith("tg:editbridge:")) {
    const bridgeId = data.split(":")[2];
    await assertOwnedBridge("telegram", from.id, bridgeId);
    const row = await bridgeById(bridgeId);
    if (!row) return renderTelegramBridges(chatId, messageId);
    const keyboard = [
      [{ text: `💬 Telegram: ${compactButtonLabel(bridgeTelegramTitle(row), 28)}`, callback_data: `tg:edittg:${bridgeId}` }],
      [{ text: `💬 МАКС: ${compactButtonLabel(bridgeMaxTitle(row), 28)}`, callback_data: `tg:editmax:${bridgeId}` }],
      [{ text: `Направление: ${formatBridgeDirection(row.direction)}`, callback_data: `tg:editdir:${bridgeId}` }],
      [{ text: "← Назад", callback_data: "tg:bridges" }]
    ];
    return editTelegramMenu(chatId, messageId, "Настройка связки.", keyboard);
  }
  if (data.startsWith("tg:edittg:")) {
    const bridgeId = data.split(":")[2];
    await assertOwnedBridge("telegram", from.id, bridgeId);
    const row = await bridgeById(bridgeId);
    if (!row) return renderTelegramBridges(chatId, messageId);
    const rows = await channelsForAccount("telegram", from.id, "telegram");
    const keyboard = rows.map((item) => [{
      text: compactUnicodeText(item.title, 64, "Telegram-канал"),
      callback_data: `tg:retg:${bridgeId}:${item.chat_id}`
    }]);
    keyboard.push([{ text: "← Назад", callback_data: "tg:bridges" }]);
    return editTelegramMenu(chatId, messageId, `Выберите новый Telegram-канал для связки с ${row.max_title || row.max_chat_id}.`, keyboard);
  }
  if (data.startsWith("tg:editmax:")) {
    const bridgeId = data.split(":")[2];
    await assertOwnedBridge("telegram", from.id, bridgeId);
    const row = await bridgeById(bridgeId);
    if (!row) return renderTelegramBridges(chatId, messageId);
    const rows = await channelsForAccount("telegram", from.id, "max");
    const keyboard = rows.map((item) => [{
      text: compactUnicodeText(item.title, 64, "MAX-канал"),
      callback_data: `tg:remax:${bridgeId}:${item.chat_id}`
    }]);
    keyboard.push([{ text: "← Назад", callback_data: "tg:bridges" }]);
    return editTelegramMenu(chatId, messageId, `Выберите новый МАКС-канал для связки с ${row.telegram_title || row.telegram_chat_id}.`, keyboard);
  }
  if (data.startsWith("tg:retg:")) {
    const [, , bridgeId, telegramChatId] = data.split(":");
    const account = await assertOwnedBridge("telegram", from.id, bridgeId);
    await assertAccountChannel(account.id, "telegram", telegramChatId);
    const row = await bridgeById(bridgeId);
    if (!row) return renderTelegramBridges(chatId, messageId);
    await updateBridgeChannels(bridgeId, telegramChatId, row.max_chat_id);
    return renderTelegramBridges(chatId, messageId);
  }
  if (data.startsWith("tg:remax:")) {
    const [, , bridgeId, maxChatId] = data.split(":");
    const account = await assertOwnedBridge("telegram", from.id, bridgeId);
    await assertAccountChannel(account.id, "max", maxChatId);
    const row = await bridgeById(bridgeId);
    if (!row) return renderTelegramBridges(chatId, messageId);
    await updateBridgeChannels(bridgeId, row.telegram_chat_id, maxChatId);
    return renderTelegramBridges(chatId, messageId);
  }
  if (data.startsWith("tg:editdir:")) {
    const bridgeId = data.split(":")[2];
    await assertOwnedBridge("telegram", from.id, bridgeId);
    const keyboard = [
      [{ text: "В обе стороны", callback_data: `tg:redir:${bridgeId}:both` }],
      [{ text: "из Telegram в МАКС", callback_data: `tg:redir:${bridgeId}:tg_to_max` }],
      [{ text: "из МАКС в Telegram", callback_data: `tg:redir:${bridgeId}:max_to_tg` }],
      [{ text: "← Назад", callback_data: `tg:editbridge:${bridgeId}` }]
    ];
    return editTelegramMenu(chatId, messageId, "Выберите направление связки.", keyboard);
  }
  if (data.startsWith("tg:redir:")) {
    const [, , bridgeId, direction] = data.split(":");
    await assertOwnedBridge("telegram", from.id, bridgeId);
    await updateBridgeDirection(bridgeId, direction);
    return renderTelegramBridges(chatId, messageId);
  }
  if (data.startsWith("tg:picktg:")) {
    const telegramChatId = data.split(":")[2];
    await setTelegramState(from.id, "pick_max_channel", { telegramChatId });
    const rows = await channelsForAccount("telegram", from.id, "max");
    const keyboard = rows.map((row) => [{
      text: compactUnicodeText(row.title, 64, "MAX-канал"),
      callback_data: `tg:pickmax:${telegramChatId}:${row.chat_id}`
    }]);
    keyboard.push([{ text: "← Назад", callback_data: "tg:create" }]);
    return editTelegramMenu(chatId, messageId, "Теперь выберите MAX-канал.", keyboard);
  }
  if (data.startsWith("tg:pickmax:")) {
    const [, , telegramChatId, maxChatId] = data.split(":");
    const keyboard = [
      [{ text: "Обе стороны", callback_data: `tg:save:${telegramChatId}:${maxChatId}:both` }],
      [{ text: "Telegram → MAX", callback_data: `tg:save:${telegramChatId}:${maxChatId}:tg_to_max` }],
      [{ text: "MAX → Telegram", callback_data: `tg:save:${telegramChatId}:${maxChatId}:max_to_tg` }],
      [{ text: "← Назад", callback_data: "tg:create" }]
    ];
    return editTelegramMenu(chatId, messageId, "Выберите направление связки.", keyboard);
  }
  if (data.startsWith("tg:save:")) {
    const [, , telegramChatId, maxChatId, direction] = data.split(":");
    await saveBridge("telegram", from.id, telegramChatId, maxChatId, direction);
    await setTelegramState(from.id, null, null);
    return renderTelegramBridges(chatId, messageId);
  }
  if (data.startsWith("tg:toggle:")) {
    const [, , routeId, enabledValue] = data.split(":");
    if (!new Set(["0", "1"]).has(enabledValue)) {
      return renderTelegramBridges(chatId, messageId);
    }
    await assertOwnedRoute("telegram", from.id, routeId);
    await db("UPDATE repost_routes SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [Number(enabledValue), routeId]);
    return renderTelegramBridges(chatId, messageId);
  }
  if (data.startsWith("tg:delete:")) {
    const routeId = data.split(":")[2];
    const existing = await db("SELECT 1 FROM repost_routes WHERE id = ? LIMIT 1", [routeId]);
    if (!existing[0]) return renderTelegramBridges(chatId, messageId);
    const account = await assertOwnedRoute("telegram", from.id, routeId);
    await deleteRouteAndReleaseUnusedChannels(routeId, account.id);
    return renderTelegramBridges(chatId, messageId);
  }
}

function extractMaxUser(update) {
  return update?.callback?.user || update?.user || update?.message?.sender || update?.sender || update?.from || null;
}

function extractMaxChat(update) {
  return update?.chat || update?.message?.chat || update?.data?.chat || null;
}

function extractMaxMessage(update) {
  if (update?.message) return update.message;
  if (update?.data?.message) return update.data.message;
  if (update?.body && (update.body.text || typeof update.body === "string")) return update;
  return {};
}

function extractMaxCallback(update) {
  if (update?.callback) return update.callback;
  if (update?.data?.callback) return update.data.callback;
  if (update?.callback_id || update?.payload) return update;
  return {};
}

function maxEventChatId(update, chat = {}, message = {}, callback = {}) {
  return (
    update?.chat_id ||
    callback?.chat_id ||
    callback?.message?.chat_id ||
    message?.chat_id ||
    message?.recipient?.chat_id ||
    message?.recipient?.chat?.chat_id ||
    message?.recipient?.chat?.id ||
    message?.chat?.chat_id ||
    message?.chat?.id ||
    update?.message_created?.chat_id ||
    chat?.chat_id ||
    chat?.id ||
    null
  );
}

function maxEventChatTitle(update, chat = {}, message = {}) {
  return (
    message?.chat_title ||
    chat?.title ||
    update?.chat_title ||
    null
  );
}

function maxEventChatType(update, chat = {}, message = {}) {
  if (typeof update?.is_channel === "boolean") {
    return update.is_channel ? "channel" : "chat";
  }
  return (
    message?.chat_type ||
    message?.recipient?.chat_type ||
    message?.recipient?.chat?.type ||
    message?.chat?.type ||
    chat?.type ||
    update?.chat_type ||
    ""
  );
}

function maxMessageText(message = {}) {
  if (typeof message?.body?.text === "string") return message.body.text;
  if (typeof message?.body === "string") return message.body;
  if (typeof message?.text === "string") return message.text;
  return "";
}

async function handleMaxMenuMessage(chatId, text = MAIN_MENU_TEXT) {
  debugLog("max_menu_outgoing", {
    chatId,
    buttons: maxMainButtons().map((row) => row.map((button) => button.text))
  });
  return sendMaxChat(chatId, text, maxKeyboard(maxMainButtons()));
}

async function deliverMaxChannelMessage(job, assertOwned) {
  const storedMessage = job.message || {};
  // The webhook payload is the immutable delivery manifest. Re-fetching by mid
  // here would let an edit between retries change part boundaries while old
  // operation keys still describe the original send.
  const fullMessage = storedMessage;
  const chatId = job.identity.chatId;
  const sourceIdentity = maxSourceIdentity(chatId, fullMessage);
  const contentMessages = maxRelayContentMessages(fullMessage);
  const telegramPayloads = contentMessages.map((contentMessage) => {
    const text = maxMessageText(contentMessage);
    const attList = maxAttachmentList(contentMessage);
    const telegramTextParts = maxTelegramTextParts(text, attList);
    const telegramText = telegramTextParts[0] || "";
    return {
      text: telegramText,
      supplemental_texts: telegramTextParts.slice(1),
      entities: maxMessageEntitiesForTelegram(contentMessage),
      media: maxAttachmentsToTelegram(attList),
      reply_markup: maxInlineKeyboardToTelegram(attList, telegramText)
    };
  });
  const maxPayloads = contentMessages.flatMap((contentMessage, contentIndex) => {
    const text = maxMessageText(contentMessage);
    const attList = maxAttachmentList(contentMessage);
    const maxFormatted = maxMessageTextForMax(contentMessage);
    const payloads = splitMaxPayload({
      text: maxFormatted.text,
      plainText: text,
      format: maxFormatted.format,
      attachments: maxAttachmentRequests(attList)
    });
    return payloads.map((payload, payloadIndex) => ({
      payload,
      operationKey: contentIndex === 0
        ? (payloads.length === 1 ? "whole" : `message:${payloadIndex}`)
        : `content:${contentIndex}:message:${payloadIndex}`
    }));
  });

  await assertOwned();
  if (await shouldIgnoreOutboundWebhook(
    sourceIdentity.platform,
    sourceIdentity.chatId,
    sourceIdentity.messageIds
  )) {
    debugLog("relay_outbound_webhook_ignored", {
      platform: sourceIdentity.platform,
      chatId: sourceIdentity.chatId,
      messageIds: sourceIdentity.messageIds
    });
    return;
  }
  const links = Array.isArray(job.routes) ? job.routes : [];
  debugLog("max_links_resolved", {
    chatId,
    links: links.map((link) => ({
      id: link.route_id,
      target_platform: link.platform,
      target_chat_id: link.chat_id
    }))
  });
  const targetFailures = [];
  await forEachRelayTargetWithLease(links, assertOwned, async (link) => {
    try {
      const activeTarget = await relayTargetIsActive(
        link.route_id,
        "max",
        chatId,
        link.platform,
        link.chat_id,
        link.target_id || null
      );
      if (!activeTarget) {
        debugLog("relay_target_no_longer_active", {
          routeId: link.route_id,
          sourcePlatform: "max",
          sourceChatId: String(chatId),
          targetPlatform: link.platform,
          targetChatId: String(link.chat_id)
        });
        return;
      }
      const deliveryTargetChatId = activeTarget.targetChatId;
      if (await outboundTargetIsCompleted(sourceIdentity, link.platform, deliveryTargetChatId)) {
        return;
      }
      if (link.platform === "telegram") {
        for (let index = 0; index < telegramPayloads.length; index += 1) {
          const telegramPayload = telegramPayloads[index];
          await sendTelegramBridgeMessage(
            deliveryTargetChatId,
            telegramPayload,
            (operationKey, send) => sendTrackedOutbound({
              sourceIdentity,
              targetPlatform: "telegram",
              targetChatId: deliveryTargetChatId,
              operationKey: index === 0
                ? operationKey
                : `content:${index}:${operationKey}`,
              send,
              extractMessageIds: extractTelegramOutboundMessageIds
            })
          );
        }
      } else {
        for (const maxPayload of maxPayloads) {
          await sendTrackedOutbound({
            sourceIdentity,
            targetPlatform: "max",
            targetChatId: deliveryTargetChatId,
            operationKey: maxPayload.operationKey,
            send: (markRequestStarted) => sendMaxPayload(
              deliveryTargetChatId,
              maxPayload.payload,
              markRequestStarted
            ),
            extractMessageIds: extractMaxOutboundMessageIds
          });
        }
      }
      await markOutboundTargetCompleted(sourceIdentity, link.platform, deliveryTargetChatId);
      debugLog("max_relay_delivered", {
        sourceChatId: String(chatId),
        sourceMessageIds: sourceIdentity.messageIds,
        targetPlatform: link.platform,
        targetChatId: String(deliveryTargetChatId)
      });
    } catch (error) {
      if (error?.code === "RELAY_SOURCE_LEASE_LOST") throw error;
      targetFailures.push({ link, error });
      debugLog("max_relay_target_failed", {
        routeId: link.route_id,
        targetPlatform: link.platform,
        targetChatId: String(link.chat_id),
        code: relayFailureCode(error)
      });
    }
  });
  throwRelayTargetFailures(targetFailures);
}

let maxRelayWorkerRunning = false;

async function processMaxRelayJob(job) {
  try {
    await withRelaySourceHeartbeat(
      job,
      (assertOwned) => deliverMaxChannelMessage(job, assertOwned),
      "max_relay"
    );
    const completed = await finishRelaySourceEvent(
      job.identity,
      "completed",
      null,
      job.leaseToken
    );
    if (!completed) {
      debugLog("max_relay_completion_lease_lost", {
        eventId: job.identity.eventId
      });
    }
  } catch (error) {
    const retryAfterSeconds = relayRetryAfterSeconds(error);
    const failure = relayHasFailureCode(error, "OUTBOUND_DELIVERY_UNCERTAIN")
      ? await terminalizeRelayJobWithCode(job, "OUTBOUND_DELIVERY_UNCERTAIN")
      : error?.code === "OUTBOUND_ECHO_UNCERTAIN"
      ? await terminalizeRelayJobWithCode(job, "OUTBOUND_ECHO_UNCERTAIN")
      : error?.code === "OUTBOUND_ECHO_PENDING"
      ? await deferRelayJobWithoutAttempt(job, error)
      : retryAfterSeconds > 0
        ? await deferRelayJobWithoutAttempt(job, error, retryAfterSeconds)
      : await failRelayJob(job, error);
    debugLog(
      failure.uncertain
        ? "max_relay_delivery_uncertain"
        : failure.deferred
        ? "max_relay_deferred"
        : failure.terminal ? "max_relay_terminal" : "max_relay_retry_scheduled",
      {
      eventId: job.identity.eventId,
      attempt: job.attemptCount,
      retryDelaySeconds: failure.retryDelay,
      leaseOwned: failure.updated,
      code: relayFailureCode(error),
      causeCode: error?.cause ? relayFailureCode(error.cause) : null
      }
    );
  }
}

async function runMaxRelayWorker() {
  if (!workersEnabled(env) || !platformEnabled(env, "max")) return;
  if (maxRelayWorkerRunning) return;
  maxRelayWorkerRunning = true;
  try {
    for (let processed = 0; processed < 25; processed += 1) {
      const job = await claimNextRelayJob("max");
      if (!job) break;
      if (job.terminalized) {
        debugLog("max_relay_terminal", {
          eventId: job.eventId,
          attempt: job.attemptCount,
          code: job.code || "retry_limit_exhausted"
        });
        continue;
      }
      await processMaxRelayJob(job);
    }
  } catch (error) {
    debugLog("max_relay_worker_failed", { code: relayFailureCode(error) });
  } finally {
    maxRelayWorkerRunning = false;
  }
}

function startMaxRelayWorker() {
  if (!workersEnabled(env) || !platformEnabled(env, "max")) return;
  void runMaxRelayWorker();
  const timer = setInterval(
    () => void runMaxRelayWorker(),
    RELAY_RETRY_POLICY.pollMilliseconds
  );
  timer.unref?.();
}

async function handleMaxEventOnce(body, receipt = null) {
  const updateType = body.update_type || body.type || body.event || body?.update?.type || "";
  const user = extractMaxUser(body) || {};
  const chat = extractMaxChat(body) || {};
  const message = extractMaxMessage(body);
  const callback = extractMaxCallback(body);
  const eventChatId = maxEventChatId(body, chat, message, callback);
  debugLog("max_event", {
    updateType,
    chatId: eventChatId,
    userId: user.user_id || user.id || null
  });
  await rememberInboundEvent("max", updateType || "unknown", eventChatId, user.user_id || user.id || null, body);

  if (updateType === "bot_added") {
    if (eventChatId) {
      await syncMaxChannel(
        eventChatId,
        maxEventChatTitle(body, chat, message) || String(eventChatId),
        maxEventChatType(body, chat, message),
        "added"
      );
    }
    return { ok: true, recorded: true };
  }

  if (updateType === "bot_removed") {
    if (eventChatId) {
      await db(
        `UPDATE max_channels
         SET bot_status = 'removed', can_post = 0, is_active = 0,
             last_seen_at = UTC_TIMESTAMP()
         WHERE chat_id = ?`,
        [String(eventChatId)]
      );
    }
    return { ok: true, recorded: true };
  }

  if (updateType === "bot_started") {
    const userId = user.user_id || user.id;
    const chatId = eventChatId;
    if (!userId || !chatId) return { ok: true, ignored: true };
    await rememberMaxUser(userId, chatId, user.username || "", user.first_name || user.name || "");
    const access = await accountAccess("max", userId);
    if (access.blocked) {
      await sendMaxChat(chatId, access.reason);
      return { ok: true, ignored: true };
    }
    if (env.PUBLIC_MAX_ENABLED !== "1") {
      await sendMaxChat(chatId, "Публичный доступ сейчас выключен владельцем сервиса.");
      return { ok: true, ignored: true };
    }
    await setMaxState(userId, null, null);
    await handleMaxMenuMessage(chatId);
    return { ok: true };
  }

  if (updateType === "message_created") {
    const chatId = eventChatId;
    const userId = user.user_id || user.id;
    const initialChatType = maxEventChatType(body, chat, message);
    if (chatId && initialChatType && !isMaxDirectChat(initialChatType)) {
      await rememberMaxChannelActivity(
        chatId,
        maxEventChatTitle(body, chat, message) || String(chatId),
        initialChatType
      );
      const queued = await enqueueMaxRelayMessage(chatId, message);
      debugLog("max_relay_queued", {
        chatId: String(chatId),
        eventId: queued.eventId,
        queued: queued.queued,
        state: queued.state
      });
      return { ok: true, queued: queued.queued };
    }
    const fullMessage = await fetchMaxMessage(message?.body?.mid || message?.mid || null) || message;
    const chatType = maxEventChatType(body, chat, fullMessage);
    const text = maxMessageText(fullMessage);
    debugLog("max_message_created", {
      chatId,
      chatType,
      text
    });

    if (isMaxDirectChat(chatType) && userId) {
      await rememberMaxUser(userId, chatId, user.username || "", user.first_name || user.name || "");
      const access = await accountAccess("max", userId);
      if (access.blocked || env.PUBLIC_MAX_ENABLED !== "1") {
        await sendMaxChat(chatId, access.blocked ? access.reason : "Публичный доступ сейчас выключен владельцем сервиса.");
        return { ok: true, ignored: true };
      }
      const forwardedChannel = forwardedMaxChannel(fullMessage);
      if (forwardedChannel) {
        try {
          const title = await claimForwardedMaxChannel(userId, forwardedChannel);
          await sendMaxChat(chatId, `Канал «${title}» добавлен в ваш список. Теперь его можно использовать в пересылках.`);
        } catch (error) {
          await sendMaxChat(chatId, error.message || "Не удалось добавить канал.");
        }
        return { ok: true };
      }
      const directText = String(text || "").trim();
      if (/^\d{6}$/.test(directText)) {
        const result = await consumeAccountLinkCode("max", userId, directText, { receipt });
        await sendMaxChat(chatId, result.message);
        return { ok: true };
      }
      if (/^(связать аккаунты|связь аккаунтов|связь аккаунтов Telegram и МАКС)$/i.test(directText) || directText === "/link") {
        const account = await linkedAccountStatus("max", userId);
        await sendMaxChat(chatId, accountLinkStatusText(account));
        return { ok: true };
      }
      if (/^\/start$|^start$|^меню$/i.test(String(text).trim())) {
        await setMaxState(userId, null, null);
        await handleMaxMenuMessage(chatId);
      }
      return { ok: true };
    }

    return { ok: true };
  }

  if (updateType === "message_callback") {
    const callbackId = callback.callback_id || callback.id;
    const payload = callback.payload || body.payload || "";
    const chatId = eventChatId;
    const userId = callback.user_id || callback.user?.user_id || callback.user?.id || user.user_id || user.id;
    if (!callbackId || !chatId || !userId) return { ok: true, ignored: true };
    const access = await accountAccess("max", userId);
    if (access.blocked || env.PUBLIC_MAX_ENABLED !== "1") {
      await answerMaxCallback(
        callbackId,
        access.blocked ? access.reason : "Публичный доступ сейчас выключен владельцем сервиса."
      );
      return { ok: true, ignored: true };
    }
    const userRow = await getMaxUser(userId);
    if (payload === "max:link") {
      const account = await linkedAccountStatus("max", userId);
      const action = account.telegram_user_id ? "Заменить аккаунт Telegram" : "Связать аккаунт Telegram";
      const buttons = [[maxCallbackButton(action, "max:linkcode")]];
      if (account.telegram_user_id) buttons.push([maxCallbackButton("Отвязать аккаунт Telegram", "max:unlinktg")]);
      buttons.push([maxCallbackButton("← Назад", "max:menu")]);
      await answerMaxCallback(callbackId, accountLinkStatusText(account), buttons);
      return { ok: true };
    }
    if (payload === "max:linkcode") {
      const code = await createAccountLinkCode("max", userId);
      const buttons = [];
      if (env.TELEGRAM_BOT_URL) buttons.push([maxLinkButton("Открыть Telegram-бота", env.TELEGRAM_BOT_URL)]);
      buttons.push([maxCallbackButton("← Назад", "max:menu")]);
      await answerMaxCallback(callbackId, `Код замены связи: ${code}\n\nОтправьте этот код с нужного аккаунта Telegram в течение 10 минут.`, buttons);
      return { ok: true };
    }
    if (payload === "max:unlinktg") {
      const account = await linkedAccountStatus("max", userId);
      if (!account.telegram_user_id) {
        await answerMaxCallback(callbackId, `${accountLinkStatusText(account)}\n\nАккаунт Telegram уже не связан.`, [
          [maxCallbackButton("Связать аккаунт Telegram", "max:linkcode")],
          [maxCallbackButton("← Назад", "max:menu")]
        ]);
        return { ok: true };
      }
      await answerMaxCallback(callbackId, "Отвязать аккаунт Telegram?\n\nТекущие каналы и настроенные пересылки этой связки будут удалены.", [
        [maxCallbackButton("Да, отвязать Telegram", `max:unlinktgconfirm:${account.telegram_user_id}`)],
        [maxCallbackButton("Отмена", "max:link")]
      ]);
      return { ok: true };
    }
    if (payload === "max:unlinktgconfirm") {
      await answerMaxCallback(callbackId, "Это подтверждение устарело. Откройте раздел связи аккаунтов ещё раз.", [
        [maxCallbackButton("← К связи аккаунтов", "max:link")],
        [maxCallbackButton("← Назад", "max:menu")]
      ]);
      return { ok: true };
    }
    if (payload.startsWith("max:unlinktgconfirm:")) {
      const expectedTelegramUserId = payload.slice("max:unlinktgconfirm:".length);
      const unlinked = await unlinkTelegramAccountFromMax(userId, expectedTelegramUserId);
      const account = await linkedAccountStatus("max", userId);
      const outcome = unlinked === null
        ? "Связь аккаунтов уже изменилась; старое подтверждение отменено.\n\n"
        : unlinked
          ? "Аккаунт Telegram отвязан. Теперь его можно связать с другим аккаунтом МАКС.\n\n"
          : "Аккаунт Telegram уже не связан.\n\n";
      await answerMaxCallback(
        callbackId,
        `${outcome}${accountLinkStatusText(account)}`,
        [[maxCallbackButton("Связать аккаунт Telegram", "max:linkcode")], [maxCallbackButton("← Назад", "max:menu")]]
      );
      return { ok: true };
    }
    if (payload === "max:menu") {
      await setMaxState(userId, null, null);
      await answerMaxCallback(callbackId, MAIN_MENU_TEXT, maxMainButtons());
      return { ok: true };
    }
    if (payload === "max:noop") {
      await answerMaxCallback(
        callbackId,
        maxMessageText(message) || "Действие обработано.",
        maxCallbackRowsFromMessage(message)
      );
      return { ok: true };
    }
    if (payload === "max:addchannel") {
      await answerMaxCallback(
        callbackId,
        "Чтобы добавить МАКС-канал:\n\n1. Добавьте GitRePosted администратором канала с правом публикации.\n2. Перешлите сюда любую публикацию из этого канала.\n\nПосле проверки канал появится в списке при создании пересылки.",
        [[maxCallbackButton("← Назад", "max:menu")]]
      );
      return { ok: true };
    }
    if (payload === "max:bridges") {
      await renderMaxBridges(chatId, callbackId, 0, userId);
      return { ok: true };
    }
    if (payload.startsWith("max:bridges:")) {
      await renderMaxBridges(chatId, callbackId, parsePageZeroBased(payload.split(":")[2]), userId);
      return { ok: true };
    }
    if (payload === "max:channels") {
      await answerMaxCallback(callbackId, MAIN_MENU_TEXT, maxMainButtons());
      return { ok: true };
    }
    if (payload === "max:tgchannels") {
      await answerMaxCallback(callbackId, MAIN_MENU_TEXT, maxMainButtons());
      return { ok: true };
    }
    if (payload === "max:create") {
      await setMaxState(userId, "route_source", {});
      await renderMaxRouteSourcePicker(callbackId, userId);
      return { ok: true };
    }
    if (payload.startsWith("max:rsourcepage:")) {
      await renderMaxRouteSourcePicker(callbackId, userId, parsePageZeroBased(payload.split(":")[2]));
      return { ok: true };
    }
    if (payload.startsWith("max:rsrc:")) {
      const [, , platformCode, ...chatIdParts] = payload.split(":");
      await setMaxState(userId, "route_targets", { source_platform: channelPlatformFromCode(platformCode), source_chat_id: chatIdParts.join(":"), targets: [] });
      await renderMaxRouteTargetPicker(callbackId, userId);
      return { ok: true };
    }
    if (payload.startsWith("max:rtgt:")) {
      const [, , action, platformCode, ...chatIdParts] = payload.split(":");
      if (!new Set(["add", "remove"]).has(action)) {
        await renderMaxRouteTargetPicker(callbackId, userId);
        return { ok: true, stale: true };
      }
      const key = `${channelPlatformFromCode(platformCode)}:${chatIdParts.join(":")}`;
      await mutateRouteTargetState("max", userId, key, action);
      await renderMaxRouteTargetPicker(callbackId, userId);
      return { ok: true };
    }
    if (payload.startsWith("max:rtargetpage:")) {
      await renderMaxRouteTargetPicker(callbackId, userId, parsePageZeroBased(payload.split(":")[2]));
      return { ok: true };
    }
    if (payload === "max:rsave") {
      const current = await getMaxUser(userId);
      const statePayload = parseStatePayload(current?.state_payload);
      const targets = (statePayload.targets || []).map((key) => {
        const [platform, ...chatIdParts] = key.split(":");
        return { platform, chat_id: chatIdParts.join(":") };
      });
      const saved = await saveUniversalRouteForUser(
        "max",
        userId,
        statePayload.source_platform,
        statePayload.source_chat_id,
        targets,
        { receipt, responseKind: "callback" }
      );
      await answerMaxCallback(callbackId, `Пересылка сохранена. Получателей: ${saved.targetCount}.`, [[maxCallbackButton("← В меню", "max:menu")]]);
      return { ok: true };
    }
    if (/^max:(?:(?:editbridge|edittg|editmax|retg|remax|editdir|redir|picktg|pickmax|save)(?::|$)|(?:toggle|delete):bridge_)/.test(payload)) {
      await setMaxState(userId, null, null);
      await answerMaxCallback(
        callbackId,
        "Эта кнопка относится к прежней версии настройки. Откройте меню и создайте пересылку заново.",
        [[maxCallbackButton("← В меню", "max:menu")]]
      );
      return { ok: true };
    }
    if (payload.startsWith("max:editbridge:")) {
      const bridgeId = payload.split(":")[2];
      await assertOwnedBridge("max", userId, bridgeId);
      const row = await bridgeById(bridgeId);
      if (!row) {
        await renderMaxBridges(chatId, callbackId, 0, userId);
        return { ok: true };
      }
      await answerMaxCallback(callbackId, "Настройка связки.", [
        [maxCallbackButton(`💬 Telegram: ${compactButtonLabel(bridgeTelegramTitle(row), 28)}`, `max:edittg:${bridgeId}`)],
        [maxCallbackButton(`💬 МАКС: ${compactButtonLabel(bridgeMaxTitle(row), 28)}`, `max:editmax:${bridgeId}`)],
        [maxCallbackButton(`Направление: ${formatBridgeDirection(row.direction)}`, `max:editdir:${bridgeId}`)],
        [maxCallbackButton("← Назад", "max:bridges")]
      ]);
      return { ok: true };
    }
    if (payload.startsWith("max:edittg:")) {
      const bridgeId = payload.split(":")[2];
      await assertOwnedBridge("max", userId, bridgeId);
      const row = await bridgeById(bridgeId);
      if (!row) {
        await renderMaxBridges(chatId, callbackId, 0, userId);
        return { ok: true };
      }
      const rows = await channelsForAccount("max", userId, "telegram");
      const buttons = rows.map((item) => [maxCallbackButton(item.title, `max:retg:${bridgeId}:${item.chat_id}`)]);
      buttons.push([maxCallbackButton("← Назад", "max:bridges")]);
      await answerMaxCallback(callbackId, `Выберите новый Telegram-канал для связки с ${row.max_title || row.max_chat_id}.`, buttons);
      return { ok: true };
    }
    if (payload.startsWith("max:editmax:")) {
      const bridgeId = payload.split(":")[2];
      await assertOwnedBridge("max", userId, bridgeId);
      const row = await bridgeById(bridgeId);
      if (!row) {
        await renderMaxBridges(chatId, callbackId, 0, userId);
        return { ok: true };
      }
      const rows = await channelsForAccount("max", userId, "max");
      const buttons = rows.map((item) => [maxCallbackButton(item.title, `max:remax:${bridgeId}:${item.chat_id}`)]);
      buttons.push([maxCallbackButton("← Назад", "max:bridges")]);
      await answerMaxCallback(callbackId, `Выберите новый MAX-канал для связки с ${row.telegram_title || row.telegram_chat_id}.`, buttons);
      return { ok: true };
    }
    if (payload.startsWith("max:retg:")) {
      const [, , bridgeId, telegramChatId] = payload.split(":");
      const account = await assertOwnedBridge("max", userId, bridgeId);
      await assertAccountChannel(account.id, "telegram", telegramChatId);
      const row = await bridgeById(bridgeId);
      if (!row) {
        await renderMaxBridges(chatId, callbackId, 0, userId);
        return { ok: true };
      }
      await updateBridgeChannels(bridgeId, telegramChatId, row.max_chat_id);
      await renderMaxBridges(chatId, callbackId, 0, userId);
      return { ok: true };
    }
    if (payload.startsWith("max:remax:")) {
      const [, , bridgeId, maxChatId] = payload.split(":");
      const account = await assertOwnedBridge("max", userId, bridgeId);
      await assertAccountChannel(account.id, "max", maxChatId);
      const row = await bridgeById(bridgeId);
      if (!row) {
        await renderMaxBridges(chatId, callbackId, 0, userId);
        return { ok: true };
      }
      await updateBridgeChannels(bridgeId, row.telegram_chat_id, maxChatId);
      await renderMaxBridges(chatId, callbackId, 0, userId);
      return { ok: true };
    }
    if (payload.startsWith("max:editdir:")) {
      const bridgeId = payload.split(":")[2];
      await assertOwnedBridge("max", userId, bridgeId);
      await answerMaxCallback(callbackId, "Выберите направление связки.", [
        [maxCallbackButton("в обе стороны", `max:redir:${bridgeId}:both`)],
        [maxCallbackButton("из Telegram в МАКС", `max:redir:${bridgeId}:tg_to_max`)],
        [maxCallbackButton("из МАКС в Telegram", `max:redir:${bridgeId}:max_to_tg`)],
        [maxCallbackButton("← Назад", `max:editbridge:${bridgeId}`)]
      ]);
      return { ok: true };
    }
    if (payload.startsWith("max:redir:")) {
      const [, , bridgeId, direction] = payload.split(":");
      await assertOwnedBridge("max", userId, bridgeId);
      await updateBridgeDirection(bridgeId, direction);
      await renderMaxBridges(chatId, callbackId, 0, userId);
      return { ok: true };
    }
    if (payload.startsWith("max:pickmax:")) {
      const maxChatId = payload.split(":")[2];
      const rows = await channelsForAccount("max", userId, "telegram");
      const buttons = rows.map((row) => [maxCallbackButton(row.title, `max:picktg:${maxChatId}:${row.chat_id}`)]);
      buttons.push([maxCallbackButton("← Назад", "max:create")]);
      await answerMaxCallback(callbackId, "Теперь выберите Telegram-канал.", buttons);
      return { ok: true };
    }
    if (payload.startsWith("max:picktg:")) {
      const [, , maxChatId, telegramChatId] = payload.split(":");
      await answerMaxCallback(callbackId, "Выберите направление связки.", [
        [maxCallbackButton("Обе стороны", `max:save:${telegramChatId}:${maxChatId}:both`)],
        [maxCallbackButton("MAX → Telegram", `max:save:${telegramChatId}:${maxChatId}:max_to_tg`)],
        [maxCallbackButton("Telegram → MAX", `max:save:${telegramChatId}:${maxChatId}:tg_to_max`)],
        [maxCallbackButton("← Назад", "max:create")]
      ]);
      return { ok: true };
    }
    if (payload.startsWith("max:save:")) {
      const [, , telegramChatId, maxChatId, direction] = payload.split(":");
      await saveBridge("max", userId, telegramChatId, maxChatId, direction);
      await renderMaxBridges(chatId, callbackId, 0, userId);
      return { ok: true };
    }
    if (payload.startsWith("max:toggle:")) {
      const [, , routeId, enabledValue] = payload.split(":");
      if (!new Set(["0", "1"]).has(enabledValue)) {
        await renderMaxBridges(chatId, callbackId, 0, userId);
        return { ok: true, stale: true };
      }
      await assertOwnedRoute("max", userId, routeId);
      await db("UPDATE repost_routes SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [Number(enabledValue), routeId]);
      await renderMaxBridges(chatId, callbackId, 0, userId);
      return { ok: true };
    }
    if (payload.startsWith("max:delete:")) {
      const routeId = payload.split(":")[2];
      const existing = await db("SELECT 1 FROM repost_routes WHERE id = ? LIMIT 1", [routeId]);
      if (!existing[0]) {
        await renderMaxBridges(chatId, callbackId, 0, userId);
        return { ok: true, replayed: true };
      }
      const account = await assertOwnedRoute("max", userId, routeId);
      await deleteRouteAndReleaseUnusedChannels(routeId, account.id);
      await renderMaxBridges(chatId, callbackId, 0, userId);
      return { ok: true };
    }
  }

  return { ok: true, ignored: true };
}

async function handleMaxEvent(body) {
  const updateType = maxIngressEventType(body);
  const providerEventId = maxIngressProviderEventId(body, updateType);
  const receipt = await claimBotEventReceipt("max", updateType, providerEventId);
  if (!receipt.claimed) {
    debugLog("max_event_duplicate", { providerEventId, updateType });
    if (receipt.disposition === "in_progress") {
      const error = new Error("MAX event is already being processed.");
      error.code = "BOT_EVENT_IN_PROGRESS";
      throw error;
    }
    return { ok: true, duplicate: true };
  }
  try {
    const result = await withBotEventReceiptHeartbeat(receipt, async (assertReceipt) => {
      await assertReceipt();
      const handled = ["save_route", "consume_link_code"].includes(receipt.result?.action)
        ? await replayMaxBotAction(body, receipt)
        : await handleMaxEventOnce(body, receipt);
      await assertReceipt();
      return handled;
    });
    const finished = await finishBotEventReceipt(receipt, "max", "completed");
    if (!finished) {
      const error = new Error("MAX callback receipt lease was lost.");
      error.code = "BOT_EVENT_LEASE_LOST";
      throw error;
    }
    return result;
  } catch (error) {
    try {
      await finishBotEventReceipt(receipt, "max", "failed", error);
    } catch (receiptError) {
      debugLog("max_event_receipt_finish_failed", {
        providerEventId,
        updateType,
        code: relayFailureCode(receiptError)
      });
    }
    throw error;
  }
}

function maxCallbackIsAlreadyClosed(error) {
  const status = Number(error?.httpStatus || 0);
  if (![400, 404, 409, 410].includes(status)) return false;
  const message = String(error?.message || "");
  return /callback[\s\S]*(?:already|answered|expired|not[ _.-]?found|unknown)|(?:already|expired)[\s\S]*callback/i.test(message);
}

async function replayMaxBotAction(body, receipt) {
  const result = receipt?.result;
  const retryGuaranteedResponseFailure = receipt?.lastError === "MAX_RATE_LIMIT";
  if (result?.action === "consume_link_code") {
    if (retryGuaranteedResponseFailure) {
      const callback = extractMaxCallback(body);
      const message = extractMaxMessage(body);
      const chat = extractMaxChat(body) || {};
      const chatId = maxEventChatId(body, chat, message, callback);
      if (chatId) {
        await sendMaxChat(
          chatId,
          result.message || "Аккаунты Telegram и МАКС успешно связаны."
        );
      }
    }
    debugLog("max_link_result_replayed_without_duplicate_send", {
      providerEventId: maxIngressProviderEventId(body, maxIngressEventType(body)),
      responseRetried: retryGuaranteedResponseFailure
    });
    return { ok: true, replayed: true };
  }
  const callback = extractMaxCallback(body);
  const callbackId = callback.callback_id || callback.id;
  if (!callbackId) return { ok: true, replayed: true };
  try {
    await answerMaxCallback(
      callbackId,
      `Пересылка сохранена. Получателей: ${Number(result.target_count || 0)}.`,
      [[maxCallbackButton("← В меню", "max:menu")]]
    );
  } catch (error) {
    if (!maxCallbackIsAlreadyClosed(error)) throw error;
    debugLog("max_callback_replay_already_closed", {
      callbackId: String(callbackId),
      code: relayFailureCode(error)
    });
  }
  return { ok: true, replayed: true };
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/landing.html")) {
      return sendText(res, 200, renderPublicHtml(await readStaticFile("landing.html"), env.PUBLIC_BASE_URL), "text/html; charset=utf-8");
    }
    if (req.method === "GET" && url.pathname === "/index.html") {
      res.writeHead(301, { location: publicLocalPath(env.PUBLIC_BASE_URL, "/control/") });
      return res.end();
    }
    if (req.method === "GET" && (url.pathname === "/control" || url.pathname === "/control/")) {
      return sendText(res, 200, renderPublicHtml(await readStaticFile("index.html"), env.PUBLIC_BASE_URL), "text/html; charset=utf-8");
    }
    if (req.method === "GET" && url.pathname === "/landing.css") {
      return sendText(res, 200, await readStaticFile("landing.css"), "text/css; charset=utf-8");
    }
    if (req.method === "GET" && url.pathname === "/landing-strict.css") {
      return sendText(res, 200, await readStaticFile("landing-strict.css"), "text/css; charset=utf-8");
    }
    if (req.method === "GET" && url.pathname === "/app.js") {
      return sendText(res, 200, await readStaticFile("app.js"), "application/javascript; charset=utf-8");
    }
    if (req.method === "GET" && url.pathname === "/app.css") {
      return sendText(res, 200, await readStaticFile("app.css"), "text/css; charset=utf-8");
    }
    if (req.method === "GET" && url.pathname === "/assets/telegram.png") {
      return sendText(res, 200, await readStaticFile("assets/telegram.png"), "image/png");
    }
    if (req.method === "GET" && url.pathname === "/assets/max.png") {
      return sendText(res, 200, await readStaticFile("assets/max.png"), "image/png");
    }
    if (req.method === "GET" && url.pathname === "/assets/reposted-logo.png") {
      return sendText(res, 200, await readStaticFile("assets/reposted-logo.png"), "image/png");
    }
    if (req.method === "GET" && url.pathname === "/health") {
      return json(res, 200, { ok: true, now: new Date().toISOString() });
    }
    if (req.method === "GET" && url.pathname === "/api/public-status") {
      const telegramPublic = platformEnabled(env, "telegram") && env.PUBLIC_TELEGRAM_ENABLED === "1";
      const maxPublic = platformEnabled(env, "max") && env.PUBLIC_MAX_ENABLED === "1";
      return json(res, 200, {
        ok: true,
        telegram: {
          public: telegramPublic,
          url: telegramPublic ? env.TELEGRAM_BOT_URL || "" : ""
        },
        max: {
          public: maxPublic,
          url: maxPublic ? env.MAX_BOT_URL || "" : ""
        }
      });
    }
    if (req.method === "GET" && url.pathname === "/api/auth-config") {
      const rows = await db("SELECT COUNT(*) AS total FROM admin_passkeys");
      return json(res, 200, {
        ok: true,
        hcaptcha_enabled: env.HCAPTCHA_ENABLED !== "0",
        hcaptcha_sitekey: env.HCAPTCHA_SITEKEY || "",
        passkey_available: Number(rows[0]?.total || 0) > 0
      });
    }
    if (req.method === "POST" && url.pathname === "/api/passkeys/auth/options") {
      if (passkeyAuthenticationRateLimited(req, res)) return;
      return json(res, 200, { ok: true, options: await passkeyAuthenticationOptions() });
    }
    if (req.method === "POST" && url.pathname === "/api/passkeys/auth/verify") {
      if (passkeyAuthenticationRateLimited(req, res)) return;
      const body = await readBody(req);
      await authenticateAdminPasskey(body, res);
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/api/login") {
      const ip = requestIp(req);
      const blockedMinutes = adminLoginBlocked(ip);
      if (blockedMinutes) {
        return json(res, 429, { error: "too_many_attempts", message: `Слишком много попыток входа. Повторите через ${blockedMinutes} мин.` });
      }
      const body = await readBody(req);
      if (!(await verifyHcaptcha(req, body.hcaptcha_token))) {
        return json(res, 403, { error: "captcha_failed", message: "Подтвердите, что вы не робот." });
      }
      if (!verifyAdminCredentials(env, body.username, body.password)) {
        recordAdminLoginFailure(ip);
        return unauthorized(res);
      }
      adminLoginAttempts.delete(ip);
      createAdminSession(res);
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/api/logout") {
      clearAdminSession(req, res);
      return json(res, 200, { ok: true });
    }
    if (req.method === "GET" && url.pathname === "/api/session") {
      const authorized = ensureAdmin(req, url);
      return json(res, authorized ? 200 : 401, { ok: authorized });
    }
    if (req.method === "GET" && url.pathname === "/api/passkeys") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      return json(res, 200, { ok: true, passkeys: await adminPasskeysState(), limit: 3 });
    }
    if (req.method === "POST" && url.pathname === "/api/passkeys/register/options") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      return json(res, 200, { ok: true, options: await passkeyRegistrationOptions(req) });
    }
    if (req.method === "POST" && url.pathname === "/api/passkeys/register/verify") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      return json(res, 200, { ok: true, passkeys: await registerAdminPasskey(req, body) });
    }
    if (req.method === "DELETE" && url.pathname.startsWith("/api/passkeys/")) {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const passkeyId = decodeURIComponent(url.pathname.split("/").pop() || "");
      await db("DELETE FROM admin_passkeys WHERE id = ?", [passkeyId]);
      return json(res, 200, { ok: true, passkeys: await adminPasskeysState() });
    }
    if (req.method === "POST" && url.pathname === "/api/change-password") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      if (String(body.new_password || "") !== String(body.confirm_password || "")) {
        return json(res, 400, { error: "password_mismatch", message: "Подтверждение пароля не совпадает." });
      }
      changeAdminPassword(body.current_password, body.new_password, req, res);
      return json(res, 200, { ok: true });
    }
    if (req.method === "GET" && url.pathname === "/api/channels") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      return json(res, 200, { ok: true, ...(await adminChannelState()) });
    }
    if (req.method === "GET" && url.pathname === "/api/bridges") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const page = parsePositiveInt(url.searchParams.get("page"), 1);
      const perPage = parsePositiveInt(url.searchParams.get("per_page"), 10);
      return json(res, 200, { ok: true, ...(await adminBridgeState(page, perPage)) });
    }
    if (req.method === "GET" && url.pathname === "/api/system") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      return json(res, 200, { ok: true, ...(await adminSystemState()) });
    }
    if (req.method === "GET" && url.pathname === "/api/relay/uncertain") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const state = await debugState();
      return json(res, 200, {
        ok: true,
        operations: state.uncertain_outbound_operations,
        quarantined_events: state.quarantined_source_events
      });
    }
    if (req.method === "POST" && url.pathname === "/api/relay/uncertain/resolve") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      const result = await resolveUncertainOutboundOperation(
        body.id,
        body.resolution,
        body.message_ids
      );
      return json(res, 200, { ok: true, result });
    }
    if (req.method === "GET" && url.pathname === "/api/config") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      return json(res, 200, { ok: true, config: editableConfigState() });
    }
    if (req.method === "GET" && url.pathname === "/api/service") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      return json(res, 200, {
        ok: true,
        service: {
          status: "running",
          pid: process.pid,
          uptime_seconds: Math.floor(process.uptime()),
          started_at: new Date(Date.now() - process.uptime() * 1000).toISOString(),
          telegram_configured: Boolean(
            env.TELEGRAM_BOT_TOKEN && webhookSecretConfigured(env.TELEGRAM_WEBHOOK_SECRET)
          ),
          max_configured: Boolean(
            env.MAX_BOT_TOKEN && webhookSecretConfigured(env.MAX_WEBHOOK_SECRET)
          ),
          local_telegram_api: telegramLocalFileModeEnabled()
        }
      });
    }
    if (req.method === "POST" && url.pathname === "/api/service/restart") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      json(res, 202, { ok: true, restarting: true });
      setTimeout(() => {
        process.exit(0);
      }, 300);
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/admin/permissions") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      return json(res, 200, { ok: true, permissions: ADMIN_PERMISSIONS });
    }
    if (req.method === "GET" && url.pathname === "/api/accounts") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      return json(res, 200, { ok: true, accounts: await adminAccountsState() });
    }
    if (req.method === "POST" && url.pathname === "/api/accounts/moderate") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      return json(res, 200, { ok: true, account: await adminModerateAccount(body) });
    }
    if (req.method === "GET" && url.pathname === "/api/admin/users") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const platform = String(url.searchParams.get("platform") || "telegram");
      const query = String(url.searchParams.get("query") || "");
      return json(res, 200, { ok: true, users: await adminUsersState(platform, query) });
    }
    if (req.method === "POST" && url.pathname === "/api/config") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      return json(res, 200, { ok: true, config: await updateEditableConfig(body) });
    }
    if (req.method === "POST" && url.pathname === "/api/admin/users") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      return json(res, 200, { ok: true, user: await adminUpsertUserAccess(body) });
    }
    if (req.method === "DELETE" && url.pathname === "/api/admin/users") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      await adminDeleteUserAccess(body);
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/api/bridges") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      const bridge = await adminSaveBridge(body);
      return json(res, 200, { ok: true, bridge });
    }
    if (req.method === "POST" && url.pathname === "/api/bridges/toggle") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      await db("UPDATE repost_routes SET enabled = NOT enabled, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [String(body.id || "")]);
      return json(res, 200, { ok: true });
    }
    if (req.method === "DELETE" && url.pathname.startsWith("/api/bridges/")) {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const bridgeId = decodeURIComponent(url.pathname.split("/").pop() || "");
      const rows = await db("SELECT account_id FROM repost_routes WHERE id = ? LIMIT 1", [bridgeId]);
      if (rows[0]) await deleteRouteAndReleaseUnusedChannels(bridgeId, rows[0].account_id);
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/api/setup/telegram-webhook") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      assertPlatformEnabled("telegram");
      assertWebhookSettingsApplied();
      const body = await readBody(req);
      if (body.takeover !== undefined && typeof body.takeover !== "boolean") return json(res, 400, { error: "invalid_request" });
      const publicBaseUrl = requestPublicBaseUrl(req);
      await replaceTelegramWebhookSubscription(`${publicBaseUrl}/webhooks/telegram`, body.takeover === true);
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/api/setup/max-webhook") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      assertPlatformEnabled("max");
      assertWebhookSettingsApplied();
      const body = await readBody(req);
      if (body.takeover !== undefined && typeof body.takeover !== "boolean") return json(res, 400, { error: "invalid_request" });
      const publicBaseUrl = requestPublicBaseUrl(req);
      await replaceMaxWebhookSubscription(`${publicBaseUrl}/webhooks/max`, body.takeover === true);
      return json(res, 200, { ok: true });
    }
    if (req.method === "GET" && url.pathname === "/debug/state") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      return json(res, 200, { ok: true, state: await debugState() });
    }
    if (req.method === "POST" && url.pathname === "/setup-webhooks") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      if (body.takeover !== undefined && typeof body.takeover !== "boolean") return json(res, 400, { error: "invalid_request" });
      await setWebhooks(body.takeover === true);
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/admin/reconcile-telegram-bridges") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const result = await adminReconcileTelegramBridgeIds();
      return json(res, 200, { ok: true, bridges: result });
    }
    if (req.method === "POST" && url.pathname === "/admin/upsert-max-channel") {
      if (!ensureAdmin(req, url)) return unauthorized(res);
      const body = await readBody(req);
      const result = await adminUpsertMaxChannel(
        String(body.chat_id || ""),
        String(body.title || ""),
        body.chat_type ? String(body.chat_type) : "channel",
        body.bot_status ? String(body.bot_status) : "member"
      );
      return json(res, 200, { ok: true, channels: result });
    }
    if (req.method === "POST" && url.pathname === "/webhooks/telegram") {
      if (!platformEnabled(env, "telegram")) return json(res, 503, { error: "telegram_disabled" });
      const configuredSecret = String(env.TELEGRAM_WEBHOOK_SECRET || "");
      const providedSecret = String(req.headers["x-telegram-bot-api-secret-token"] || "");
      if (!webhookSecretConfigured(configuredSecret)) {
        return json(res, 503, { error: "telegram_webhook_not_configured" });
      }
      if (!providedSecret || !secureEqual(providedSecret, configuredSecret)) {
        return json(res, 401, { error: "unauthorized" });
      }
      const body = await readBody(req);
      const eventType = telegramIngressEventType(body);
      const relayMessage = body.channel_post || body.edited_channel_post;
      if (relayMessage) {
        await enqueueTelegramRelayMessage(relayMessage, {
          replaceExisting: Boolean(body.edited_channel_post)
        });
      }
      const providerEventId = String(body?.update_id ?? JSON.stringify(body || {}));
      const queued = await enqueueBotIngressEvent(
        "telegram",
        eventType,
        providerEventId,
        body
      );
      return json(res, 200, { ok: true, queued: queued.queued });
    }
    if (req.method === "POST" && url.pathname === "/webhooks/max") {
      if (!platformEnabled(env, "max")) return json(res, 503, { error: "max_disabled" });
      const configuredSecret = String(env.MAX_WEBHOOK_SECRET || "");
      const providedSecret = String(
        req.headers["x-max-bot-api-secret"] || req.headers["x-hook-secret"] || ""
      );
      if (!webhookSecretConfigured(configuredSecret)) {
        return json(res, 503, { error: "max_webhook_not_configured" });
      }
      if (!providedSecret || !secureEqual(providedSecret, configuredSecret)) {
        return json(res, 401, { error: "unauthorized" });
      }
      const body = await readBody(req);
      const eventType = maxIngressEventType(body);
      if (eventType === "message_created") {
        const chat = extractMaxChat(body) || {};
        const message = extractMaxMessage(body);
        const eventChatId = maxEventChatId(body, chat, message, extractMaxCallback(body));
        const chatType = maxEventChatType(body, chat, message);
        if (eventChatId && !isMaxDirectChat(chatType)) {
          await enqueueMaxRelayMessage(eventChatId, message);
        }
      }
      const providerEventId = maxIngressProviderEventId(body, eventType);
      const queued = await enqueueBotIngressEvent("max", eventType, providerEventId, body);
      return json(res, 200, { ok: true, queued: queued.queued });
    }
    return json(res, 404, { error: "not_found" });
  } catch (error) {
    const statusCode = Number(error.statusCode) || 500;
    const code = statusCode === 409 && ["TAKEOVER_REQUIRED", "RESTART_REQUIRED"].includes(error.code)
      ? error.code.toLowerCase() : statusCode === 500 ? "internal_error" : "invalid_request";
    return json(res, statusCode, { error: code, message: error.message });
  }
});

const cliArguments = process.argv.slice(2);
if (cliArguments.length) {
  try {
    if (cliArguments.length !== 1 || !["--initialize", "--verify-schema"].includes(cliArguments[0])) {
      throw new Error("Expected exactly --initialize or --verify-schema.");
    }
    assertRuntimeConfiguration();
    if (cliArguments[0] === "--initialize") await ensureSchema();
    const result = await verifyRuntimeSchema(db);
    process.stdout.write(`${JSON.stringify({ ok: true, result })}\n`);
  } catch {
    process.stderr.write(`${JSON.stringify({ ok: false, error: "runtime_initialization_or_schema_verification_failed" })}\n`);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
} else {
  assertRuntimeConfiguration();
  await ensureSchema();
  startBotIngressWorkers();
  startTelegramRelayWorker();
  startMaxRelayWorker();
  server.listen(Number(env.PORT || 3010), env.HOST || "127.0.0.1");
}
