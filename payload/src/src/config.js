import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function loadDotEnv(envPath) {
  if (!fs.existsSync(envPath)) {
    return;
  }

  const content = fs.readFileSync(envPath, "utf8");
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const separatorIndex = line.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    const value = line.slice(separatorIndex + 1).trim().replace(/^"(.*)"$/, "$1");
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

const currentFile = fileURLToPath(import.meta.url);
const rootDir = path.resolve(path.dirname(currentFile), "..");
const envFilePath = process.env.GITREPOSTED_ENV_FILE
  || process.env.REPOSTED_ENV_FILE
  || "/etc/gitreposted/application.env";
loadDotEnv(envFilePath);

function required(name, fallback = "") {
  return process.env[name] || fallback;
}

export const config = {
  rootDir,
  publicDir: path.join(rootDir, "public"),
  dataDir: process.env.GITREPOSTED_DATA_DIR
    || required("REPOSTED_DATA_DIR", "/var/lib/gitreposted"),
  port: Number.parseInt(required("PORT", "3010"), 10),
  host: required("HOST", "0.0.0.0"),
  publicBaseUrl: required("PUBLIC_BASE_URL", ""),
  adminApiKey: required("ADMIN_API_KEY", ""),
  relayEventLeaseSeconds: Number.parseInt(required("RELAY_EVENT_LEASE_SECONDS", "300"), 10),
  relayIdTtlDays: Number.parseInt(required("RELAY_ID_TTL_DAYS", "30"), 10),
  relayRetryMaxAttempts: Number.parseInt(required("RELAY_RETRY_MAX_ATTEMPTS", "8"), 10),
  relayRetryBaseSeconds: Number.parseInt(required("RELAY_RETRY_BASE_SECONDS", "10"), 10),
  relayRetryMaxSeconds: Number.parseInt(required("RELAY_RETRY_MAX_SECONDS", "3600"), 10),
  relayRetryPollMs: Number.parseInt(required("RELAY_RETRY_POLL_MS", "1000"), 10),
  telegramAlbumSettleMs: Number.parseInt(required("TELEGRAM_ALBUM_SETTLE_MS", "5000"), 10),
  telegram: {
    token: required("TELEGRAM_BOT_TOKEN", ""),
    webhookSecret: required("TELEGRAM_WEBHOOK_SECRET", ""),
    apiBaseUrl: required("TELEGRAM_API_BASE_URL", "https://api.telegram.org"),
    botApiContainerDataDir: required("TELEGRAM_BOT_API_CONTAINER_DATA_DIR", "/var/lib/telegram-bot-api"),
    botApiHostDataDir: required("TELEGRAM_BOT_API_HOST_DATA_DIR", "/var/lib/gitreposted/telegram-bot-api"),
    relayTempSubdir: required("TELEGRAM_RELAY_TEMP_SUBDIR", "gitreposted-relay")
  },
  max: {
    token: required("MAX_BOT_TOKEN", ""),
    webhookSecret: required("MAX_WEBHOOK_SECRET", ""),
    apiBaseUrl: required("MAX_API_BASE_URL", "https://platform-api2.max.ru")
  },
  db: {
    host: required("DB_HOST", "127.0.0.1"),
    port: Number.parseInt(required("DB_PORT", "3306"), 10),
    name: required("DB_NAME", "GitRePosted"),
    user: required("DB_USER", "database"),
    password: required("DB_PASSWORD", "")
  }
};
