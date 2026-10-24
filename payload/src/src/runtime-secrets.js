const PLACEHOLDER_SECRET_PATTERN = /^(?:REPLACE(?:_|$)|CHANGE_ME|CHANGEME|EXAMPLE|TODO)/i;

export function runtimeSecretConfigured(value, minimumLength = 1) {
  const normalized = String(value || "").trim();
  return normalized.length >= minimumLength
    && !PLACEHOLDER_SECRET_PATTERN.test(normalized);
}

export function webhookSecretConfigured(value) {
  const normalized = String(value || "").trim();
  return runtimeSecretConfigured(normalized, 16)
    && normalized.length <= 256
    && /^[A-Za-z0-9_-]+$/.test(normalized);
}
