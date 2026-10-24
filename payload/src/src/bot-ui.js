const MAX_CALLBACK_TEXT_LENGTH = 128;
const MAX_CALLBACK_PAYLOAD_LENGTH = 1024;

function normalizedUiText(value, fallback = "") {
  const normalized = String(value ?? "")
    .replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]+/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  return normalized || fallback;
}

function fitsTextLimit(value, limit) {
  return value.length <= limit && Array.from(value).length <= limit;
}

export function compactUnicodeText(value, limit, fallback = "—") {
  const safeLimit = Math.max(1, Number.parseInt(String(limit ?? ""), 10) || 1);
  const normalized = normalizedUiText(value, normalizedUiText(fallback, "—"));
  if (fitsTextLimit(normalized, safeLimit)) return normalized;

  const suffix = safeLimit > 1 ? "…" : "";
  const contentLimit = safeLimit - suffix.length;
  let result = "";
  let codePoints = 0;
  for (const character of normalized) {
    if (codePoints + 1 > contentLimit || result.length + character.length > contentLimit) break;
    result += character;
    codePoints += 1;
  }
  return `${result}${suffix}` || "…";
}

function safeMaxCallbackPayload(payload) {
  const value = String(payload ?? "").trim();
  if (!value
    || !fitsTextLimit(value, MAX_CALLBACK_PAYLOAD_LENGTH)
    || /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(value)) {
    return "max:noop";
  }
  return value;
}

export function maxCallbackButton(text, payload) {
  return {
    type: "callback",
    text: compactUnicodeText(text, MAX_CALLBACK_TEXT_LENGTH, "Действие"),
    payload: safeMaxCallbackPayload(payload)
  };
}

function platformIcon(platform) {
  return platform === "max" ? "🟣" : "✈️";
}

function bridgeLine(row, fallbackIndex, limit) {
  const routeIndex = row?._index || fallbackIndex;
  const sourceTitle = compactUnicodeText(
    row?.source_title || row?.source_chat_id,
    36,
    "без названия"
  );
  const targets = Array.isArray(row?.targets) ? row.targets : [];
  const visibleTargets = targets.slice(0, 2).map((target) => (
    `${platformIcon(target?.platform)} ${compactUnicodeText(target?.title || target?.chat_id, 30, "без названия")}`
  ));
  const hiddenTargets = targets.length - visibleTargets.length;
  const targetDetails = targets.length === 0
    ? "нет получателей"
    : `${targets.length} получ.: ${visibleTargets.join(", ")}${hiddenTargets > 0 ? `, +${hiddenTargets}` : ""}`;
  const line = `${routeIndex}. ${platformIcon(row?.source_platform)} ${sourceTitle} → ${targetDetails}`;
  return compactUnicodeText(line, limit);
}

export function bridgeSummaryText(rows, limit, emptyText = "Пересылок пока нет.") {
  const safeLimit = Math.max(1, Number.parseInt(String(limit ?? ""), 10) || 1);
  const items = Array.isArray(rows) ? rows : [];
  if (items.length === 0) return compactUnicodeText(emptyText, safeLimit);

  const separator = "\n";
  const separatorLength = Math.max(0, items.length - 1) * separator.length;
  const lineLimit = Math.max(1, Math.floor((safeLimit - separatorLength) / items.length));
  const result = items
    .map((row, index) => bridgeLine(row, index + 1, lineLimit))
    .join(separator);

  // The page currently contains at most 25 rows. Keep this final guard so a
  // future pagination change cannot produce a provider-invalid message.
  return fitsTextLimit(result, safeLimit) ? result : compactUnicodeText(result, safeLimit);
}
