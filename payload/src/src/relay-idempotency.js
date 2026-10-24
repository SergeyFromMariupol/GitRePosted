import crypto from "node:crypto";

export function normalizePlatformMessageIds(values = []) {
  const input = Array.isArray(values) ? values : [values];
  return [...new Set(input
    .map((value) => String(value ?? "").trim())
    .filter((value) => value && value !== "0"))]
    .sort((left, right) => left.localeCompare(right, "en", { numeric: true }));
}

export function stableRelayEventId({
  platform,
  chatId,
  messageIds,
  groupId = ""
}) {
  const normalizedIds = normalizePlatformMessageIds(messageIds);
  if (!platform || !chatId || !normalizedIds.length) {
    throw new TypeError("Relay source platform, chat and message IDs are required.");
  }
  const identity = JSON.stringify({
    platform: String(platform),
    chat_id: String(chatId),
    group_id: String(groupId || ""),
    message_ids: normalizedIds
  });
  return crypto.createHash("sha256").update(identity).digest("hex");
}

export function stableOutboundOperationId({
  sourcePlatform,
  sourceChatId,
  sourceEventId,
  targetPlatform,
  targetChatId,
  operationKey = "whole"
}) {
  const values = [
    sourcePlatform,
    sourceChatId,
    sourceEventId,
    targetPlatform,
    targetChatId
  ].map((value) => String(value || ""));
  if (values.some((value) => !value)) {
    throw new TypeError("Outbound relay operation identity is incomplete.");
  }
  if (String(operationKey || "whole") !== "whole") {
    values.push(String(operationKey));
  }
  return crypto.createHash("sha256").update(JSON.stringify(values)).digest("hex");
}

export function outboundOperationDisposition(state, leaseActive = false) {
  if (state === "completed") return "skip";
  if (state === "uncertain") return "uncertain";
  if (state === "sending") return leaseActive ? "wait" : "uncertain";
  if (state === "pending" && leaseActive) return "wait";
  return "send";
}

export function telegramSourceIdentity(messages = []) {
  const normalizedMessages = (Array.isArray(messages) ? messages : [messages]).filter(Boolean);
  const first = normalizedMessages[0] || {};
  const chatId = first?.chat?.id;
  const messageIds = normalizePlatformMessageIds(
    normalizedMessages.map((message) => message?.message_id)
  );
  const groupId = normalizedMessages.find((message) => message?.media_group_id)?.media_group_id || "";
  return {
    platform: "telegram",
    chatId: String(chatId ?? ""),
    messageIds,
    groupId: String(groupId || ""),
    eventId: stableRelayEventId({
      platform: "telegram",
      chatId,
      messageIds,
      groupId
    })
  };
}

export function maxMessageId(message = {}) {
  const value = message?.body?.mid
    ?? message?.mid
    ?? message?.message_id
    ?? message?.body?.message_id
    ?? "";
  const providerId = String(value || "").trim();
  if (providerId) return providerId;

  // MAX permits body=null when a post contains only Message.link. Such a
  // message has no outer mid, so derive a retry-stable ID from the outer
  // message metadata rather than reusing the linked/original mid (the same
  // original can legitimately be forwarded more than once).
  const linkedMid = String(message?.link?.message?.mid || "").trim();
  const timestamp = String(message?.timestamp ?? "").trim();
  const publicUrl = String(message?.url || "").trim();
  if (!linkedMid || (!timestamp && !publicUrl)) return "";
  const fingerprint = JSON.stringify({
    timestamp,
    public_url: publicUrl,
    recipient_chat_id: String(message?.recipient?.chat_id ?? ""),
    recipient_user_id: String(message?.recipient?.user_id ?? ""),
    sender_user_id: String(message?.sender?.user_id ?? ""),
    link_type: String(message?.link?.type || ""),
    linked_chat_id: String(message?.link?.chat_id ?? ""),
    linked_mid: linkedMid
  });
  return `linked-${crypto.createHash("sha256").update(fingerprint).digest("hex")}`;
}

export function maxSourceIdentity(chatId, message = {}) {
  const messageIds = normalizePlatformMessageIds([maxMessageId(message)]);
  return {
    platform: "max",
    chatId: String(chatId ?? ""),
    messageIds,
    groupId: "",
    eventId: stableRelayEventId({
      platform: "max",
      chatId,
      messageIds
    })
  };
}

function responseObjects(response) {
  if (Array.isArray(response)) return response;
  if (Array.isArray(response?.result)) return response.result;
  if (Array.isArray(response?.messages)) return response.messages;
  if (response?.result && typeof response.result === "object") return [response.result];
  if (response?.message && typeof response.message === "object") return [response.message];
  return response && typeof response === "object" ? [response] : [];
}

export function extractTelegramOutboundMessageIds(response) {
  return normalizePlatformMessageIds(
    responseObjects(response).map((message) => message?.message_id)
  );
}

export function extractMaxOutboundMessageIds(response) {
  return normalizePlatformMessageIds(
    responseObjects(response).map((message) => maxMessageId(message))
  );
}

export function outboundMessageLookupKeys(platform, chatId, messageIds = []) {
  return normalizePlatformMessageIds(messageIds).map((messageId) => (
    `${String(platform)}:${String(chatId)}:${messageId}`
  ));
}
