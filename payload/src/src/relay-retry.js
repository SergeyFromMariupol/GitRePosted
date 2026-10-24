import crypto from "node:crypto";

function positiveInteger(value, fallback, minimum = 1) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isSafeInteger(parsed) && parsed >= minimum ? parsed : fallback;
}

export function relayRetryPolicy(values = {}) {
  const maxAttempts = positiveInteger(values.maxAttempts, 8);
  const baseDelaySeconds = positiveInteger(values.baseDelaySeconds, 10);
  const maxDelaySeconds = Math.max(
    baseDelaySeconds,
    positiveInteger(values.maxDelaySeconds, 3600)
  );
  const pollMilliseconds = positiveInteger(values.pollMilliseconds, 1000, 250);
  const albumSettleMilliseconds = positiveInteger(
    values.albumSettleMilliseconds,
    5000,
    1000
  );
  return {
    maxAttempts,
    baseDelaySeconds,
    maxDelaySeconds,
    pollMilliseconds,
    albumSettleMilliseconds
  };
}

export function relayRetryDelaySeconds(attemptNumber, policy = relayRetryPolicy()) {
  const attempt = Math.max(1, positiveInteger(attemptNumber, 1));
  const exponent = Math.min(30, attempt - 1);
  return Math.min(
    policy.maxDelaySeconds,
    policy.baseDelaySeconds * (2 ** exponent)
  );
}

export function relayRetryDisposition(attemptNumber, policy = relayRetryPolicy()) {
  return Number(attemptNumber) >= policy.maxAttempts ? "terminal" : "retry";
}

export function relayLeaseHeartbeatMilliseconds(leaseSeconds) {
  const seconds = Math.max(3, positiveInteger(leaseSeconds, 300));
  return Math.max(1000, Math.floor((seconds * 1000) / 3));
}

function relayLeaseLostError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export async function forEachRelayTargetWithLease(targets, assertOwned, deliver) {
  if (!Array.isArray(targets)
    || typeof assertOwned !== "function"
    || typeof deliver !== "function") {
    throw new TypeError("Relay target lease callbacks are required.");
  }
  for (const target of targets) {
    await assertOwned();
    await deliver(target);
  }
}

export async function withRelayLeaseHeartbeat({
  leaseSeconds,
  renewLease,
  assertLease,
  work,
  onRenewError = () => {},
  leaseLostCode = "RELAY_SOURCE_LEASE_LOST",
  leaseLostMessage = "Relay source lease was lost.",
  setIntervalImpl = setInterval,
  clearIntervalImpl = clearInterval
}) {
  if (typeof renewLease !== "function"
    || typeof assertLease !== "function"
    || typeof work !== "function") {
    throw new TypeError("Relay lease heartbeat callbacks are required.");
  }

  let heartbeatPromise = null;
  let heartbeatStopped = false;
  let leaseLost = false;
  const assertOwned = async () => {
    if (leaseLost) throw relayLeaseLostError(leaseLostCode, leaseLostMessage);
    await assertLease();
    if (leaseLost) throw relayLeaseLostError(leaseLostCode, leaseLostMessage);
  };
  const heartbeat = setIntervalImpl(() => {
    if (heartbeatPromise || leaseLost) return;
    heartbeatPromise = Promise.resolve()
      .then(renewLease)
      .then((renewed) => {
        if (!renewed) leaseLost = true;
      })
      .catch(async (error) => {
        try {
          await onRenewError(error);
        } catch {
        }
      })
      .finally(() => {
        heartbeatPromise = null;
      });
  }, relayLeaseHeartbeatMilliseconds(leaseSeconds));
  heartbeat?.unref?.();

  const stopHeartbeat = async () => {
    if (!heartbeatStopped) {
      clearIntervalImpl(heartbeat);
      heartbeatStopped = true;
    }
    const pendingHeartbeat = heartbeatPromise;
    if (pendingHeartbeat) await pendingHeartbeat;
  };

  try {
    await assertOwned();
    const result = await work(assertOwned);
    await stopHeartbeat();
    await assertOwned();
    return result;
  } finally {
    await stopHeartbeat();
  }
}

function storedMessages(value) {
  if (Array.isArray(value)) return value;
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function mergeTelegramRelayMessages(existingPayload, incomingMessage) {
  const messages = storedMessages(existingPayload).filter(Boolean);
  if (incomingMessage) messages.push(incomingMessage);
  const unique = new Map();
  for (const message of messages) {
    const messageId = String(message?.message_id ?? "").trim();
    if (messageId) unique.set(messageId, message);
  }
  return [...unique.values()].sort((left, right) => (
    String(left.message_id).localeCompare(
      String(right.message_id),
      "en",
      { numeric: true }
    )
  ));
}

export function telegramRelayJobKey(message = {}) {
  const chatId = String(message?.chat?.id ?? "").trim();
  const messageId = String(message?.message_id ?? "").trim();
  const groupId = String(message?.media_group_id ?? "").trim();
  if (!chatId || !messageId) {
    throw new TypeError("Telegram relay job needs chat and message IDs.");
  }
  return crypto.createHash("sha256").update(JSON.stringify({
    platform: "telegram",
    chat_id: chatId,
    album_id: groupId || null,
    message_id: groupId ? null : messageId
  })).digest("hex");
}

export function buildTelegramRelayEnvelope(existingPayload, incomingMessage) {
  const messages = mergeTelegramRelayMessages(existingPayload, incomingMessage);
  return {
    jobKey: telegramRelayJobKey(incomingMessage),
    chatId: String(incomingMessage?.chat?.id ?? ""),
    groupId: String(incomingMessage?.media_group_id ?? ""),
    messageIds: messages.map((message) => String(message.message_id)),
    messages
  };
}

export function telegramRelaySettleMilliseconds(message, policy = relayRetryPolicy()) {
  return message?.media_group_id ? policy.albumSettleMilliseconds : 0;
}
