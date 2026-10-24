import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  extractMaxOutboundMessageIds,
  extractTelegramOutboundMessageIds,
  maxMessageId,
  maxSourceIdentity,
  outboundMessageLookupKeys,
  outboundOperationDisposition,
  stableOutboundOperationId,
  telegramSourceIdentity
} from "../../payload/src/src/relay-idempotency.js";

function telegramMessage(messageId, text = "", mediaGroupId = "") {
  return {
    message_id: messageId,
    text,
    chat: { id: -100123 },
    ...(mediaGroupId ? { media_group_id: mediaGroupId } : {})
  };
}

test("identical text in different Telegram message IDs is accepted as two events", () => {
  const first = telegramSourceIdentity([telegramMessage(101, "Одинаковый текст")]);
  const second = telegramSourceIdentity([telegramMessage(102, "Одинаковый текст")]);
  const duplicate = telegramSourceIdentity([telegramMessage(101, "Одинаковый текст")]);

  assert.notEqual(first.eventId, second.eventId);
  assert.equal(first.eventId, duplicate.eventId);
  assert.deepEqual(first.messageIds, ["101"]);
  assert.deepEqual(second.messageIds, ["102"]);
});

test("MAX source identity depends on body.mid rather than text or attachments", () => {
  const first = maxSourceIdentity("-7743", {
    body: { mid: "mid-one", text: "", attachments: [{ type: "image" }] }
  });
  const second = maxSourceIdentity("-7743", {
    body: { mid: "mid-two", text: "", attachments: [{ type: "image" }] }
  });
  assert.notEqual(first.eventId, second.eventId);
  assert.deepEqual(first.messageIds, ["mid-one"]);
});

test("forward-only MAX posts receive a stable outer identity", () => {
  const forwarded = {
    timestamp: 1789000000123,
    recipient: { chat_id: -7743, chat_type: "channel" },
    url: "https://max.ru/channel/post-one",
    body: null,
    link: {
      type: "forward",
      chat_id: -100,
      message: { mid: "original-mid", text: "Исходный пост", attachments: [] }
    }
  };
  const firstId = maxMessageId(forwarded);
  assert.match(firstId, /^linked-[a-f0-9]{64}$/);
  assert.equal(maxMessageId(structuredClone(forwarded)), firstId);
  assert.deepEqual(maxSourceIdentity("-7743", forwarded).messageIds, [firstId]);

  const secondForward = {
    ...forwarded,
    timestamp: forwarded.timestamp + 1,
    url: "https://max.ru/channel/post-two"
  };
  assert.notEqual(maxMessageId(secondForward), firstId);
  assert.notEqual(
    maxSourceIdentity("-7743", secondForward).eventId,
    maxSourceIdentity("-7743", forwarded).eventId
  );
});

test("link-only MAX send responses can be recorded and matched to their webhook", () => {
  const message = {
    timestamp: 1789000000456,
    recipient: { chat_id: -9900 },
    body: null,
    link: { type: "forward", message: { mid: "source-mid", text: "Пост" } }
  };
  const recorded = extractMaxOutboundMessageIds({ message });
  const incoming = maxSourceIdentity("-9900", message).messageIds;
  assert.deepEqual(recorded, incoming);
  assert.deepEqual(outboundMessageLookupKeys("max", "-9900", recorded), [
    `max:-9900:${recorded[0]}`
  ]);
});

test("media-only reciprocal webhook matches the recorded outbound message key", () => {
  const recorded = outboundMessageLookupKeys("max", "-7743", ["max-created-mid"]);
  const incoming = outboundMessageLookupKeys("max", "-7743", ["max-created-mid"]);
  assert.deepEqual(incoming, recorded);
});

test("album identity and Telegram response IDs are stable and complete", () => {
  const firstOrder = telegramSourceIdentity([
    telegramMessage(33, "", "album-9"),
    telegramMessage(31, "", "album-9"),
    telegramMessage(32, "", "album-9")
  ]);
  const replayOrder = telegramSourceIdentity([
    telegramMessage(32, "", "album-9"),
    telegramMessage(33, "", "album-9"),
    telegramMessage(31, "", "album-9")
  ]);
  assert.equal(firstOrder.eventId, replayOrder.eventId);
  assert.deepEqual(firstOrder.messageIds, ["31", "32", "33"]);
  assert.deepEqual(
    extractTelegramOutboundMessageIds([
      { message_id: 901 },
      { message_id: 902 },
      { message_id: 903 }
    ]),
    ["901", "902", "903"]
  );
});

test("MAX POST /messages response shapes yield body.mid", () => {
  assert.deepEqual(
    extractMaxOutboundMessageIds({ message: { body: { mid: "wrapped-mid" } } }),
    ["wrapped-mid"]
  );
  assert.deepEqual(
    extractMaxOutboundMessageIds({ body: { mid: "direct-mid" } }),
    ["direct-mid"]
  );
  assert.deepEqual(
    extractMaxOutboundMessageIds({ messages: [
      { body: { mid: "one" } },
      { body: { mid: "two" } }
    ] }),
    ["one", "two"]
  );
});

test("partial multi-target retry skips completed A and resumes failed B once", () => {
  const source = {
    platform: "telegram",
    chatId: "-100123",
    eventId: "a".repeat(64)
  };
  const targets = [
    { platform: "max", chatId: "-1" },
    { platform: "max", chatId: "-2" }
  ];
  const states = new Map();
  const sends = new Map(targets.map((target) => [target.chatId, 0]));
  const operationId = (target) => stableOutboundOperationId({
    sourcePlatform: source.platform,
    sourceChatId: source.chatId,
    sourceEventId: source.eventId,
    targetPlatform: target.platform,
    targetChatId: target.chatId
  });
  const runTarget = (target, shouldFail = false) => {
    const id = operationId(target);
    const disposition = outboundOperationDisposition(states.get(id), false);
    if (disposition === "skip") return;
    sends.set(target.chatId, sends.get(target.chatId) + 1);
    states.set(id, shouldFail ? "failed" : "completed");
  };

  runTarget(targets[0]);
  runTarget(targets[1], true);
  runTarget(targets[0]);
  runTarget(targets[1]);

  assert.equal(sends.get("-1"), 1);
  assert.equal(sends.get("-2"), 2);
  assert.equal(states.get(operationId(targets[0])), "completed");
  assert.equal(states.get(operationId(targets[1])), "completed");
  assert.equal(outboundOperationDisposition("pending", true), "wait");
});

test("whole outbound operation ID stays backward-compatible", () => {
  const identity = {
    sourcePlatform: "telegram",
    sourceChatId: "-100123",
    sourceEventId: "b".repeat(64),
    targetPlatform: "max",
    targetChatId: "-7743"
  };
  const legacyId = crypto.createHash("sha256").update(JSON.stringify([
    identity.sourcePlatform,
    identity.sourceChatId,
    identity.sourceEventId,
    identity.targetPlatform,
    identity.targetChatId
  ])).digest("hex");

  assert.equal(stableOutboundOperationId(identity), legacyId);
  assert.equal(stableOutboundOperationId({ ...identity, operationKey: "whole" }), legacyId);
});

test("outbound operation keys produce distinct stable IDs", () => {
  const identity = {
    sourcePlatform: "max",
    sourceChatId: "-7743",
    sourceEventId: "c".repeat(64),
    targetPlatform: "telegram",
    targetChatId: "-100123"
  };
  const mediaId = stableOutboundOperationId({ ...identity, operationKey: "media:0:image" });
  const textId = stableOutboundOperationId({ ...identity, operationKey: "text" });

  assert.equal(
    mediaId,
    stableOutboundOperationId({ ...identity, operationKey: "media:0:image" })
  );
  assert.notEqual(mediaId, textId);
  assert.notEqual(mediaId, stableOutboundOperationId(identity));
});
