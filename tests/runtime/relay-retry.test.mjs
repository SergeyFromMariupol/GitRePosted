import assert from "node:assert/strict";
import test from "node:test";
import {
  stableOutboundOperationId,
  telegramSourceIdentity
} from "../../payload/src/src/relay-idempotency.js";
import {
  buildTelegramRelayEnvelope,
  forEachRelayTargetWithLease,
  relayLeaseHeartbeatMilliseconds,
  relayRetryDelaySeconds,
  relayRetryDisposition,
  relayRetryPolicy,
  telegramRelayJobKey,
  withRelayLeaseHeartbeat
} from "../../payload/src/src/relay-retry.js";

function albumMessage(messageId) {
  return {
    message_id: messageId,
    media_group_id: "album-eight",
    chat: { id: -100777 },
    photo: [{ file_id: `file-${messageId}` }]
  };
}

test("eight Telegram album items merge into one durable job before final identity", () => {
  const jobs = new Map();
  for (const message of Array.from({ length: 8 }, (_, index) => albumMessage(101 + index))) {
    const jobKey = telegramRelayJobKey(message);
    const envelope = buildTelegramRelayEnvelope(jobs.get(jobKey)?.messages, message);
    jobs.set(jobKey, envelope);
  }

  assert.equal(jobs.size, 1);
  const [jobKey, envelope] = [...jobs.entries()][0];
  const payload = envelope.messages;
  assert.equal(payload.length, 8);
  assert.deepEqual(
    envelope.messageIds,
    ["101", "102", "103", "104", "105", "106", "107", "108"]
  );
  assert.deepEqual(
    payload.map((message) => message.message_id),
    [101, 102, 103, 104, 105, 106, 107, 108]
  );
  assert.equal(telegramRelayJobKey(albumMessage(999)), jobKey);

  const finalIdentity = telegramSourceIdentity(payload);
  const replayIdentity = telegramSourceIdentity([...payload].reverse());
  assert.equal(finalIdentity.eventId, replayIdentity.eventId);
  assert.notEqual(
    finalIdentity.eventId,
    telegramSourceIdentity([payload[0]]).eventId
  );
  assert.deepEqual(
    finalIdentity.messageIds,
    ["101", "102", "103", "104", "105", "106", "107", "108"]
  );
  const operation = (identity) => stableOutboundOperationId({
    sourcePlatform: identity.platform,
    sourceChatId: identity.chatId,
    sourceEventId: identity.eventId,
    targetPlatform: "max",
    targetChatId: "-900"
  });
  assert.equal(operation(finalIdentity), operation(replayIdentity));
});

test("retry backoff is capped and the configured last attempt is terminal", () => {
  const policy = relayRetryPolicy({
    maxAttempts: 4,
    baseDelaySeconds: 10,
    maxDelaySeconds: 25,
    pollMilliseconds: 1000,
    albumSettleMilliseconds: 5000
  });
  assert.deepEqual(
    [1, 2, 3].map((attempt) => relayRetryDelaySeconds(attempt, policy)),
    [10, 20, 25]
  );
  assert.equal(relayRetryDisposition(3, policy), "retry");
  assert.equal(relayRetryDisposition(4, policy), "terminal");
});

test("MAX 323 MB transfer renews its source lease and asserts ownership per target", async () => {
  let heartbeatCallback;
  let heartbeatDelay;
  let cleared = false;
  let renewals = 0;
  let ownershipChecks = 0;
  const timer = { unref() {} };

  await withRelayLeaseHeartbeat({
    leaseSeconds: 300,
    renewLease: async () => {
      renewals += 1;
      return true;
    },
    assertLease: async () => {
      ownershipChecks += 1;
    },
    setIntervalImpl(callback, delay) {
      heartbeatCallback = callback;
      heartbeatDelay = delay;
      return timer;
    },
    clearIntervalImpl(value) {
      assert.strictEqual(value, timer);
      cleared = true;
    },
    work: async (assertOwned) => {
      await forEachRelayTargetWithLease(["telegram-a", "telegram-b"], assertOwned, async (target) => {
        assert.match(target, /^telegram-/);
        if (target === "telegram-a") {
          heartbeatCallback();
          await new Promise((resolve) => setImmediate(resolve));
        }
      });
    }
  });

  assert.equal(heartbeatDelay, relayLeaseHeartbeatMilliseconds(300));
  assert.equal(heartbeatDelay, 100_000);
  assert.equal(renewals, 1);
  assert.equal(ownershipChecks, 4);
  assert.equal(cleared, true);
});

test("lost MAX source lease fences the next target", async () => {
  let heartbeatCallback;
  const delivered = [];
  await assert.rejects(
    withRelayLeaseHeartbeat({
      leaseSeconds: 30,
      renewLease: async () => false,
      assertLease: async () => {},
      setIntervalImpl(callback) {
        heartbeatCallback = callback;
        return { unref() {} };
      },
      clearIntervalImpl() {},
      work: async (assertOwned) => {
        await forEachRelayTargetWithLease(
          ["telegram-a", "telegram-b"],
          assertOwned,
          async (target) => {
            delivered.push(target);
            if (target === "telegram-a") {
              heartbeatCallback();
              await new Promise((resolve) => setImmediate(resolve));
            }
          }
        );
      }
    }),
    { code: "RELAY_SOURCE_LEASE_LOST" }
  );
  assert.deepEqual(delivered, ["telegram-a"]);
});

test("lost outbound operation lease uses the target fencing error", async () => {
  let heartbeatCallback;
  await assert.rejects(
    withRelayLeaseHeartbeat({
      leaseSeconds: 300,
      renewLease: async () => false,
      assertLease: async () => {},
      leaseLostCode: "OUTBOUND_OPERATION_LEASE_LOST",
      leaseLostMessage: "Outbound relay operation lease was lost.",
      setIntervalImpl(callback) {
        heartbeatCallback = callback;
        return { unref() {} };
      },
      clearIntervalImpl() {},
      work: async () => {
        heartbeatCallback();
        await new Promise((resolve) => setImmediate(resolve));
      }
    }),
    {
      code: "OUTBOUND_OPERATION_LEASE_LOST",
      message: "Outbound relay operation lease was lost."
    }
  );
});
