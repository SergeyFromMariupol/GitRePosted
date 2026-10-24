import assert from "node:assert/strict";
import test from "node:test";

import {
  BoundedRateLimiter,
  BoundedTtlStore,
  HashedSessionRegistry
} from "../../payload/src/src/security-state.js";

test("admin session registry revokes copied cookies and never exposes raw cookie values", () => {
  let now = 1_000;
  const sessions = new HashedSessionRegistry({ maxEntries: 2, now: () => now });
  const stolenCookie = "2000.random.signature";

  assert.equal(sessions.register(stolenCookie, 2_000), true);
  assert.equal(sessions.has(stolenCookie, 2_000), true);
  assert.equal(sessions.has(stolenCookie, 2_001), false);
  assert.equal(JSON.stringify(sessions).includes(stolenCookie), false);

  assert.equal(sessions.revoke(stolenCookie), true);
  assert.equal(sessions.has(stolenCookie, 2_000), false);

  sessions.register("session-b", 3_000);
  sessions.register("session-c", 3_000);
  sessions.register("session-d", 3_000);
  assert.equal(sessions.size, 2);
  assert.equal(sessions.has("session-b", 3_000), false);
  assert.equal(sessions.has("session-c", 3_000), true);
  assert.equal(sessions.has("session-d", 3_000), true);

  now = 3_000;
  assert.equal(sessions.has("session-c", 3_000), false);
});

test("passkey challenge store is single-use, expiring, and hard-capped", () => {
  let now = 0;
  const challenges = new BoundedTtlStore({
    maxEntries: 2,
    ttlMs: 100,
    now: () => now
  });

  challenges.set("challenge-a", { type: "authenticate" });
  challenges.set("challenge-b", { type: "authenticate" });
  challenges.set("challenge-c", { type: "authenticate" });
  assert.equal(challenges.size, 2);
  assert.equal(challenges.take("challenge-a"), undefined);
  assert.deepEqual(challenges.take("challenge-b"), { type: "authenticate" });
  assert.equal(challenges.take("challenge-b"), undefined);

  now = 101;
  assert.equal(challenges.take("challenge-c"), undefined);
  challenges.set("challenge-d", { type: "register" });
  assert.deepEqual(challenges.take("challenge-d"), { type: "register" });
});

test("passkey authentication limiter is per-client, expiring, and hard-capped", () => {
  let now = 0;
  const limiter = new BoundedRateLimiter({
    maxAttempts: 2,
    windowMs: 1_000,
    maxKeys: 2,
    now: () => now
  });

  assert.deepEqual(limiter.consume("192.0.2.1"), { allowed: true, retryAfterSeconds: 0 });
  assert.deepEqual(limiter.consume("192.0.2.1"), { allowed: true, retryAfterSeconds: 0 });
  assert.deepEqual(limiter.consume("192.0.2.1"), { allowed: false, retryAfterSeconds: 1 });
  assert.equal(limiter.consume("192.0.2.2").allowed, true);
  assert.equal(limiter.consume("192.0.2.3").allowed, true);
  assert.equal(limiter.size, 2);

  now = 1_001;
  assert.equal(limiter.consume("192.0.2.2").allowed, true);
  assert.equal(limiter.size <= 2, true);
});
