import crypto from "node:crypto";

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function opaqueKey(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("base64url");
}

function removeOldest(entries) {
  const oldest = entries.keys().next();
  if (!oldest.done) entries.delete(oldest.value);
}

/**
 * In-memory allow-list for signed sessions. Only a SHA-256 digest of the cookie
 * is retained, so a memory dump of this registry does not expose reusable
 * session cookies. Eviction fails closed by invalidating the oldest session.
 */
export class HashedSessionRegistry {
  #entries = new Map();
  #maxEntries;
  #now;

  constructor({ maxEntries = 256, now = Date.now } = {}) {
    this.#maxEntries = positiveInteger(maxEntries, 256);
    this.#now = typeof now === "function" ? now : Date.now;
  }

  register(sessionId, expiresAt) {
    const raw = String(sessionId || "");
    const expiry = Number(expiresAt);
    if (!raw || !Number.isFinite(expiry) || expiry <= this.#now()) return false;

    const key = opaqueKey(raw);
    this.#entries.delete(key);
    while (this.#entries.size >= this.#maxEntries) removeOldest(this.#entries);
    this.#entries.set(key, expiry);
    return true;
  }

  has(sessionId, expectedExpiresAt) {
    const raw = String(sessionId || "");
    if (!raw) return false;
    const key = opaqueKey(raw);
    const expiry = this.#entries.get(key);
    if (!Number.isFinite(expiry)) return false;
    if (expiry <= this.#now()) {
      this.#entries.delete(key);
      return false;
    }
    return expectedExpiresAt === undefined || expiry === Number(expectedExpiresAt);
  }

  revoke(sessionId) {
    const raw = String(sessionId || "");
    return raw ? this.#entries.delete(opaqueKey(raw)) : false;
  }

  clear() {
    this.#entries.clear();
  }

  get size() {
    return this.#entries.size;
  }
}

/**
 * A fixed-TTL, insertion-ordered store. Expiry cleanup removes only the oldest
 * entries, making cleanup amortized O(1); the hard cap bounds memory even under
 * a distributed request flood.
 */
export class BoundedTtlStore {
  #entries = new Map();
  #maxEntries;
  #ttlMs;
  #now;

  constructor({ maxEntries = 1024, ttlMs, now = Date.now } = {}) {
    this.#maxEntries = positiveInteger(maxEntries, 1024);
    this.#ttlMs = positiveInteger(ttlMs, 5 * 60 * 1000);
    this.#now = typeof now === "function" ? now : Date.now;
  }

  #pruneExpired(now) {
    while (this.#entries.size) {
      const oldest = this.#entries.entries().next().value;
      if (!oldest || oldest[1].expiresAt > now) break;
      this.#entries.delete(oldest[0]);
    }
  }

  set(key, value) {
    const normalizedKey = String(key || "");
    if (!normalizedKey) return false;
    const now = this.#now();
    this.#pruneExpired(now);
    this.#entries.delete(normalizedKey);
    while (this.#entries.size >= this.#maxEntries) removeOldest(this.#entries);
    this.#entries.set(normalizedKey, { value, expiresAt: now + this.#ttlMs });
    return true;
  }

  take(key) {
    const normalizedKey = String(key || "");
    if (!normalizedKey) return undefined;
    const stored = this.#entries.get(normalizedKey);
    this.#entries.delete(normalizedKey);
    if (!stored || stored.expiresAt <= this.#now()) return undefined;
    return stored.value;
  }

  clear() {
    this.#entries.clear();
  }

  get size() {
    return this.#entries.size;
  }
}

/**
 * Fixed-window limiter with hashed client keys and an insertion-ordered cap.
 * Expired clients are removed from the head in amortized O(1) time.
 */
export class BoundedRateLimiter {
  #entries = new Map();
  #maxAttempts;
  #windowMs;
  #maxKeys;
  #now;

  constructor({ maxAttempts, windowMs, maxKeys = 4096, now = Date.now } = {}) {
    this.#maxAttempts = positiveInteger(maxAttempts, 20);
    this.#windowMs = positiveInteger(windowMs, 60 * 1000);
    this.#maxKeys = positiveInteger(maxKeys, 4096);
    this.#now = typeof now === "function" ? now : Date.now;
  }

  #pruneExpired(now) {
    while (this.#entries.size) {
      const oldest = this.#entries.entries().next().value;
      if (!oldest || oldest[1].resetAt > now) break;
      this.#entries.delete(oldest[0]);
    }
  }

  consume(clientKey) {
    const now = this.#now();
    this.#pruneExpired(now);
    const key = opaqueKey(clientKey);
    let state = this.#entries.get(key);

    if (!state || state.resetAt <= now) {
      if (state) this.#entries.delete(key);
      while (this.#entries.size >= this.#maxKeys) removeOldest(this.#entries);
      state = { count: 0, resetAt: now + this.#windowMs };
      this.#entries.set(key, state);
    }

    if (state.count >= this.#maxAttempts) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((state.resetAt - now) / 1000))
      };
    }

    state.count += 1;
    return { allowed: true, retryAfterSeconds: 0 };
  }

  clear() {
    this.#entries.clear();
  }

  get size() {
    return this.#entries.size;
  }
}
