import assert from "node:assert/strict";
import test from "node:test";
import { isLoopbackIp, normalizeNetworkIp, requestIp } from "../../payload/src/src/request-ip.js";

test("request IP trusts forwarded headers only behind a loopback proxy", () => {
  assert.equal(requestIp({
    socket: { remoteAddress: "203.0.113.9" },
    headers: { "x-forwarded-for": "198.51.100.10" }
  }), "203.0.113.9");

  assert.equal(requestIp({
    socket: { remoteAddress: "127.0.0.1" },
    headers: { "x-forwarded-for": "198.51.100.10, 203.0.113.9" }
  }), "203.0.113.9");

  assert.equal(requestIp({
    socket: { remoteAddress: "::1" },
    headers: { "x-forwarded-for": "spoofed", "x-real-ip": "203.0.113.11" }
  }), "203.0.113.11");
});

test("request IP normalizes mapped IPv4 loopback and rejects malformed values", () => {
  assert.equal(normalizeNetworkIp("::ffff:127.0.0.1"), "127.0.0.1");
  assert.equal(isLoopbackIp("127.42.0.7"), true);
  assert.equal(isLoopbackIp("::1"), true);
  assert.equal(normalizeNetworkIp("203.0.113.1, spoofed"), "");
  assert.equal(requestIp({
    socket: { remoteAddress: "::ffff:127.0.0.1" },
    headers: { "x-forwarded-for": "198.51.100.7, invalid" }
  }), "127.0.0.1");
});
