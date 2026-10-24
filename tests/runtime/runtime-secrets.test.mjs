import assert from "node:assert/strict";
import test from "node:test";
import {
  runtimeSecretConfigured,
  webhookSecretConfigured
} from "../../payload/src/src/runtime-secrets.js";

test("published placeholder secrets never become runtime credentials", () => {
  for (const value of [
    "",
    "REPLACE_RANDOM_TELEGRAM_WEBHOOK_SECRET",
    "REPLACE_RANDOM_MAX_WEBHOOK_SECRET",
    "CHANGE_ME_SECRET",
    "CHANGEME",
    "EXAMPLE_SECRET",
    "TODO-secret"
  ]) {
    assert.equal(runtimeSecretConfigured(value), false, value);
    assert.equal(webhookSecretConfigured(value), false, value);
  }
});

test("webhook secrets require a non-placeholder value of practical length", () => {
  assert.equal(webhookSecretConfigured("short-secret"), false);
  assert.equal(webhookSecretConfigured("random_webhook_secret_2026"), true);
  assert.equal(webhookSecretConfigured("invalid!webhook!secret"), false);
  assert.equal(webhookSecretConfigured("x".repeat(257)), false);
  assert.equal(runtimeSecretConfigured("legacy-admin"), true);
});
