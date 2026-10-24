import assert from "node:assert/strict";
import test from "node:test";

import {
  bridgeSummaryText,
  maxCallbackButton
} from "../../payload/src/src/bot-ui.js";

test("MAX callback button bounds a 200-character title and rejects unsafe payloads", () => {
  const button = maxCallbackButton("Я".repeat(200), "max:pick:42");

  assert.equal(button.type, "callback");
  assert.equal(Array.from(button.text).length, 128);
  assert.equal(button.text.length, 128);
  assert.match(button.text, /…$/u);
  assert.equal(button.payload, "max:pick:42");

  assert.deepEqual(maxCallbackButton("\u0000\n", "max:bad\u0000payload"), {
    type: "callback",
    text: "Действие",
    payload: "max:noop"
  });
  assert.equal(maxCallbackButton("Кнопка", "x".repeat(1025)).payload, "max:noop");
});

test("bridge summaries stay within Telegram and MAX limits on the worst-case page", () => {
  const longTitle = `<&>\n${"Очень длинное название 🚀 ".repeat(100)}`;
  const rows = Array.from({ length: 25 }, (_, index) => ({
    _index: index + 1,
    source_platform: index % 2 ? "max" : "telegram",
    source_chat_id: `source-${index + 1}`,
    source_title: longTitle,
    targets: Array.from({ length: 75 }, (_, targetIndex) => ({
      platform: targetIndex % 2 ? "telegram" : "max",
      chat_id: `target-${index + 1}-${targetIndex + 1}`,
      title: `${longTitle}-${targetIndex + 1}`
    }))
  }));

  const telegramText = bridgeSummaryText(rows, 4096);
  const maxText = bridgeSummaryText(rows, 4000);

  assert.ok(telegramText.length <= 4096);
  assert.ok(Array.from(telegramText).length <= 4096);
  assert.ok(maxText.length <= 4000);
  assert.ok(Array.from(maxText).length <= 4000);
  assert.equal(telegramText.split("\n").length, 25);
  assert.equal(maxText.split("\n").length, 25);
  for (let index = 1; index <= 25; index += 1) {
    assert.match(telegramText, new RegExp(`(?:^|\\n)${index}\\.`));
    assert.match(maxText, new RegExp(`(?:^|\\n)${index}\\.`));
  }
  assert.match(telegramText, /75 получ\./u);
  assert.match(maxText, /\+73/u);
  assert.doesNotMatch(telegramText, /<tg-emoji/u);
});
