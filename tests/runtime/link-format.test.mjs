import assert from "node:assert/strict";
import test from "node:test";
import {
  maxInlineKeyboardRowsForTelegram,
  maxMessageEntitiesForTelegram,
  maxMessageTextForMax,
  telegramCompatibleUrl,
  telegramMessageTextForMax
} from "../../payload/src/src/link-format.js";

test("MAX links are limited to URL schemes accepted by Telegram", () => {
  assert.equal(telegramCompatibleUrl("https://example.org/path?q=1"), "https://example.org/path?q=1");
  assert.equal(telegramCompatibleUrl("tg://resolve?domain=example_bot"), "tg://resolve?domain=example_bot");
  for (const url of ["max://user/42", "javascript:alert(1)", "https://", "not a url", "https://example.org/\nnext"]) {
    assert.equal(telegramCompatibleUrl(url), null);
  }
});

test("malformed MAX keyboard rows are ignored without leaking unsupported links", () => {
  const rows = maxInlineKeyboardRowsForTelegram([
    [
      { type: "link", text: "Сайт", url: "https://example.org/path" },
      { type: "link", text: "MAX", url: "max://user/42" },
      { type: "callback", text: "Чужой callback", payload: "unsafe" }
    ],
    null,
    "not-a-row",
    [{ type: "link", text: "Telegram", url: "tg://resolve?domain=example_bot" }],
    [{ type: "link", text: "Сломано", url: "https://" }],
    [null]
  ]);

  assert.deepEqual(rows, [
    [{ text: "Сайт", url: "https://example.org/path" }],
    [{ text: "Telegram", url: "tg://resolve?domain=example_bot" }]
  ]);
});

test("unsupported MAX markup links degrade to plain Telegram text", () => {
  const text = "Сайт MAX TG";
  assert.deepEqual(maxMessageEntitiesForTelegram({
    body: {
      text,
      markup: [
        { type: "link", from: 0, length: 4, url: "https://example.org" },
        { type: "link", from: 5, length: 3, url: "max://user/42" },
        { type: "link", from: 9, length: 2, url: "tg://resolve?domain=example_bot" },
        null
      ]
    }
  }), [
    { type: "text_link", offset: 0, length: 4, url: "https://example.org/" },
    { type: "text_link", offset: 9, length: 2, url: "tg://resolve?domain=example_bot" }
  ]);
});

test("Telegram hidden link survives conversion to MAX HTML after an emoji", () => {
  const text = "😀 Скрытая ссылка";
  const actual = telegramMessageTextForMax({
    text,
    entities: [{
      type: "text_link",
      offset: 3,
      length: 14,
      url: "https://example.org/path?a=1&b=2"
    }]
  });

  assert.deepEqual(actual, {
    text: "😀 <a href=\"https://example.org/path?a=1&amp;b=2\">Скрытая ссылка</a>",
    format: "html"
  });
});

test("MAX hidden link survives conversion to Telegram entities after an emoji", () => {
  const message = {
    body: {
      text: "😀 Скрытая ссылка",
      markup: [{
        type: "link",
        from: 3,
        length: 14,
        url: "https://example.org/hidden"
      }]
    }
  };

  assert.deepEqual(maxMessageEntitiesForTelegram(message), [{
    type: "text_link",
    offset: 3,
    length: 14,
    url: "https://example.org/hidden"
  }]);
  assert.deepEqual(maxMessageTextForMax(message), {
    text: "😀 <a href=\"https://example.org/hidden\">Скрытая ссылка</a>",
    format: "html"
  });
});

test("Telegram URL entity remains clickable in MAX", () => {
  const text = "Сайт: https://example.org";
  const actual = telegramMessageTextForMax({
    caption: text,
    caption_entities: [{
      type: "url",
      offset: 6,
      length: 19
    }]
  });

  assert.deepEqual(actual, {
    text: "Сайт: <a href=\"https://example.org\">https://example.org</a>",
    format: "html"
  });
});

test("Telegram blockquote text degrades safely when MAX has no outgoing quote tag", () => {
  const text = "До цитаты\nЖдём вас в гости\nПосле цитаты";
  const quote = "Ждём вас в гости";
  const actual = telegramMessageTextForMax({
    text,
    entities: [{ type: "blockquote", offset: text.indexOf(quote), length: quote.length }]
  });
  assert.equal(actual.text, text);
  assert.equal(actual.format, null);
});

test("Telegram expandable blockquote keeps its link while quote styling degrades safely", () => {
  const text = "Ждём вас: example.com";
  const actual = telegramMessageTextForMax({
    text,
    entities: [
      { type: "expandable_blockquote", offset: 0, length: text.length },
      { type: "url", offset: 10, length: 11 }
    ]
  });
  assert.equal(
    actual.text,
    'Ждём вас: <a href="example.com">example.com</a>'
  );
  assert.equal(actual.format, "html");
});

test("Telegram formatting supported by MAX is preserved", () => {
  const text = "Жирный курсив подчёркнут зачёркнут код";
  const actual = telegramMessageTextForMax({
    text,
    entities: [
      { type: "bold", offset: 0, length: 6 },
      { type: "italic", offset: 7, length: 6 },
      { type: "underline", offset: 14, length: 10 },
      { type: "strikethrough", offset: 25, length: 9 },
      { type: "code", offset: 35, length: 3 }
    ]
  });
  assert.equal(
    actual.text,
    "<b>Жирный</b> <i>курсив</i> <u>подчёркнут</u> <s>зачёркнут</s> <code>код</code>"
  );
  assert.equal(actual.format, "html");
});

test("MAX formatting stays intact on a MAX to MAX route", () => {
  const text = "Жирный курсив подчёркнут зачёркнут код";
  const actual = maxMessageTextForMax({
    body: {
      text,
      markup: [
        { type: "strong", from: 0, length: 6 },
        { type: "emphasized", from: 7, length: 6 },
        { type: "underline", from: 14, length: 10 },
        { type: "strikethrough", from: 25, length: 9 },
        { type: "monospaced", from: 35, length: 3 }
      ]
    }
  });
  assert.deepEqual(actual, {
    text: "<b>Жирный</b> <i>курсив</i> <u>подчёркнут</u> <s>зачёркнут</s> <code>код</code>",
    format: "html"
  });
});

test("MAX heading, highlight and mentions survive while quote text stays readable", () => {
  const text = "Заголовок Метка Цитата Иван Пётр";
  const range = (value) => ({ from: text.indexOf(value), length: value.length });
  const actual = maxMessageTextForMax({
    body: {
      text,
      markup: [
        { type: "heading", ...range("Заголовок") },
        { type: "highlighted", ...range("Метка") },
        { type: "quote", ...range("Цитата") },
        { type: "user_mention", ...range("Иван"), user_id: 42 },
        { type: "user_mention", ...range("Пётр"), user_link: "@petr" }
      ]
    }
  });

  assert.deepEqual(actual, {
    text: '<h1>Заголовок</h1> <mark>Метка</mark> Цитата <a href="max://user/42">Иван</a> <a href="https://max.ru/petr">Пётр</a>',
    format: "html"
  });
});

test("MAX-only formatting degrades safely to Telegram entities", () => {
  const text = "Заголовок Метка Цитата Иван Пётр";
  const range = (value) => ({ from: text.indexOf(value), length: value.length });
  const entities = maxMessageEntitiesForTelegram({
    body: {
      text,
      markup: [
        { type: "heading", ...range("Заголовок") },
        { type: "highlighted", ...range("Метка") },
        { type: "quote", ...range("Цитата") },
        { type: "user_mention", ...range("Иван"), user_id: 42 },
        { type: "user_mention", ...range("Пётр"), user_link: "@petr" }
      ]
    }
  });

  assert.deepEqual(entities, [
    { type: "bold", ...range("Заголовок"), offset: range("Заголовок").from },
    { type: "underline", ...range("Метка"), offset: range("Метка").from },
    { type: "blockquote", ...range("Цитата"), offset: range("Цитата").from },
    {
      type: "text_link",
      offset: range("Пётр").from,
      length: range("Пётр").length,
      url: "https://max.ru/petr"
    }
  ].map(({ from, ...entity }) => entity));
});

test("overlapping Telegram styles produce correctly nested MAX HTML", () => {
  const actual = telegramMessageTextForMax({
    text: "важно",
    entities: [
      { type: "bold", offset: 0, length: 5 },
      { type: "italic", offset: 0, length: 5 }
    ]
  });
  assert.equal(actual.text, "<b><i>важно</i></b>");
});

test("crossing Telegram entity ranges never produce malformed MAX HTML", () => {
  const actual = telegramMessageTextForMax({
    text: "abcdef",
    entities: [
      { type: "bold", offset: 0, length: 4 },
      { type: "italic", offset: 2, length: 4 }
    ]
  });
  assert.equal(actual.text, "<b>ab<i>cd</i></b><i>ef</i>");
  assert.equal(actual.format, "html");
});
