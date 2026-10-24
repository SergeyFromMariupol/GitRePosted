function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export function telegramCompatibleUrl(value) {
  if (typeof value !== "string") return null;
  const source = value.trim();
  if (!source || source.length > 2048 || /[\u0000-\u001f\u007f]/.test(source)) return null;
  try {
    const parsed = new URL(source);
    if (!["http:", "https:", "tg:"].includes(parsed.protocol)) return null;
    if (!parsed.hostname) return null;
    return parsed.href;
  } catch {
    return null;
  }
}

export function maxInlineKeyboardRowsForTelegram(value) {
  return (Array.isArray(value) ? value : [])
    .map((row) => (Array.isArray(row) ? row : [])
      .flatMap((button) => {
        if (!button || typeof button !== "object" || button.type !== "link") return [];
        const url = telegramCompatibleUrl(button.url);
        if (!url) return [];
        const text = typeof button.text === "string" && button.text.length
          ? button.text
          : "Открыть";
        return [{ text, url }];
      }))
    .filter((row) => row.length);
}

function validRange(text, from, length) {
  const offset = Number(from);
  const size = Number(length);
  return Number.isInteger(offset)
    && Number.isInteger(size)
    && offset >= 0
    && size > 0
    && offset + size <= text.length;
}

function rangesToHtml(text, ranges) {
  const markup = ranges
    .filter((range) => validRange(text, range.from, range.length) && (range.url || range.tag))
    .map((range, order) => ({
      from: Number(range.from),
      length: Number(range.length),
      order,
      open: range.url
        ? `<a href="${escapeHtml(String(range.url))}">`
        : `<${range.tag}>`,
      close: range.url ? "</a>" : `</${range.tag}>`
    }));

  if (!markup.length) return { text, format: null };

  const boundaries = [...new Set([
    0,
    text.length,
    ...markup.flatMap((range) => [range.from, range.from + range.length])
  ])].sort((left, right) => left - right);

  let html = "";
  let activeBefore = [];
  for (let index = 0; index < boundaries.length - 1; index += 1) {
    const from = boundaries[index];
    const to = boundaries[index + 1];
    const activeNow = markup
      .filter((range) => range.from <= from && range.from + range.length >= to)
      .sort((left, right) => (
        left.from - right.from
        || (right.from + right.length) - (left.from + left.length)
        || left.order - right.order
      ));
    let sharedPrefix = 0;
    while (
      sharedPrefix < activeBefore.length
      && sharedPrefix < activeNow.length
      && activeBefore[sharedPrefix] === activeNow[sharedPrefix]
    ) {
      sharedPrefix += 1;
    }
    for (let closeIndex = activeBefore.length - 1; closeIndex >= sharedPrefix; closeIndex -= 1) {
      html += activeBefore[closeIndex].close;
    }
    for (let openIndex = sharedPrefix; openIndex < activeNow.length; openIndex += 1) {
      html += activeNow[openIndex].open;
    }
    html += escapeHtml(text.slice(from, to));
    activeBefore = activeNow;
  }
  for (let index = activeBefore.length - 1; index >= 0; index -= 1) {
    html += activeBefore[index].close;
  }
  return { text: html, format: "html" };
}

export function telegramMessageTextForMax(message = {}) {
  const hasText = typeof message.text === "string";
  const text = hasText
    ? message.text
    : typeof message.caption === "string"
      ? message.caption
      : "";
  const entities = hasText ? message.entities : message.caption_entities;
  const tagByType = {
    bold: "b",
    italic: "i",
    underline: "u",
    strikethrough: "s",
    code: "code",
    pre: "pre"
  };
  const ranges = (Array.isArray(entities) ? entities : []).flatMap((entity) => {
    if (!entity || !validRange(text, entity.offset, entity.length)) return [];
    if (entity.type === "text_link" && entity.url) {
      return [{ from: entity.offset, length: entity.length, url: entity.url }];
    }
    if (entity.type === "url") {
      return [{
        from: entity.offset,
        length: entity.length,
        url: text.slice(entity.offset, entity.offset + entity.length)
      }];
    }
    const tag = tagByType[entity.type];
    if (tag) return [{ from: entity.offset, length: entity.length, tag }];
    return [];
  });
  return rangesToHtml(text, ranges);
}

function maxMessageText(message = {}) {
  if (typeof message?.body?.text === "string") return message.body.text;
  if (typeof message?.body === "string") return message.body;
  if (typeof message?.text === "string") return message.text;
  return "";
}

function maxMarkup(message = {}) {
  return Array.isArray(message?.body?.markup)
    ? message.body.markup
    : Array.isArray(message?.markup)
      ? message.markup
      : [];
}

function maxUserIdLink(item) {
  const userId = String(item?.user_id ?? "").trim();
  return /^\d+$/.test(userId) ? `max://user/${userId}` : null;
}

function maxPublicUserLink(item) {
  const value = String(item?.user_link || "").trim();
  if (!value) return null;
  if (/^https:\/\/max\.ru\/[\p{L}\p{N}._-]+\/?$/iu.test(value)) {
    return value.replace(/\/$/, "");
  }
  const username = value.replace(/^@/, "");
  return /^[\p{L}\p{N}._-]+$/u.test(username)
    ? `https://max.ru/${encodeURIComponent(username)}`
    : null;
}

export function maxMessageTextForMax(message = {}) {
  const text = maxMessageText(message);
  const tagByType = {
    strong: "b",
    emphasized: "i",
    underline: "u",
    strikethrough: "s",
    monospaced: "code",
    heading: "h1",
    highlighted: "mark"
  };
  const ranges = maxMarkup(message).flatMap((item) => {
    if (item?.type === "link" && item?.url) {
      return [{ from: item.from, length: item.length, url: item.url }];
    }
    if (item?.type === "user_mention") {
      const url = maxUserIdLink(item) || maxPublicUserLink(item);
      return url ? [{ from: item.from, length: item.length, url }] : [];
    }
    const tag = tagByType[item?.type];
    return tag ? [{ from: item.from, length: item.length, tag }] : [];
  });
  return rangesToHtml(text, ranges);
}

export function maxMessageEntitiesForTelegram(message = {}) {
  const text = maxMessageText(message);
  const typeMap = {
    link: "text_link",
    strong: "bold",
    emphasized: "italic",
    underline: "underline",
    strikethrough: "strikethrough",
    monospaced: "code",
    heading: "bold",
    highlighted: "underline",
    quote: "blockquote"
  };
  return maxMarkup(message).flatMap((item) => {
    if (item?.type === "user_mention") {
      const url = telegramCompatibleUrl(maxPublicUserLink(item));
      if (!url || !validRange(text, item.from, item.length)) return [];
      return [{
        type: "text_link",
        offset: Number(item.from),
        length: Number(item.length),
        url
      }];
    }
    const type = typeMap[item?.type];
    if (!type || !validRange(text, item.from, item.length)) return [];
    const entity = {
      type,
      offset: Number(item.from),
      length: Number(item.length)
    };
    if (type === "text_link") {
      const url = telegramCompatibleUrl(item.url);
      if (!url) return [];
      entity.url = url;
    }
    return [entity];
  });
}
