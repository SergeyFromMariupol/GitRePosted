import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  appendMaxShareUrls,
  combineTelegramPayloadParts,
  extractMaxUploadToken,
  MAX_INLINE_KEYBOARD_ROWS,
  MAX_LINK_URL_LIMIT,
  MAX_MESSAGE_TEXT_LIMIT,
  MAX_VIDEO_UPLOAD_LIMIT_BYTES,
  MAX_VISUAL_ATTACHMENTS_PER_MESSAGE,
  maxAttachmentRequests,
  maxRelayContentMessages,
  maxSpecialAttachmentForTelegram,
  maxTelegramTextParts,
  readTelegramLocalFileBytes,
  resolveTelegramLocalFilePath,
  splitMaxPayload,
  telegramInlineKeyboardForMax,
  telegramKindForMaxAttachment,
  telegramSpecialAttachmentsForMax,
  telegramDocumentUploadDescriptor,
  telegramMessageIdentity,
  uploadMaxAttachmentWithFallbacks
} from "../../payload/src/src/relay-media.js";

test("four Telegram link buttons become two MAX rows without reordering", () => {
  const urls = Array.from({ length: 4 }, (_, index) => `https://example.test/${index + 1}`);
  const converted = telegramInlineKeyboardForMax({
    inline_keyboard: [[
      { text: "Один", url: urls[0] },
      { text: "Два", url: urls[1] },
      { text: "Три", url: urls[2] },
      { text: "Четыре", url: urls[3] }
    ]]
  });

  assert.deepEqual(
    converted.attachments[0].payload.buttons.map((row) => row.map((button) => button.url)),
    [urls.slice(0, 3), urls.slice(3)]
  );
  assert.deepEqual(converted.supplements, []);
});

test("Telegram link keyboard is bounded to 30 MAX rows and preserves overflow as text", () => {
  const urls = Array.from({ length: MAX_INLINE_KEYBOARD_ROWS + 2 }, (_, index) => (
    `https://example.test/row-${index + 1}`
  ));
  const converted = telegramInlineKeyboardForMax({
    inline_keyboard: urls.map((url, index) => [{ text: `Кнопка ${index + 1}`, url }])
  });
  const rows = converted.attachments[0].payload.buttons;

  assert.equal(rows.length, MAX_INLINE_KEYBOARD_ROWS);
  assert.deepEqual(rows.flat().map((button) => button.url), urls.slice(0, MAX_INLINE_KEYBOARD_ROWS));
  assert.equal(converted.supplements.length, 2);
  assert.match(converted.supplements[0], new RegExp(urls[MAX_INLINE_KEYBOARD_ROWS]));
  assert.match(converted.supplements[1], new RegExp(urls[MAX_INLINE_KEYBOARD_ROWS + 1]));

  const payloads = splitMaxPayload(combineTelegramPayloadParts([{
    text: "Пост",
    plainText: "Пост",
    format: null,
    attachments: converted.attachments,
    supplements: converted.supplements
  }]));
  assert.ok(payloads.every((payload) => payload.text.length <= MAX_MESSAGE_TEXT_LIMIT));
  assert.match(payloads.map((payload) => payload.text).join(""), new RegExp(urls.at(-1)));
  assert.equal(
    payloads.flatMap((payload) => payload.attachments)
      .find((attachment) => attachment.type === "inline_keyboard")
      .payload.buttons.length,
    MAX_INLINE_KEYBOARD_ROWS
  );
});

test("long and unsupported Telegram button URLs fall back to HTML-safe MAX supplements", () => {
  const baseUrl = "https://example.test/";
  const exactLimitUrl = `${baseUrl}${"a".repeat(MAX_LINK_URL_LIMIT - baseUrl.length)}`;
  const longUrl = `${exactLimitUrl}b`;
  const unsupportedUrl = "tg://resolve?domain=example_bot&start=<unsafe>";
  const converted = telegramInlineKeyboardForMax({
    inline_keyboard: [[
      { text: "Ровно лимит", url: exactLimitUrl },
      { text: "Слишком длинная", url: longUrl },
      { text: "Telegram", url: unsupportedUrl }
    ]]
  });

  assert.deepEqual(
    converted.attachments[0].payload.buttons.flat().map((button) => button.url),
    [exactLimitUrl]
  );
  assert.equal(converted.supplements.length, 2);
  assert.ok(converted.supplements[0].includes(longUrl));
  assert.ok(converted.supplements[1].includes(unsupportedUrl));

  const payloads = splitMaxPayload({
    text: "<b>Пост</b>",
    plainText: "Пост",
    format: "html",
    attachments: converted.attachments,
    supplements: converted.supplements
  });
  const relayedText = payloads.map((payload) => payload.text).join("");
  assert.ok(payloads.every((payload) => payload.text.length <= MAX_MESSAGE_TEXT_LIMIT));
  assert.ok(relayedText.includes(longUrl));
  assert.ok(relayedText.includes("tg://resolve?domain=example_bot&amp;start=&lt;unsafe&gt;"));
  assert.ok(!relayedText.includes(unsupportedUrl));
});

test("MAX image upload token is extracted from the real photos response shape", () => {
  assert.equal(
    extractMaxUploadToken({ photos: { photoId: { token: "image-token" } } }),
    "image-token"
  );
  assert.equal(extractMaxUploadToken({ retval: { token: "legacy-token" } }), "legacy-token");
});

test("MAX response attachments are reduced to valid reusable request shapes", () => {
  const requests = maxAttachmentRequests([
    {
      type: "image",
      payload: { photo_id: 17, token: "image-token", url: "https://cdn.test/image" },
      response_only: true
    },
    { type: "video", payload: { token: "video-token", url: "https://cdn.test/video" }, width: 1920 },
    { type: "audio", payload: { token: "audio-token", url: "https://cdn.test/audio" }, transcription: "text" },
    { type: "file", payload: { token: "file-token", url: "https://cdn.test/file" }, filename: "report.pdf", size: 42 },
    { type: "sticker", payload: { code: "sticker-code", url: "https://cdn.test/sticker" }, width: 128 },
    { type: "location", latitude: 47.1, longitude: 37.5, response_only: true },
    {
      type: "contact",
      payload: {
        vcf_info: "BEGIN:VCARD\\r\\nEND:VCARD",
        hash: "response-only-hash",
        max_info: { user_id: 7, name: "Иван", username: "response-only" }
      }
    },
    {
      type: "share",
      payload: { token: "share-token", url: "https://example.test" },
      title: "response-only title",
      description: "response-only description",
      image_url: "https://cdn.test/preview"
    },
    {
      type: "inline_keyboard",
      payload: {
        buttons: [[
          { type: "callback", text: "Unsafe callback", payload: "mx:unlink:yes" },
          { type: "link", text: "Safe link", url: "https://example.test", response_only: true }
        ]]
      }
    },
    { type: "unknown", payload: { token: "must-not-leak" } }
  ]);

  assert.deepEqual(requests, [
    { type: "image", payload: { token: "image-token" } },
    { type: "video", payload: { token: "video-token" } },
    { type: "audio", payload: { token: "audio-token" } },
    { type: "file", payload: { token: "file-token" } },
    { type: "sticker", payload: { code: "sticker-code" } },
    { type: "location", latitude: 47.1, longitude: 37.5 },
    {
      type: "contact",
      payload: { name: "Иван", contact_id: 7, vcf_info: "BEGIN:VCARD\\r\\nEND:VCARD" }
    },
    { type: "share", payload: { token: "share-token", url: "https://example.test" } },
    {
      type: "inline_keyboard",
      payload: { buttons: [[{ type: "link", text: "Safe link", url: "https://example.test" }]] }
    }
  ]);
});

test("MAX image request uses exactly one supported payload variant", () => {
  assert.deepEqual(maxAttachmentRequests([
    { type: "image", payload: { photos: { first: { token: "one", extra: true } }, url: "https://fallback.test" } },
    { type: "image", payload: { url: "https://image.test", photo_id: 99 } },
    { type: "video", payload: { url: "https://download-only.test" } }
  ]), [
    { type: "image", payload: { photos: { first: { token: "one" } } } },
    { type: "image", payload: { url: "https://image.test" } }
  ]);
});

test("MAX share URL is preserved for Telegram without duplicating body links", () => {
  const share = [{
    type: "share",
    payload: { url: "https://example.test/article", token: "share-token" },
    title: "Preview"
  }];

  assert.equal(appendMaxShareUrls("", share), "https://example.test/article");
  assert.equal(
    appendMaxShareUrls("Читайте: https://example.test/article", share),
    "Читайте: https://example.test/article"
  );
  assert.equal(
    appendMaxShareUrls("Описание", [...share, ...share]),
    "Описание\n\nhttps://example.test/article"
  );
  assert.equal(
    appendMaxShareUrls("x".repeat(4090), share),
    "x".repeat(4090)
  );
  assert.deepEqual(
    maxTelegramTextParts("x".repeat(4090), share),
    ["x".repeat(4090), "https://example.test/article"]
  );
});

test("MAX share metadata, contact identity and audio transcription survive Telegram fallback", () => {
  const parts = maxTelegramTextParts("", [
    {
      type: "share",
      payload: { token: "preview-token" },
      title: "Карточка",
      description: "Описание карточки",
      image_url: "https://cdn.test/preview.jpg"
    },
    {
      type: "contact",
      payload: { max_info: { user_id: 77, name: "Иван", username: "ivan" } }
    },
    {
      type: "audio",
      payload: { token: "audio-token" },
      transcription: "Текст записи"
    }
  ]);

  assert.equal(parts.length, 1);
  assert.match(parts[0], /Карточка/);
  assert.match(parts[0], /https:\/\/cdn\.test\/preview\.jpg/);
  assert.match(parts[0], /Контакт MAX: Иван · @ivan · MAX ID 77/);
  assert.match(parts[0], /Расшифровка аудио:\nТекст записи/);
  assert.ok(parts[0].length <= 4096);
});

test("MAX media formats are conservatively classified for Telegram", () => {
  assert.equal(telegramKindForMaxAttachment(
    { type: "video", filename: "clip.mp4" },
    "https://cdn.test/download"
  ), "video");
  assert.equal(telegramKindForMaxAttachment(
    { type: "video", filename: "clip.webm" },
    "https://cdn.test/download"
  ), "document");
  assert.equal(telegramKindForMaxAttachment(
    { type: "audio" },
    "https://cdn.test/voice.wav?token=1"
  ), "document");
  assert.equal(telegramKindForMaxAttachment(
    { type: "audio", payload: { filename: "track.m4a" } },
    "https://cdn.test/download"
  ), "audio");
  assert.equal(telegramKindForMaxAttachment(
    { type: "image" },
    "https://cdn.test/image.gif#preview"
  ), "document");
  assert.equal(telegramKindForMaxAttachment(
    { type: "image" },
    "https://cdn.test/image.jpeg?token=1"
  ), "photo");
});

test("MAX location and contact are converted to native Telegram payloads", () => {
  assert.deepEqual(maxSpecialAttachmentForTelegram({
    type: "location",
    latitude: 47.0971,
    longitude: 37.5434
  }), {
    kind: "location",
    latitude: 47.0971,
    longitude: 37.5434
  });
  assert.equal(maxSpecialAttachmentForTelegram({
    type: "location",
    latitude: 100,
    longitude: 37
  }), null);

  const vcard = "BEGIN:VCARD\r\nFN:Иван Иванов\r\nTEL;TYPE=cell:+380501234567\r\nEND:VCARD\r\n";
  assert.deepEqual(maxSpecialAttachmentForTelegram({
    type: "contact",
    payload: { vcf_info: vcard, max_info: { name: "Иван Иванов" }, hash: "response-only" }
  }), {
    kind: "contact",
    phoneNumber: "+380501234567",
    firstName: "Иван Иванов",
    vcard
  });

  const oversizedVcard = `BEGIN:VCARD\r\nFN:Иван\r\nTEL:+380501234567\r\nNOTE:${"я".repeat(1100)}\r\nEND:VCARD`;
  const normalized = maxSpecialAttachmentForTelegram({
    type: "contact",
    payload: { vcf_info: oversizedVcard }
  });
  assert.ok(Buffer.byteLength(normalized.vcard, "utf8") <= 2048);
  assert.match(normalized.vcard, /^BEGIN:VCARD\r\nVERSION:3\.0\r\n/);
  assert.match(normalized.vcard, /\r\nEND:VCARD$/);
  assert.doesNotMatch(normalized.vcard, /NOTE:/);
});

test("MAX forward-only posts expose linked text and attachments as relay content", () => {
  const attachment = {
    type: "image",
    payload: { token: "image-token", url: "https://cdn.test/image.jpg" }
  };
  const source = {
    timestamp: 1789000000123,
    recipient: { chat_id: -7743 },
    body: null,
    link: {
      type: "forward",
      chat_id: -100,
      message: {
        mid: "original-mid",
        text: "Исходный пост",
        attachments: [attachment],
        markup: [{ type: "strong", from: 0, length: 8 }]
      }
    }
  };

  const parts = maxRelayContentMessages(source);
  assert.equal(parts.length, 1);
  assert.equal(parts[0].body.text, "Исходный пост");
  assert.deepEqual(parts[0].body.attachments, [attachment]);
  assert.deepEqual(parts[0].body.markup, [{ type: "strong", from: 0, length: 8 }]);
  assert.equal(parts[0].link, null);
});

test("MAX own text and linked content become deterministic separate relay parts", () => {
  const source = {
    body: { mid: "outer-mid", text: "Комментарий", attachments: [] },
    link: {
      type: "reply",
      message: {
        mid: "linked-mid",
        text: "Ответ",
        attachments: [{ type: "file", payload: { token: "file-token" } }],
        markup: [{ type: "emphasized", from: 0, length: 5 }]
      }
    }
  };

  const parts = maxRelayContentMessages(source);
  assert.equal(parts.length, 2);
  assert.equal(parts[0].body.text, "Комментарий");
  assert.equal(parts[1].body.text, "Ответ на сообщение:\nОтвет");
  assert.equal(parts[1].body.attachments[0].payload.token, "file-token");
  assert.deepEqual(parts[1].body.markup, [{
    type: "emphasized",
    from: "Ответ на сообщение:\n".length,
    length: 5
  }]);
});

test("Telegram location and contact become native MAX attachment requests", () => {
  assert.deepEqual(telegramSpecialAttachmentsForMax({
    location: { latitude: 47.0971, longitude: 37.5434 }
  }), [{
    type: "location",
    latitude: 47.0971,
    longitude: 37.5434
  }]);

  const vcard = "BEGIN:VCARD\r\nFN:Иван Иванов\r\nTEL:+380501234567\r\nEND:VCARD";
  assert.deepEqual(telegramSpecialAttachmentsForMax({
    contact: {
      phone_number: "+380501234567",
      first_name: "Иван",
      last_name: "Иванов",
      user_id: 123456789,
      vcard
    }
  }), [{
    type: "contact",
    payload: {
      name: "Иван Иванов",
      vcf_info: vcard,
      vcf_phone: "+380501234567"
    }
  }]);

  assert.deepEqual(telegramSpecialAttachmentsForMax({
    location: { latitude: 91, longitude: 0 }
  }), []);
});

test("pure Telegram location and contact payloads are never filtered as empty", () => {
  for (const message of [
    { location: { latitude: 47.1, longitude: 37.5 } },
    { contact: { first_name: "Иван", phone_number: "+380501234567" } }
  ]) {
    const payloads = splitMaxPayload({
      attachments: telegramSpecialAttachmentsForMax(message)
    });
    assert.equal(payloads.length, 1);
    assert.equal(payloads[0].attachments.length, 1);
  }
});

const CONTAINER_ROOT = "/var/lib/telegram-bot-api";

test("absolute local Bot API path is mapped from container root to host root", async (t) => {
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gitreposted-media-"));
  t.after(() => fs.rm(hostRoot, { recursive: true, force: true }));

  const sourcePath = `${CONTAINER_ROOT}/123456789:bot-token/documents/Happ.apk`;
  const expectedPath = path.join(hostRoot, "123456789:bot-token", "documents", "Happ.apk");
  assert.equal(
    resolveTelegramLocalFilePath(sourcePath, {
      containerRoot: CONTAINER_ROOT,
      hostRoot
    }),
    expectedPath
  );
});

test("local Bot API mapping rejects relative, traversal and sibling paths", async (t) => {
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gitreposted-media-"));
  t.after(() => fs.rm(hostRoot, { recursive: true, force: true }));
  const options = { containerRoot: CONTAINER_ROOT, hostRoot };

  assert.throws(
    () => resolveTelegramLocalFilePath("../../etc/passwd", options),
    { code: "TELEGRAM_LOCAL_PATH_INVALID" }
  );
  assert.throws(
    () => resolveTelegramLocalFilePath(`${CONTAINER_ROOT}/../../etc/passwd`, options),
    { code: "TELEGRAM_LOCAL_PATH_OUTSIDE_ROOT" }
  );
  assert.throws(
    () => resolveTelegramLocalFilePath(`${CONTAINER_ROOT}-old/file.bin`, options),
    { code: "TELEGRAM_LOCAL_PATH_OUTSIDE_ROOT" }
  );
});

test("local Bot API file is read from mapped host storage", async (t) => {
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gitreposted-media-"));
  t.after(() => fs.rm(hostRoot, { recursive: true, force: true }));
  const relativePath = path.join("bot-token", "documents", "Happ.apk");
  const destinationPath = path.join(hostRoot, relativePath);
  await fs.mkdir(path.dirname(destinationPath), { recursive: true });
  const expected = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0xff, 0x00]);
  await fs.writeFile(destinationPath, expected);

  const actual = await readTelegramLocalFileBytes(
    `${CONTAINER_ROOT}/bot-token/documents/Happ.apk`,
    { containerRoot: CONTAINER_ROOT, hostRoot }
  );
  assert.deepEqual(actual, expected);
});

test("local Bot API read errors do not disclose token-bearing paths", async (t) => {
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gitreposted-media-"));
  t.after(() => fs.rm(hostRoot, { recursive: true, force: true }));
  const secretDirectory = "123456789:very-secret-bot-token";

  await assert.rejects(
    readTelegramLocalFileBytes(
      `${CONTAINER_ROOT}/${secretDirectory}/documents/missing.apk`,
      { containerRoot: CONTAINER_ROOT, hostRoot }
    ),
    (error) => {
      assert.equal(error.code, "TELEGRAM_LOCAL_FILE_UNAVAILABLE");
      assert.doesNotMatch(error.message, /very-secret-bot-token/);
      assert.doesNotMatch(error.message, /telegram-bot-api/);
      return true;
    }
  );
});

test("symlink escape from host storage is rejected", async (t) => {
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gitreposted-media-"));
  const outsideRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gitreposted-outside-"));
  t.after(() => Promise.all([
    fs.rm(hostRoot, { recursive: true, force: true }),
    fs.rm(outsideRoot, { recursive: true, force: true })
  ]));
  await fs.writeFile(path.join(outsideRoot, "secret.bin"), "secret");
  await fs.mkdir(path.join(hostRoot, "bot"), { recursive: true });
  try {
    await fs.symlink(outsideRoot, path.join(hostRoot, "bot", "documents"), "dir");
  } catch (error) {
    t.skip(`symlink creation is unavailable: ${error.code || "unknown"}`);
    return;
  }

  await assert.rejects(
    readTelegramLocalFileBytes(
      `${CONTAINER_ROOT}/bot/documents/secret.bin`,
      { containerRoot: CONTAINER_ROOT, hostRoot }
    ),
    { code: "TELEGRAM_LOCAL_PATH_OUTSIDE_ROOT" }
  );
});

test("forbidden APK is retried as Happ.apk.zip with the exact same bytes", async () => {
  const bytes = Buffer.from("not-an-archive: original APK bytes");
  const originalHash = crypto.createHash("sha256").update(bytes).digest("hex");
  const calls = [];
  const upload = async (type, receivedBytes, filename, mimeType) => {
    calls.push({ type, receivedBytes, filename, mimeType });
    if (calls.length === 1) throw new Error("415 File extension is forbidden");
    return "max-attachment-token";
  };

  const attachment = await uploadMaxAttachmentWithFallbacks({
    upload,
    type: "file",
    bytes,
    filename: "Happ.apk",
    mimeType: "application/vnd.android.package-archive"
  });

  assert.equal(calls.length, 2);
  assert.deepEqual(
    calls.map(({ type, filename, mimeType }) => ({ type, filename, mimeType })),
    [
      {
        type: "file",
        filename: "Happ.apk",
        mimeType: "application/vnd.android.package-archive"
      },
      {
        type: "file",
        filename: "Happ.apk.zip",
        mimeType: "application/zip"
      }
    ]
  );
  assert.strictEqual(calls[0].receivedBytes, bytes);
  assert.strictEqual(calls[1].receivedBytes, bytes);
  assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), originalHash);
  assert.deepEqual(attachment, {
    type: "file",
    payload: { token: "max-attachment-token" },
    renamedFrom: "Happ.apk",
    renamedTo: "Happ.apk.zip",
    deliveryNote: null
  });
});

test("non-extension upload errors are not retried", async () => {
  let calls = 0;
  await assert.rejects(
    uploadMaxAttachmentWithFallbacks({
      upload: async () => {
        calls += 1;
        throw new Error("MAX upload failed");
      },
      type: "file",
      bytes: Buffer.from("data"),
      filename: "document.pdf",
      mimeType: "application/pdf"
    }),
    /MAX upload failed/
  );
  assert.equal(calls, 1);
});

test("video over 250 MB is uploaded as a file with original bytes and filename", async () => {
  const bytes = { byteLength: MAX_VIDEO_UPLOAD_LIMIT_BYTES + 1 };
  const calls = [];
  const attachment = await uploadMaxAttachmentWithFallbacks({
    upload: async (type, receivedBytes, filename, mimeType) => {
      calls.push({ type, receivedBytes, filename, mimeType });
      return "large-video-token";
    },
    type: "video",
    bytes,
    filename: "IMG_7712.MP4",
    mimeType: "video/mp4"
  });

  assert.equal(calls.length, 1);
  assert.deepEqual(
    { type: calls[0].type, filename: calls[0].filename, mimeType: calls[0].mimeType },
    { type: "file", filename: "IMG_7712.MP4", mimeType: "video/mp4" }
  );
  assert.strictEqual(calls[0].receivedBytes, bytes);
  assert.equal(attachment.type, "file");
  assert.equal(attachment.payload.token, "large-video-token");
  assert.match(attachment.deliveryNote, /250 МБ/);
});

test("explicit MAX video size error retries as file, but arbitrary errors do not", async () => {
  const bytes = Buffer.from("same video bytes");
  const sizeCalls = [];
  const attachment = await uploadMaxAttachmentWithFallbacks({
    upload: async (type, receivedBytes, filename) => {
      sizeCalls.push({ type, receivedBytes, filename });
      if (sizeCalls.length === 1) throw new Error("MAX upload video: 413 Payload Too Large");
      return "fallback-token";
    },
    type: "video",
    bytes,
    filename: "clip.mp4",
    mimeType: "video/mp4"
  });
  assert.deepEqual(sizeCalls.map((call) => call.type), ["video", "file"]);
  assert.strictEqual(sizeCalls[0].receivedBytes, bytes);
  assert.strictEqual(sizeCalls[1].receivedBytes, bytes);
  assert.equal(attachment.type, "file");

  let arbitraryCalls = 0;
  await assert.rejects(
    uploadMaxAttachmentWithFallbacks({
      upload: async () => {
        arbitraryCalls += 1;
        throw new Error("MAX authentication failed");
      },
      type: "video",
      bytes,
      filename: "clip.mp4",
      mimeType: "video/mp4"
    }),
    /authentication failed/
  );
  assert.equal(arbitraryCalls, 1);
});

test("Telegram PNG sent as document stays a file with original name and bytes", async () => {
  const descriptor = telegramDocumentUploadDescriptor({
    file_id: "telegram-file-id",
    file_name: "original-image.png",
    mime_type: "image/png"
  }, 42);
  assert.deepEqual(descriptor, {
    fileId: "telegram-file-id",
    type: "file",
    filename: "original-image.png",
    mimeType: "image/png"
  });

  const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x01]);
  const sourceHash = crypto.createHash("sha256").update(bytes).digest("hex");
  const calls = [];
  const attachment = await uploadMaxAttachmentWithFallbacks({
    upload: async (type, receivedBytes, filename, mimeType) => {
      calls.push({ type, receivedBytes, filename, mimeType });
      return "png-document-token";
    },
    type: descriptor.type,
    bytes,
    filename: descriptor.filename,
    mimeType: descriptor.mimeType
  });

  assert.equal(calls.length, 1);
  assert.deepEqual(
    { type: calls[0].type, filename: calls[0].filename, mimeType: calls[0].mimeType },
    { type: "file", filename: "original-image.png", mimeType: "image/png" }
  );
  assert.strictEqual(calls[0].receivedBytes, bytes);
  assert.equal(crypto.createHash("sha256").update(calls[0].receivedBytes).digest("hex"), sourceHash);
  assert.equal(attachment.type, "file");
});

test("three-image album keeps caption and attachment order", () => {
  const payload = combineTelegramPayloadParts([
    { text: "Подпись альбома", format: null, attachments: [{ type: "image", payload: { token: "one" } }] },
    { text: "", format: null, attachments: [{ type: "image", payload: { token: "two" } }] },
    { text: "", format: null, attachments: [{ type: "image", payload: { token: "three" } }] }
  ]);

  assert.equal(payload.text, "Подпись альбома");
  assert.deepEqual(
    payload.attachments.map((attachment) => attachment.payload.token),
    ["one", "two", "three"]
  );
});

test("Telegram media identity is stable for album deduplication", () => {
  assert.equal(
    telegramMessageIdentity({
      message_id: 10,
      photo: [{ file_unique_id: "small" }, { file_unique_id: "large" }],
      media_group_id: "album"
    }),
    "large"
  );
  assert.equal(telegramMessageIdentity({ message_id: 11, media_group_id: "album" }), "album");
  assert.equal(telegramMessageIdentity({ message_id: 12 }), "12");
});

test("MAX payload keeps 4000 characters in one message and splits 4001 losslessly", () => {
  const exactLimit = "а".repeat(MAX_MESSAGE_TEXT_LIMIT);
  const exactPayloads = splitMaxPayload({ text: exactLimit });
  assert.equal(exactPayloads.length, 1);
  assert.equal(exactPayloads[0].text, exactLimit);

  const overLimit = `${exactLimit}б`;
  const splitPayloads = splitMaxPayload({ text: overLimit });
  assert.deepEqual(splitPayloads.map((payload) => payload.text.length), [4000, 1]);
  assert.equal(splitPayloads.map((payload) => payload.text).join(""), overLimit);
  assert.ok(splitPayloads.every((payload) => payload.text.length <= MAX_MESSAGE_TEXT_LIMIT));
});

test("oversized formatted MAX text falls back to exact plain text", () => {
  const plainText = "x".repeat(MAX_MESSAGE_TEXT_LIMIT - 6);
  const formattedText = `<b>${plainText}</b>`;
  assert.ok(formattedText.length > MAX_MESSAGE_TEXT_LIMIT);

  const payloads = splitMaxPayload({
    text: formattedText,
    plainText,
    format: "html"
  });

  assert.equal(payloads.map((payload) => payload.text).join(""), plainText);
  assert.ok(payloads.every((payload) => payload.format === null));
  assert.ok(payloads.every((payload) => payload.text.length <= MAX_MESSAGE_TEXT_LIMIT));
});

test("MAX text splitting never breaks an emoji surrogate pair", () => {
  const sourceText = `${"a".repeat(MAX_MESSAGE_TEXT_LIMIT - 1)}🙂z`;
  const payloads = splitMaxPayload({ text: sourceText });

  assert.equal(payloads.map((payload) => payload.text).join(""), sourceText);
  assert.ok(payloads.every((payload) => payload.text.length <= MAX_MESSAGE_TEXT_LIMIT));
  for (const payload of payloads) {
    assert.doesNotMatch(payload.text, /^[\uDC00-\uDFFF]/);
    assert.doesNotMatch(payload.text, /[\uD800-\uDBFF]$/);
  }
});

test("MAX visual attachments are ordered once and partitioned into batches of 12", () => {
  const attachments = Array.from({ length: 25 }, (_, index) => ({
    type: index % 2 === 0 ? "image" : "video",
    payload: { token: `visual-${index}` }
  }));
  const text = `${"п".repeat(MAX_MESSAGE_TEXT_LIMIT)}хвост`;
  const payloads = splitMaxPayload({ text, attachments });
  const attachmentBatches = payloads
    .map((payload) => payload.attachments)
    .filter((batch) => batch.length);

  assert.deepEqual(attachmentBatches.map((batch) => batch.length), [12, 12, 1]);
  assert.equal(payloads[0].attachments.length, MAX_VISUAL_ATTACHMENTS_PER_MESSAGE);
  assert.ok(attachmentBatches.every((batch) => (
    batch.filter((attachment) => attachment.type !== "inline_keyboard").length
      <= MAX_VISUAL_ATTACHMENTS_PER_MESSAGE
  )));
  assert.deepEqual(
    attachmentBatches.flat().map((attachment) => attachment.payload.token),
    attachments.map((attachment) => attachment.payload.token)
  );
  assert.equal(payloads[0].text, text.slice(0, MAX_MESSAGE_TEXT_LIMIT));
  assert.equal(payloads.map((payload) => payload.text).join(""), text);
});

test("MAX sends file and audio separately, with keyboard isolated from files", () => {
  const attachments = [
    { type: "file", payload: { token: "file-one" } },
    { type: "audio", payload: { token: "audio-one" } },
    { type: "file", payload: { token: "file-two" } },
    { type: "inline_keyboard", payload: { buttons: [[{ text: "Кнопка", url: "https://example.test" }]] } }
  ];
  const text = `${"т".repeat(MAX_MESSAGE_TEXT_LIMIT)}хвост`;
  const payloads = splitMaxPayload({ text, attachments });

  assert.equal(payloads.map((payload) => payload.text).join(""), text);
  assert.ok(payloads.every((payload) => payload.text.length <= MAX_MESSAGE_TEXT_LIMIT));
  assert.ok(payloads.every((payload) => {
    const types = payload.attachments.map((attachment) => attachment.type);
    return !(types.includes("inline_keyboard") && types.includes("file"));
  }));
  assert.deepEqual(
    payloads
      .flatMap((payload) => payload.attachments)
      .filter((attachment) => attachment.type !== "inline_keyboard")
      .map((attachment) => attachment.type),
    ["file", "audio", "file"]
  );
  assert.ok(payloads
    .filter((payload) => payload.attachments.some((attachment) => attachment.type !== "inline_keyboard"))
    .every((payload) => payload.attachments.length === 1));
});
