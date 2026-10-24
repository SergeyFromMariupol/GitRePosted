import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { createMultipartFileUpload } from "../../payload/src/src/multipart-stream.js";
import {
  createTelegramLocalFileContent,
  mapSequential
} from "../../payload/src/src/relay-media.js";
import {
  downloadMaxFileToTelegramRelay,
  maxAttachmentFilename,
  sanitizeRelayFilename
} from "../../payload/src/src/relay-temp-file.js";

async function collect(readable) {
  const chunks = [];
  for await (const chunk of readable) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

test("local Telegram file creates repeatable streaming multipart with exact Content-Length", async (t) => {
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gitreposted-stream-"));
  t.after(() => fs.rm(hostRoot, { recursive: true, force: true }));
  const filePath = path.join(hostRoot, "bot", "documents", "Happ.apk");
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const original = Buffer.from("APK bytes are not converted into an archive");
  await fs.writeFile(filePath, original);
  const content = await createTelegramLocalFileContent(
    "/var/lib/telegram-bot-api/bot/documents/Happ.apk",
    {
      containerRoot: "/var/lib/telegram-bot-api",
      hostRoot
    }
  );

  const first = createMultipartFileUpload({
    content,
    fieldName: "document",
    filename: "Happ.apk",
    mimeType: "application/vnd.android.package-archive",
    fields: {
      chat_id: "-100123",
      reply_markup: JSON.stringify({ inline_keyboard: [] })
    },
    boundary: "gitreposted-test-boundary"
  });
  const second = createMultipartFileUpload({
    content,
    filename: "Happ.apk.zip",
    mimeType: "application/zip",
    boundary: "gitreposted-test-boundary-2"
  });
  const firstBody = await collect(first.body);
  const secondBody = await collect(second.body);

  assert.equal(firstBody.byteLength, first.contentLength);
  assert.equal(secondBody.byteLength, second.contentLength);
  assert.ok(firstBody.includes(original));
  assert.ok(secondBody.includes(original));
  assert.match(firstBody.toString("utf8"), /name="chat_id"\r\n\r\n-100123\r\n/);
  assert.match(firstBody.toString("utf8"), /name="document"; filename="Happ\.apk"/);
  assert.equal(crypto.createHash("sha256").update(original).digest("hex"),
    crypto.createHash("sha256").update(
      firstBody.subarray(firstBody.indexOf(original), firstBody.indexOf(original) + original.length)
    ).digest("hex"));
});

test("323 MB multipart construction is lazy and does not allocate the file", () => {
  let opened = 0;
  const content = {
    byteLength: 323_504_085,
    async openStream() {
      opened += 1;
      return Readable.from([]);
    }
  };
  const upload = createMultipartFileUpload({
    content,
    filename: "IMG_7712.MP4",
    mimeType: "video/mp4",
    boundary: "lazy-boundary"
  });
  assert.equal(opened, 0);
  assert.ok(upload.contentLength > content.byteLength);
  upload.body.destroy();
});

test("album mapper never processes more than one file concurrently", async () => {
  let active = 0;
  let maximumActive = 0;
  const result = await mapSequential([1, 2, 3, 4], async (value) => {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    await new Promise((resolve) => setTimeout(resolve, 2));
    active -= 1;
    return value * 2;
  });
  assert.equal(maximumActive, 1);
  assert.deepEqual(result, [2, 4, 6, 8]);
});

test("MAX document streams to Bot API temp mount with original filename and bytes", async (t) => {
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gitreposted-max-download-"));
  const relayRoot = path.join(hostRoot, "gitreposted-relay");
  await fs.mkdir(relayRoot);
  t.after(() => fs.rm(hostRoot, { recursive: true, force: true }));
  const original = Buffer.from("large-file-contract-in-small-test-chunks");
  const response = new Response(Readable.toWeb(Readable.from([
    original.subarray(0, 8),
    original.subarray(8)
  ])), {
    status: 200,
    headers: { "content-length": String(original.byteLength) }
  });

  const temporary = await downloadMaxFileToTelegramRelay({
    url: "https://cdn.example.test/download/random-id",
    filename: "Мой документ.png",
    hostRoot,
    containerRoot: "/var/lib/telegram-bot-api",
    fetchImpl: async () => response
  });
  assert.equal(temporary.filename, "Мой документ.png");
  assert.match(
    temporary.containerPath,
    /^\/var\/lib\/telegram-bot-api\/gitreposted-relay\/[0-9a-f-]+\/Мой документ\.png$/
  );
  const downloaded = await fs.readFile(temporary.hostPath);
  assert.deepEqual(downloaded, original);
  assert.deepEqual(await collect(await temporary.openStream()), original);
  assert.equal(
    crypto.createHash("sha256").update(downloaded).digest("hex"),
    crypto.createHash("sha256").update(original).digest("hex")
  );
  const operationDirectory = path.dirname(temporary.hostPath);
  await temporary.cleanup();
  await assert.rejects(fs.stat(operationDirectory), { code: "ENOENT" });
});

test("MAX attachment filename prefers payload metadata and blocks traversal", () => {
  assert.equal(maxAttachmentFilename({
    type: "file",
    payload: {
      name: "report.apk",
      url: "https://cdn.example.test/random"
    }
  }), "report.apk");
  assert.equal(sanitizeRelayFilename("../../evil.png"), ".._.._evil.png");
  assert.doesNotMatch(sanitizeRelayFilename("bad\r\nname.html"), /[\r\n]/);
});

test("MAX download reports a sanitized size reason and removes partial state", async (t) => {
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "gitreposted-max-limit-"));
  const relayRoot = path.join(hostRoot, "gitreposted-relay");
  await fs.mkdir(relayRoot);
  t.after(() => fs.rm(hostRoot, { recursive: true, force: true }));

  await assert.rejects(
    downloadMaxFileToTelegramRelay({
      url: "https://cdn.example.test/private-token",
      filename: "large.bin",
      hostRoot,
      maxBytes: 10,
      fetchImpl: async () => new Response("too many bytes", {
        status: 200,
        headers: { "content-length": "14" }
      })
    }),
    (error) => {
      assert.equal(error.code, "MAX_FILE_DOWNLOAD_FAILED");
      assert.equal(error.reasonCode, "FILE_TOO_LARGE");
      assert.doesNotMatch(error.message, /private-token/);
      return true;
    }
  );
  assert.deepEqual(await fs.readdir(relayRoot), []);
});
