import crypto from "node:crypto";
import { Readable } from "node:stream";

function cleanHeaderValue(value, fallback) {
  const cleaned = String(value || "")
    .replace(/[\r\n\0]/g, "")
    .replace(/\\/g, "_")
    .replace(/"/g, "'");
  return cleaned || fallback;
}

function bufferView(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  return null;
}

export function multipartContentSize(content) {
  const direct = bufferView(content);
  const value = direct?.byteLength ?? content?.byteLength ?? content?.size;
  const size = Number(value);
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new TypeError("Multipart content size is required.");
  }
  return size;
}

async function* contentChunks(content) {
  const direct = bufferView(content);
  if (direct) {
    yield direct;
    return;
  }
  if (typeof content?.openStream !== "function") {
    throw new TypeError("Repeatable multipart stream factory is required.");
  }
  const stream = await content.openStream();
  for await (const chunk of stream) yield chunk;
}

export function createMultipartFileUpload({
  content,
  fieldName = "data",
  filename = "upload.bin",
  mimeType = "application/octet-stream",
  fields = {},
  boundary = `----gitreposted-${crypto.randomBytes(18).toString("hex")}`
}) {
  const safeFieldName = cleanHeaderValue(fieldName, "data");
  const safeFilename = cleanHeaderValue(filename, "upload.bin");
  const safeMimeType = cleanHeaderValue(mimeType, "application/octet-stream");
  const encodedFilename = encodeURIComponent(safeFilename)
    .replaceAll("'", "%27")
    .replaceAll("(", "%28")
    .replaceAll(")", "%29");
  const fieldParts = Object.entries(fields && typeof fields === "object" ? fields : {})
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([name, value]) => Buffer.from(
      `--${boundary}\r\n`
        + `Content-Disposition: form-data; name="${cleanHeaderValue(name, "field")}"\r\n\r\n`
        + `${String(value)}\r\n`,
      "utf8"
    ));
  const header = Buffer.from(
    `--${boundary}\r\n`
      + `Content-Disposition: form-data; name="${safeFieldName}"; filename="${safeFilename}"; filename*=UTF-8''${encodedFilename}\r\n`
      + `Content-Type: ${safeMimeType}\r\n\r\n`,
    "utf8"
  );
  const footer = Buffer.from(`\r\n--${boundary}--\r\n`, "utf8");
  const contentLength = fieldParts.reduce((total, part) => total + part.byteLength, 0)
    + header.byteLength
    + multipartContentSize(content)
    + footer.byteLength;

  async function* bodyChunks() {
    yield* fieldParts;
    yield header;
    yield* contentChunks(content);
    yield footer;
  }

  return {
    boundary,
    contentLength,
    contentType: `multipart/form-data; boundary=${boundary}`,
    body: Readable.from(bodyChunks())
  };
}
