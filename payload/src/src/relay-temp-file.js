import crypto from "node:crypto";
import fsNative from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

export const TELEGRAM_LOCAL_UPLOAD_LIMIT_BYTES = 2 * 1024 * 1024 * 1024;

function isInsidePath(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === ""
    || (relative !== ".."
      && !relative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relative));
}

export function sanitizeRelayFilename(value, fallback = "document.bin") {
  let filename = String(value || "");
  try {
    filename = decodeURIComponent(filename);
  } catch {
  }
  filename = filename
    .normalize("NFKC")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .replace(/[\\/]/g, "_")
    .replace(/[<>:"|?*]/g, "_")
    .trim()
    .replace(/[. ]+$/g, "");
  if (!filename || filename === "." || filename === "..") filename = fallback;
  const characters = [...filename];
  if (characters.length > 180) {
    const extension = path.extname(filename).slice(0, 24);
    const baseLength = Math.max(1, 180 - [...extension].length);
    filename = `${characters.slice(0, baseLength).join("")}${extension}`;
  }
  return filename;
}

function urlFilename(value) {
  try {
    const url = new URL(String(value || ""));
    return url.pathname.split("/").filter(Boolean).at(-1) || "";
  } catch {
    return "";
  }
}

export function maxAttachmentFilename(item = {}, index = 0) {
  const payload = item?.payload || {};
  const url = payload.url
    || payload.file_url
    || payload?.urls?.download
    || item?.url
    || "";
  return sanitizeRelayFilename(
    payload.file_name
      || payload.filename
      || payload.name
      || item.file_name
      || item.filename
      || item.name
      || urlFilename(url),
    `document-${index + 1}.bin`
  );
}

function nodeReadable(body) {
  if (!body) throw new Error("MAX download response has no body.");
  if (typeof body.getReader === "function") return Readable.fromWeb(body);
  if (typeof body.pipe === "function") return body;
  return Readable.from(body);
}

function sanitizedDownloadError(error) {
  const code = /^[A-Z0-9_]+$/.test(String(error?.code || ""))
    ? String(error.code)
    : "DOWNLOAD_ERROR";
  const wrapped = new Error(`MAX file download failed (${code}).`);
  wrapped.code = "MAX_FILE_DOWNLOAD_FAILED";
  wrapped.reasonCode = code;
  return wrapped;
}

export async function downloadMaxFileToTelegramRelay({
  url,
  filename,
  hostRoot,
  containerRoot = "/var/lib/telegram-bot-api",
  tempSubdir = "gitreposted-relay",
  maxBytes = TELEGRAM_LOCAL_UPLOAD_LIMIT_BYTES,
  timeoutMs = 30 * 60 * 1000,
  fetchImpl = fetch
}) {
  const sourceUrl = new URL(String(url || ""));
  if (!["http:", "https:"].includes(sourceUrl.protocol)) {
    throw new TypeError("MAX attachment URL must use HTTP or HTTPS.");
  }
  if (!path.isAbsolute(String(hostRoot || ""))) {
    throw new TypeError("Telegram Bot API host root must be absolute.");
  }
  if (!path.posix.isAbsolute(String(containerRoot || ""))) {
    throw new TypeError("Telegram Bot API container root must be absolute.");
  }
  if (!/^[a-zA-Z0-9._-]{1,64}$/.test(String(tempSubdir || ""))
    || tempSubdir === "."
    || tempSubdir === "..") {
    throw new TypeError("Telegram relay temp subdirectory is invalid.");
  }

  const normalizedHostRoot = path.resolve(hostRoot);
  const relayRoot = path.resolve(normalizedHostRoot, tempSubdir);
  if (!isInsidePath(normalizedHostRoot, relayRoot)) {
    throw new TypeError("Telegram relay temp directory is outside the Bot API host root.");
  }
  const realHostRoot = await fs.realpath(normalizedHostRoot);
  const realRelayRoot = await fs.realpath(relayRoot);
  if (!isInsidePath(realHostRoot, realRelayRoot)) {
    throw new TypeError("Telegram relay temp directory resolves outside the Bot API host root.");
  }

  const safeFilename = sanitizeRelayFilename(filename);
  const operationDirectoryName = crypto.randomUUID();
  const operationDirectory = path.join(realRelayRoot, operationDirectoryName);
  const hostPath = path.join(operationDirectory, safeFilename);
  const containerPath = path.posix.join(
    path.posix.resolve(containerRoot),
    tempSubdir,
    operationDirectoryName,
    safeFilename
  );
  let response;
  let bytesWritten = 0;
  const transferTimeoutMs = Math.max(60 * 1000, Number(timeoutMs) || 30 * 60 * 1000);
  const transferSignal = AbortSignal.timeout(transferTimeoutMs);

  try {
    await fs.mkdir(operationDirectory, { mode: 0o750 });
    response = await fetchImpl(sourceUrl, { signal: transferSignal });
    if (!response?.ok) {
      const error = new Error("MAX attachment download returned an HTTP error.");
      error.code = `HTTP_${Number(response?.status || 0) || "ERROR"}`;
      throw error;
    }
    const declaredSize = Number(response.headers?.get?.("content-length") || 0);
    if (Number.isFinite(declaredSize) && declaredSize > maxBytes) {
      const error = new Error("MAX attachment exceeds Telegram local upload limit.");
      error.code = "FILE_TOO_LARGE";
      throw error;
    }

    const limiter = new Transform({
      transform(chunk, encoding, callback) {
        bytesWritten += chunk.length;
        if (bytesWritten > maxBytes) {
          const error = new Error("MAX attachment exceeds Telegram local upload limit.");
          error.code = "FILE_TOO_LARGE";
          callback(error);
          return;
        }
        callback(null, chunk);
      }
    });
    await pipeline(
      nodeReadable(response.body),
      limiter,
      fsNative.createWriteStream(hostPath, {
        flags: "wx",
        mode: 0o640
      }),
      { signal: transferSignal }
    );
    if (declaredSize > 0 && bytesWritten !== declaredSize) {
      const error = new Error("MAX attachment download was incomplete.");
      error.code = "DOWNLOAD_SIZE_MISMATCH";
      throw error;
    }

    return {
      hostPath,
      containerPath,
      filename: safeFilename,
      byteLength: bytesWritten,
      async openStream() {
        try {
          const fileStat = await fs.stat(hostPath);
          if (!fileStat.isFile() || Number(fileStat.size) !== bytesWritten) {
            const error = new Error("Downloaded MAX attachment changed before upload.");
            error.code = "DOWNLOAD_FILE_CHANGED";
            throw error;
          }
          return fsNative.createReadStream(hostPath);
        } catch (error) {
          throw sanitizedDownloadError(error);
        }
      },
      async cleanup() {
        await fs.rm(operationDirectory, { recursive: true, force: true });
      }
    };
  } catch (error) {
    try {
      await fs.rm(operationDirectory, { recursive: true, force: true });
    } catch {
    }
    if (error instanceof TypeError) throw error;
    throw sanitizedDownloadError(error);
  }
}
