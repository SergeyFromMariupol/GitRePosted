import fsNative from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { Readable } from "node:stream";

export class TelegramLocalFileError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TelegramLocalFileError";
    this.code = code;
  }
}

export const MAX_VIDEO_UPLOAD_LIMIT_BYTES = 250 * 1024 * 1024;
export const MAX_LINK_BUTTONS_PER_ROW = 3;
export const MAX_INLINE_KEYBOARD_ROWS = 30;
export const MAX_LINK_URL_LIMIT = 2048;

export function extractMaxUploadToken(payload, depth = 0) {
  if (!payload || depth > 5) return null;
  if (typeof payload?.token === "string" && payload.token) return payload.token;
  if (Array.isArray(payload)) {
    for (const item of payload) {
      const token = extractMaxUploadToken(item, depth + 1);
      if (token) return token;
    }
    return null;
  }
  if (typeof payload === "object") {
    for (const value of Object.values(payload)) {
      const token = extractMaxUploadToken(value, depth + 1);
      if (token) return token;
    }
  }
  return null;
}

function isInsidePath(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === ""
    || (relative !== ".."
      && !relative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relative));
}

function localFileError(code, message) {
  return new TelegramLocalFileError(code, message);
}

export function resolveTelegramLocalFilePath(filePath, {
  containerRoot = "/var/lib/telegram-bot-api",
  hostRoot
} = {}) {
  const sourcePath = String(filePath || "");
  const sourceRoot = String(containerRoot || "");
  const destinationRoot = String(hostRoot || "");

  if (!sourcePath || sourcePath.includes("\0") || !path.posix.isAbsolute(sourcePath)) {
    throw localFileError(
      "TELEGRAM_LOCAL_PATH_INVALID",
      "Telegram local file path is invalid."
    );
  }
  if (!sourceRoot || sourceRoot.includes("\0") || !path.posix.isAbsolute(sourceRoot)) {
    throw localFileError(
      "TELEGRAM_CONTAINER_ROOT_INVALID",
      "Telegram Bot API container root is invalid."
    );
  }
  if (!destinationRoot || destinationRoot.includes("\0") || !path.isAbsolute(destinationRoot)) {
    throw localFileError(
      "TELEGRAM_HOST_ROOT_INVALID",
      "Telegram Bot API host root is invalid."
    );
  }

  const normalizedSourceRoot = path.posix.resolve(sourceRoot);
  const normalizedSourcePath = path.posix.resolve(sourcePath);
  const relativeSourcePath = path.posix.relative(normalizedSourceRoot, normalizedSourcePath);
  if (!relativeSourcePath
    || relativeSourcePath === ".."
    || relativeSourcePath.startsWith("../")
    || path.posix.isAbsolute(relativeSourcePath)) {
    throw localFileError(
      "TELEGRAM_LOCAL_PATH_OUTSIDE_ROOT",
      "Telegram local file path is outside the configured container root."
    );
  }

  const normalizedDestinationRoot = path.resolve(destinationRoot);
  const destinationPath = path.resolve(
    normalizedDestinationRoot,
    ...relativeSourcePath.split("/")
  );
  if (!isInsidePath(normalizedDestinationRoot, destinationPath)) {
    throw localFileError(
      "TELEGRAM_LOCAL_PATH_OUTSIDE_ROOT",
      "Telegram local file path is outside the configured host root."
    );
  }

  return destinationPath;
}

export async function readTelegramLocalFileBytes(filePath, options = {}) {
  const inspected = await inspectTelegramLocalFile(filePath, options);
  try {
    return await fs.readFile(inspected.realPath);
  } catch (error) {
    if (error instanceof TelegramLocalFileError) throw error;
    const errorCode = /^[A-Z0-9_]+$/.test(String(error?.code || ""))
      ? String(error.code)
      : "IO_ERROR";
    throw localFileError(
      "TELEGRAM_LOCAL_FILE_UNAVAILABLE",
      `Telegram local file is unavailable (${errorCode}).`
    );
  }
}

export async function inspectTelegramLocalFile(filePath, options = {}) {
  const destinationPath = resolveTelegramLocalFilePath(filePath, options);
  const configuredHostRoot = path.resolve(String(options.hostRoot || ""));

  try {
    const [realHostRoot, realDestinationPath] = await Promise.all([
      fs.realpath(configuredHostRoot),
      fs.realpath(destinationPath)
    ]);
    if (!isInsidePath(realHostRoot, realDestinationPath)) {
      throw localFileError(
        "TELEGRAM_LOCAL_PATH_OUTSIDE_ROOT",
        "Telegram local file resolves outside the configured host root."
      );
    }
    const fileStat = await fs.stat(realDestinationPath);
    if (!fileStat.isFile()) {
      throw localFileError(
        "TELEGRAM_LOCAL_PATH_NOT_FILE",
        "Telegram local file path does not point to a regular file."
      );
    }
    return {
      realPath: realDestinationPath,
      byteLength: Number(fileStat.size)
    };
  } catch (error) {
    if (error instanceof TelegramLocalFileError) throw error;
    const errorCode = /^[A-Z0-9_]+$/.test(String(error?.code || ""))
      ? String(error.code)
      : "IO_ERROR";
    throw localFileError(
      "TELEGRAM_LOCAL_FILE_UNAVAILABLE",
      `Telegram local file is unavailable (${errorCode}).`
    );
  }
}

export async function createTelegramLocalFileContent(filePath, options = {}) {
  const inspected = await inspectTelegramLocalFile(filePath, options);
  return {
    byteLength: inspected.byteLength,
    async openStream() {
      const current = await inspectTelegramLocalFile(filePath, options);
      if (current.byteLength !== inspected.byteLength) {
        throw localFileError(
          "TELEGRAM_LOCAL_FILE_CHANGED",
          "Telegram local file changed before upload."
        );
      }
      async function* safeChunks() {
        try {
          for await (const chunk of fsNative.createReadStream(current.realPath)) {
            yield chunk;
          }
        } catch (error) {
          const errorCode = /^[A-Z0-9_]+$/.test(String(error?.code || ""))
            ? String(error.code)
            : "IO_ERROR";
          throw localFileError(
            "TELEGRAM_LOCAL_FILE_UNAVAILABLE",
            `Telegram local file stream is unavailable (${errorCode}).`
          );
        }
      }
      return Readable.from(safeChunks());
    }
  };
}

function maxVideoSizeError(error) {
  return /\b413\b|payload too large|request entity too large|file (?:is )?too large|size limit|video.{0,40}(?:too large|limit)|maximum.{0,40}(?:file|video)/i
    .test(String(error?.message || ""));
}

export async function uploadMaxAttachmentWithFallbacks({
  upload,
  type,
  bytes,
  filename,
  mimeType,
  maxVideoBytes = MAX_VIDEO_UPLOAD_LIMIT_BYTES
}) {
  if (typeof upload !== "function") {
    throw new TypeError("MAX upload function is required.");
  }

  let token;
  let uploadedType = type;
  let renamedTo = null;
  let deliveryNote = null;
  const byteLength = Number(bytes?.byteLength ?? bytes?.length ?? 0);
  const oversizedVideo = type === "video"
    && Number.isFinite(byteLength)
    && byteLength > maxVideoBytes;

  if (oversizedVideo) {
    uploadedType = "file";
    token = await upload("file", bytes, filename, mimeType);
    deliveryNote = `Видео «${filename}» превышает лимит МАКС 250 МБ и отправлено как файл.`;
  }

  try {
    if (!token) token = await upload(type, bytes, filename, mimeType);
  } catch (error) {
    const extensionIsForbidden = /file extension is forbidden/i.test(String(error?.message || ""));
    if (type === "file" && extensionIsForbidden) {
      renamedTo = `${filename}.zip`;
      token = await upload("file", bytes, renamedTo, "application/zip");
    } else if (type === "video" && maxVideoSizeError(error)) {
      uploadedType = "file";
      token = await upload("file", bytes, filename, mimeType);
      deliveryNote = `Видео «${filename}» не прошло лимит размера МАКС и отправлено как файл.`;
    } else {
      throw error;
    }
  }

  if (!token) {
    throw new Error("MAX upload did not return an attachment token.");
  }

  return {
    type: uploadedType,
    payload: { token },
    renamedFrom: renamedTo ? filename : null,
    renamedTo,
    deliveryNote
  };
}

export function combineTelegramPayloadParts(parts = []) {
  const normalizedParts = Array.isArray(parts) ? parts.filter(Boolean) : [];
  const textPart = normalizedParts.find((part) => part.text);
  return {
    text: textPart?.text || "",
    plainText: textPart?.plainText || "",
    format: textPart?.format || null,
    attachments: normalizedParts.flatMap((part) => (
      Array.isArray(part.attachments) ? part.attachments : []
    )),
    supplements: normalizedParts.flatMap((part) => (
      Array.isArray(part.supplements) ? part.supplements : []
    ))
  };
}

function nonEmptyString(value) {
  return typeof value === "string" && value.length ? value : null;
}

function maxButtonLinkUrl(value) {
  if (typeof value !== "string") return null;
  const candidate = value.trim();
  if (!candidate
    || candidate.length > MAX_LINK_URL_LIMIT
    || /[\u0000-\u001f\u007f]/.test(candidate)) {
    return null;
  }
  try {
    const parsed = new URL(candidate);
    if (!["http:", "https:"].includes(parsed.protocol)
      || !parsed.hostname
      || parsed.username
      || parsed.password
      || parsed.href.length > MAX_LINK_URL_LIMIT) {
      return null;
    }
    return candidate;
  } catch {
    return null;
  }
}

function keyboardSupplementField(value, fallback, maxLength = 32768) {
  const cleaned = String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim();
  if (!cleaned) return fallback;
  const characters = [...cleaned];
  return characters.length <= maxLength
    ? cleaned
    : `${characters.slice(0, Math.max(1, maxLength - 1)).join("")}…`;
}

function telegramKeyboardLinkSupplement(button, rawUrl, reason) {
  const text = keyboardSupplementField(button?.text, "Открыть", 512);
  const url = keyboardSupplementField(rawUrl, "ссылка не указана");
  return `Кнопка Telegram «${text}» (${reason}): ${url}`;
}

// Telegram permits wider inline-keyboard rows than MAX. This converter keeps
// portable HTTP(S) links in their original order and turns every rejected link
// into plain supplemental text, so a relay never fails or silently loses it.
export function telegramInlineKeyboardForMax(replyMarkup = {}) {
  const sourceRows = Array.isArray(replyMarkup?.inline_keyboard)
    ? replyMarkup.inline_keyboard
    : [];
  const buttons = [];
  const supplements = [];

  for (const sourceRow of sourceRows) {
    if (!Array.isArray(sourceRow)) continue;
    const entries = sourceRow.flatMap((button) => {
      if (!button || typeof button !== "object" || typeof button.url !== "string") return [];
      const rawUrl = button.url.trim();
      if (!rawUrl) return [];
      const url = maxButtonLinkUrl(rawUrl);
      return [{
        button,
        rawUrl,
        url,
        text: keyboardSupplementField(button.text, "Открыть", 128)
      }];
    });
    const remainingRows = Math.max(0, MAX_INLINE_KEYBOARD_ROWS - buttons.length);
    const acceptedValidCount = Math.min(
      entries.filter((entry) => entry.url).length,
      remainingRows * MAX_LINK_BUTTONS_PER_ROW
    );
    let acceptedCount = 0;
    const accepted = [];

    for (const entry of entries) {
      if (!entry.url) {
        supplements.push(telegramKeyboardLinkSupplement(
          entry.button,
          entry.rawUrl,
          "ссылка недоступна как кнопка в МАКС"
        ));
      } else if (acceptedCount < acceptedValidCount) {
        accepted.push({ type: "link", text: entry.text, url: entry.url });
        acceptedCount += 1;
      } else {
        supplements.push(telegramKeyboardLinkSupplement(
          entry.button,
          entry.rawUrl,
          "не помещается в клавиатуру МАКС"
        ));
      }
    }

    for (let offset = 0; offset < accepted.length; offset += MAX_LINK_BUTTONS_PER_ROW) {
      buttons.push(accepted.slice(offset, offset + MAX_LINK_BUTTONS_PER_ROW));
    }
  }

  return {
    attachments: buttons.length
      ? [{ type: "inline_keyboard", payload: { buttons } }]
      : [],
    supplements
  };
}

function maxImageRequestPayload(payload = {}) {
  const token = nonEmptyString(payload?.token);
  if (token) return { token };

  if (payload?.photos && typeof payload.photos === "object" && !Array.isArray(payload.photos)) {
    const photos = Object.fromEntries(Object.entries(payload.photos)
      .filter(([, item]) => nonEmptyString(item?.token))
      .map(([key, item]) => [key, { token: item.token }]));
    if (Object.keys(photos).length) return { photos };
  }

  const url = nonEmptyString(payload?.url);
  return url ? { url } : null;
}

function maxReusableTokenRequest(type, payload = {}) {
  const token = nonEmptyString(payload?.token);
  return token ? { type, payload: { token } } : null;
}

function maxSafeLinkKeyboard(payload = {}) {
  const rows = Array.isArray(payload?.buttons) ? payload.buttons : [];
  const buttons = rows
    .map((row) => (Array.isArray(row) ? row : [])
      .filter((button) => button?.type === "link"
        && nonEmptyString(button?.text)
        && nonEmptyString(button?.url))
      .map((button) => ({ type: "link", text: button.text, url: button.url })))
    .filter((row) => row.length);
  return buttons.length
    ? { type: "inline_keyboard", payload: { buttons } }
    : null;
}

// MAX returns Attachment objects in webhook messages, while POST /messages
// accepts the narrower AttachmentRequest union. Reusing a media token is
// supported by MAX and avoids downloading/uploading the same file again.
// Only link buttons are portable: callback payloads belong to the original
// sender and must not be re-emitted as callbacks owned by this bot.
export function maxAttachmentRequest(attachment = {}) {
  if (!attachment || typeof attachment !== "object" || Array.isArray(attachment)) return null;
  const type = String(attachment.type || "");
  const payload = attachment.payload && typeof attachment.payload === "object"
    && !Array.isArray(attachment.payload)
    ? attachment.payload
    : {};

  if (type === "image") {
    const requestPayload = maxImageRequestPayload(payload);
    return requestPayload ? { type, payload: requestPayload } : null;
  }
  if (["video", "audio", "file"].includes(type)) {
    return maxReusableTokenRequest(type, payload);
  }
  if (type === "sticker") {
    const code = nonEmptyString(payload.code);
    return code ? { type, payload: { code } } : null;
  }
  if (type === "location") {
    const latitude = Number(attachment.latitude);
    const longitude = Number(attachment.longitude);
    return Number.isFinite(latitude) && Number.isFinite(longitude)
      ? { type, latitude, longitude }
      : null;
  }
  if (type === "contact") {
    const maxInfo = payload.max_info && typeof payload.max_info === "object"
      ? payload.max_info
      : {};
    const name = nonEmptyString(payload.name)
      || nonEmptyString(maxInfo.name)
      || nonEmptyString(maxInfo.first_name)
      || "Контакт";
    const requestPayload = { name };
    const contactId = payload.contact_id ?? maxInfo.user_id;
    if (Number.isSafeInteger(contactId)) requestPayload.contact_id = contactId;
    for (const key of ["vcf_info", "vcf_phone"]) {
      const value = nonEmptyString(payload[key]);
      if (value) requestPayload[key] = value;
    }
    return { type, payload: requestPayload };
  }
  if (type === "inline_keyboard") return maxSafeLinkKeyboard(payload);
  if (type === "share") {
    const token = nonEmptyString(payload.token);
    const url = nonEmptyString(payload.url);
    if (!token && !url) return null;
    return {
      type,
      payload: {
        ...(token ? { token } : {}),
        ...(url ? { url } : {})
      }
    };
  }
  return null;
}

export function maxAttachmentRequests(attachments = []) {
  return (Array.isArray(attachments) ? attachments : [])
    .map((attachment) => maxAttachmentRequest(attachment))
    .filter(Boolean);
}

function maxBodyHasRelayContent(body) {
  return Boolean(
    body
    && typeof body === "object"
    && !Array.isArray(body)
    && ((typeof body.text === "string" && body.text.length)
      || (Array.isArray(body.attachments) && body.attachments.length))
  );
}

function linkedBodyWithLabel(body, linkType) {
  const label = linkType === "reply"
    ? "Ответ на сообщение:"
    : "Пересланное сообщение:";
  const sourceText = typeof body.text === "string" ? body.text : "";
  const prefix = `${label}${sourceText ? "\n" : ""}`;
  const markup = (Array.isArray(body.markup) ? body.markup : []).map((item) => ({
    ...item,
    from: Number(item?.from || 0) + prefix.length
  }));
  return {
    ...body,
    text: `${prefix}${sourceText}`,
    ...(markup.length ? { markup } : { markup: [] })
  };
}

// A MAX post can carry its own body and a forwarded/replied Message.link.
// Relay each body as a deterministic content part. This avoids sending a
// cross-chat reply reference that the destination may reject and preserves
// forward-only posts whose outer body is null.
export function maxRelayContentMessages(message = {}) {
  const outerBody = message?.body && typeof message.body === "object"
    && !Array.isArray(message.body)
    ? message.body
    : null;
  const linkedBody = message?.link?.message && typeof message.link.message === "object"
    && !Array.isArray(message.link.message)
    ? message.link.message
    : null;
  if (!linkedBody) return [message];

  const parts = [];
  if (maxBodyHasRelayContent(outerBody)) {
    parts.push({ ...message, link: null, body: outerBody });
  }
  if (maxBodyHasRelayContent(linkedBody)) {
    parts.push({
      ...message,
      link: null,
      body: parts.length
        ? linkedBodyWithLabel(linkedBody, message?.link?.type)
        : linkedBody
    });
  }
  return parts.length ? parts : [message];
}

function safeHttpUrl(value) {
  const candidate = nonEmptyString(value);
  if (!candidate || candidate.length > 2048 || /[\u0000-\u001f\u007f]/.test(candidate)) {
    return null;
  }
  try {
    const parsed = new URL(candidate);
    return ["http:", "https:"].includes(parsed.protocol)
      && parsed.hostname
      && !parsed.username
      && !parsed.password
      && parsed.href.length <= 2048
      ? parsed.href
      : null;
  } catch {
    return null;
  }
}

function cleanSupplementalText(value, maxLength = 4000) {
  const cleaned = String(value || "")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .trim();
  if (!cleaned) return null;
  const characters = [...cleaned];
  return characters.length <= maxLength
    ? cleaned
    : `${characters.slice(0, Math.max(1, maxLength - 1)).join("")}…`;
}

function maxContactSupplement(attachment) {
  if (maxSpecialAttachmentForTelegram(attachment)) return null;
  const payload = attachment?.payload && typeof attachment.payload === "object"
    ? attachment.payload
    : {};
  const maxInfo = payload.max_info && typeof payload.max_info === "object"
    ? payload.max_info
    : {};
  const name = cleanSupplementalText(
    nonEmptyString(payload.name)
      || nonEmptyString(maxInfo.name)
      || [maxInfo.first_name, maxInfo.last_name].filter(nonEmptyString).join(" ")
      || "Контакт MAX",
    200
  );
  const usernameValue = nonEmptyString(maxInfo.username)?.replace(/^@+/, "") || "";
  const username = /^[A-Za-z0-9_.-]{1,128}$/.test(usernameValue)
    ? `@${usernameValue}`
    : null;
  const userId = Number.isSafeInteger(maxInfo.user_id) ? `MAX ID ${maxInfo.user_id}` : null;
  return `Контакт MAX: ${[name, username, userId].filter(Boolean).join(" · ")}`;
}

function maxAttachmentSupplements(attachments = []) {
  const supplements = [];
  for (const attachment of Array.isArray(attachments) ? attachments : []) {
    const type = String(attachment?.type || "");
    const payload = attachment?.payload && typeof attachment.payload === "object"
      ? attachment.payload
      : {};
    if (type === "share") {
      const url = safeHttpUrl(payload.url);
      if (url) {
        supplements.push(url);
        continue;
      }
      const title = cleanSupplementalText(attachment.title, 500);
      const description = cleanSupplementalText(attachment.description, 3000);
      const imageUrl = safeHttpUrl(attachment.image_url || payload.image_url);
      const details = [title, description, imageUrl].filter(Boolean);
      supplements.push(details.length
        ? `Ссылка из MAX:\n${details.join("\n")}`
        : "Ссылка из MAX: предпросмотр недоступен после пересылки.");
      continue;
    }
    if (type === "contact") {
      const contact = maxContactSupplement(attachment);
      if (contact) supplements.push(contact);
      continue;
    }
    if (type === "audio" || type === "voice") {
      const transcription = cleanSupplementalText(
        attachment.transcription || payload.transcription,
        4000
      );
      if (transcription) supplements.push(`Расшифровка аудио:\n${transcription}`);
    }
  }
  return [...new Set(supplements)];
}

export function maxTelegramTextParts(text, attachments = [], limit = 4096) {
  const sourceText = String(text || "");
  const normalizedLimit = Math.max(1, Number.parseInt(String(limit), 10) || 4096);
  const parts = sourceText ? textChunks(sourceText, normalizedLimit) : [];
  const supplements = maxAttachmentSupplements(attachments)
    .filter((supplement) => !sourceText.includes(supplement));

  for (const supplement of supplements) {
    const chunks = textChunks(supplement, normalizedLimit);
    for (const chunk of chunks) {
      const lastIndex = parts.length - 1;
      const prefix = lastIndex >= 0 && parts[lastIndex] ? "\n\n" : "";
      if (lastIndex >= 0
        && parts[lastIndex].length + prefix.length + chunk.length <= normalizedLimit) {
        parts[lastIndex] += `${prefix}${chunk}`;
      } else {
        parts.push(chunk);
      }
    }
  }
  return parts.length ? parts : [""];
}

export function appendMaxShareUrls(text, attachments = [], limit = 4096) {
  return maxTelegramTextParts(text, attachments, limit)[0];
}

function maxVcardValue(vcard, key) {
  const prefix = String(key || "").toUpperCase();
  const line = String(vcard || "")
    .split(/\r?\n/)
    .find((candidate) => {
      const normalized = candidate.toUpperCase();
      return normalized.startsWith(`${prefix}:`) || normalized.startsWith(`${prefix};`);
    });
  if (!line) return null;
  const separator = line.indexOf(":");
  if (separator < 0) return null;
  return line.slice(separator + 1)
    .replace(/\\n/gi, "\n")
    .replace(/\\([,;\\])/g, "$1")
    .trim() || null;
}

export function maxSpecialAttachmentForTelegram(attachment = {}) {
  const type = String(attachment?.type || "");
  const payload = attachment?.payload && typeof attachment.payload === "object"
    ? attachment.payload
    : {};
  if (type === "location") {
    const latitude = Number(attachment.latitude);
    const longitude = Number(attachment.longitude);
    if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90
      || !Number.isFinite(longitude) || longitude < -180 || longitude > 180) {
      return null;
    }
    return { kind: "location", latitude, longitude };
  }
  if (type !== "contact") return null;

  const vcard = nonEmptyString(payload.vcf_info) || "";
  const rawPhone = nonEmptyString(payload.vcf_phone) || maxVcardValue(vcard, "TEL");
  if (!rawPhone) return null;
  const maxInfo = payload.max_info && typeof payload.max_info === "object"
    ? payload.max_info
    : {};
  const name = nonEmptyString(payload.name)
    || nonEmptyString(maxInfo.name)
    || nonEmptyString(maxInfo.first_name)
    || maxVcardValue(vcard, "FN")
    || "Контакт";
  const minimalVcardValue = (value) => String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/\r?\n/g, "\\n")
    .replace(/([,;])/g, "\\$1");
  const minimalVcard = [
    "BEGIN:VCARD",
    "VERSION:3.0",
    `FN:${minimalVcardValue(name.slice(0, 64))}`,
    `TEL:${minimalVcardValue(rawPhone.slice(0, 64))}`,
    "END:VCARD"
  ].join("\r\n");
  const sourceVcardIsValid = /^BEGIN:VCARD(?:\r?\n|$)/i.test(vcard)
    && /(?:^|\r?\n)END:VCARD(?:\r?\n|$)/i.test(vcard)
    && Buffer.byteLength(vcard, "utf8") <= 2048;
  const telegramVcard = sourceVcardIsValid ? vcard : minimalVcard;
  return {
    kind: "contact",
    phoneNumber: rawPhone.slice(0, 64),
    firstName: name.slice(0, 64),
    ...(Buffer.byteLength(telegramVcard, "utf8") <= 2048
      ? { vcard: telegramVcard }
      : {})
  };
}

function attachmentExtension(attachment, source) {
  const payload = attachment?.payload && typeof attachment.payload === "object"
    ? attachment.payload
    : {};
  const filename = nonEmptyString(payload.file_name)
    || nonEmptyString(payload.filename)
    || nonEmptyString(payload.name)
    || nonEmptyString(attachment?.file_name)
    || nonEmptyString(attachment?.filename)
    || nonEmptyString(attachment?.name);
  let candidate = filename || "";
  if (!candidate) {
    try {
      candidate = new URL(String(source || "")).pathname.split("/").at(-1) || "";
    } catch {
    }
  }
  const match = /\.([A-Za-z0-9]{1,12})$/.exec(candidate);
  return match ? `.${match[1].toLowerCase()}` : "";
}

export function telegramKindForMaxAttachment(attachment = {}, source = "") {
  const type = String(attachment?.type || "").toLowerCase();
  const extension = attachmentExtension(attachment, source);
  if (["image", "photo"].includes(type)) {
    return [".jpg", ".jpeg", ".png", ".webp"].includes(extension)
      ? "photo"
      : "document";
  }
  if (type === "video") return extension === ".mp4" ? "video" : "document";
  if (["audio", "voice"].includes(type)) {
    return [".mp3", ".m4a"].includes(extension) ? "audio" : "document";
  }
  return "document";
}

export function telegramSpecialAttachmentsForMax(message = {}) {
  const attachments = [];
  const location = message?.location || message?.venue?.location;
  if (location) {
    const latitude = Number(location.latitude);
    const longitude = Number(location.longitude);
    if (Number.isFinite(latitude) && latitude >= -90 && latitude <= 90
      && Number.isFinite(longitude) && longitude >= -180 && longitude <= 180) {
      attachments.push({ type: "location", latitude, longitude });
    }
  }

  const contact = message?.contact;
  if (contact && typeof contact === "object") {
    const name = [contact.first_name, contact.last_name]
      .filter((value) => typeof value === "string" && value.trim())
      .map((value) => value.trim())
      .join(" ")
      .slice(0, 200) || "Контакт";
    const payload = { name };
    if (nonEmptyString(contact.vcard)) payload.vcf_info = contact.vcard;
    if (nonEmptyString(contact.phone_number)) payload.vcf_phone = contact.phone_number;
    attachments.push({ type: "contact", payload });
  }
  return attachments;
}

export const MAX_MESSAGE_TEXT_LIMIT = 4000;
export const MAX_VISUAL_ATTACHMENTS_PER_MESSAGE = 12;

function textChunks(value, limit) {
  const text = String(value || "");
  if (!text) return [""];
  const chunks = [];
  let offset = 0;
  while (offset < text.length) {
    let end = Math.min(offset + limit, text.length);
    if (end < text.length) {
      const newline = text.lastIndexOf("\n", end - 1);
      const space = text.lastIndexOf(" ", end - 1);
      const naturalBreak = Math.max(newline, space);
      if (naturalBreak >= offset + Math.floor(limit * 0.6)) end = naturalBreak + 1;
      if (
        end > offset
        && /[\uD800-\uDBFF]/.test(text[end - 1])
        && /[\uDC00-\uDFFF]/.test(text[end] || "")
      ) {
        end -= 1;
      }
    }
    chunks.push(text.slice(offset, end));
    offset = end;
  }
  return chunks;
}

function escapeMaxHtmlText(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function textWithSupplements(text, supplements) {
  return [String(text || ""), ...supplements]
    .filter((part) => part.length)
    .join("\n\n");
}

export function splitMaxPayload(payload = {}, limit = MAX_MESSAGE_TEXT_LIMIT) {
  const normalizedLimit = Math.max(1, Number.parseInt(String(limit), 10) || MAX_MESSAGE_TEXT_LIMIT);
  const supplements = (Array.isArray(payload.supplements) ? payload.supplements : [])
    .filter((item) => typeof item === "string" && item.length);
  const formattedSupplements = payload.format === "html"
    ? supplements.map(escapeMaxHtmlText)
    : supplements;
  const formattedText = textWithSupplements(payload.text, formattedSupplements);
  const plainText = textWithSupplements(
    typeof payload.plainText === "string" ? payload.plainText : payload.text,
    supplements
  );
  const usePlainFallback = Boolean(payload.format) && formattedText.length > normalizedLimit;
  const sourceText = usePlainFallback
    ? plainText
    : formattedText;
  const chunks = textChunks(sourceText, normalizedLimit);
  const attachments = Array.isArray(payload.attachments)
    ? payload.attachments.filter(Boolean)
    : [];
  const keyboards = attachments.filter((item) => item?.type === "inline_keyboard").slice(0, 1);
  const media = attachments.filter((item) => item?.type !== "inline_keyboard");
  const allVisual = media.every((item) => ["image", "video"].includes(item?.type));
  const mediaBatches = [];
  if (allVisual) {
    let offset = 0;
    while (offset < media.length) {
      const capacity = offset === 0 && keyboards.length
        ? MAX_VISUAL_ATTACHMENTS_PER_MESSAGE - keyboards.length
        : MAX_VISUAL_ATTACHMENTS_PER_MESSAGE;
      mediaBatches.push(media.slice(offset, offset + capacity));
      offset += capacity;
    }
  } else {
    // File, audio, sticker and contact attachment requests have exclusive or
    // platform-dependent limits. Sending each one separately is the safe MAX
    // representation and prevents a valid Telegram album from being rejected.
    for (const item of media) mediaBatches.push([item]);
  }

  const textPayloads = chunks.map((text) => ({
    text,
    format: usePlainFallback ? null : payload.format || null,
    attachments: []
  }));
  const hasText = textPayloads.some((item) => item.text);
  const keyboardMustBeSeparate = keyboards.length > 0 && !allVisual && media.length > 0;

  if (keyboardMustBeSeparate) {
    if (!hasText) textPayloads[0].text = "(вложения)";
    textPayloads[0].attachments.push(...keyboards);
  } else if (keyboards.length && !(allVisual && media.length)) {
    textPayloads[0].attachments.push(...keyboards);
  }

  const result = textPayloads;
  for (let index = 0; index < mediaBatches.length; index += 1) {
    const batch = mediaBatches[index];
    const canUseFirstText = index === 0
      && !keyboardMustBeSeparate
      && result[0]
      && result[0].attachments.length === 0;
    if (canUseFirstText) {
      result[0].attachments.push(...batch);
      if (keyboards.length && allVisual) result[0].attachments.push(...keyboards);
    } else {
      result.push({ text: "", format: null, attachments: batch });
    }
  }
  return result.filter((item) => item.text || item.attachments.length);
}

export async function mapSequential(values = [], mapper) {
  const results = [];
  for (let index = 0; index < values.length; index += 1) {
    results.push(await mapper(values[index], index));
  }
  return results;
}

export function telegramDocumentUploadDescriptor(document = {}, messageId = "") {
  return {
    fileId: document.file_id,
    type: "file",
    filename: document.file_name || `document-${messageId}`,
    mimeType: document.mime_type || "application/octet-stream"
  };
}

export function telegramMessageIdentity(message = {}) {
  return String(
    message.document?.file_unique_id
      || message.video?.file_unique_id
      || message.animation?.file_unique_id
      || message.audio?.file_unique_id
      || message.voice?.file_unique_id
      || message.sticker?.file_unique_id
      || message.photo?.at(-1)?.file_unique_id
      || message.media_group_id
      || message.message_id
      || ""
  );
}
