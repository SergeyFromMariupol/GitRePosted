const TRANSFER_TTL_MS = 10 * 60 * 1000;

function platformFields(platform) {
  if (platform === "telegram") return { table: "telegram_users", identity: "telegram_user_id", other: "max_user_id", counterpart: "max" };
  if (platform === "max") return { table: "max_users", identity: "max_user_id", other: "telegram_user_id", counterpart: "telegram" };
  throw new TypeError("Неизвестная платформа аккаунта.");
}

function invalid(message) {
  const error = new Error(message);
  error.code = "ACCOUNT_TRANSFER_INVALID";
  return error;
}

function payloadOf(value) {
  if (value && typeof value === "object") return value;
  try { return JSON.parse(value || "{}"); } catch { return {}; }
}

function permissionsOf(value) {
  const parsed = Array.isArray(value) ? value : payloadOf(value);
  return Array.isArray(parsed) ? parsed.filter((item) => typeof item === "string") : [];
}

function assertTransferAccounts(source, target, fields) {
  if (!source || !target) throw invalid("Аккаунт не найден. Новый аккаунт должен сначала запустить этого бота командой /start.");
  if (String(source.id) === String(target.id)) throw invalid("Выберите другой аккаунт для переноса.");
  // Moving configuration must never remove an operator's restriction on either identity.
  if ([source, target].some((account) => account.is_blocked || account.telegram_blocked || account.max_blocked)) {
    throw invalid("Перенос заблокирован владельцем сервиса. Обратитесь к нему для проверки доступа.");
  }
  if (source[fields.other] && target[fields.other]
    && String(source[fields.other]) !== String(target[fields.other])) {
    const name = fields.counterpart === "max" ? "МАКС" : "Telegram";
    throw invalid(`У получателя уже связан другой аккаунт ${name}. Для переноса всей связи выберите получателя без другой связки или обратитесь к владельцу сервиса. Не отвязывайте аккаунты через сброс настроек.`);
  }
}

async function lockAccounts(query, fields, sourceUserId, targetUserId) {
  const rows = await query(
    `SELECT id, telegram_user_id, max_user_id, is_blocked, telegram_blocked, max_blocked
     FROM linked_accounts WHERE ${fields.identity} IN (?, ?) ORDER BY id FOR UPDATE`,
    [String(sourceUserId), String(targetUserId)]
  );
  const source = rows.find((row) => String(row[fields.identity]) === String(sourceUserId));
  const target = rows.find((row) => String(row[fields.identity]) === String(targetUserId));
  assertTransferAccounts(source, target, fields);
  return { source, target };
}

async function lockUsers(query, fields, sourceUserId, targetUserId) {
  const rows = await query(
    `SELECT ${fields.identity} AS user_id, username, first_name, is_admin, permissions, state, state_payload${fields.table === "max_users" ? ", chat_id" : ""}
     FROM ${fields.table} WHERE ${fields.identity} IN (?, ?) ORDER BY ${fields.identity} FOR UPDATE`,
    [String(sourceUserId), String(targetUserId)]
  );
  const source = rows.find((row) => String(row.user_id) === String(sourceUserId));
  const target = rows.find((row) => String(row.user_id) === String(targetUserId));
  if (!source || !target || (fields.table === "max_users" && !target.chat_id)) {
    throw invalid("Новый аккаунт должен сначала запустить этого бота командой /start.");
  }
  return { source, target };
}

async function transferCounts(query, accountId) {
  const rows = await query(`SELECT
    (SELECT COUNT(*) FROM account_channels WHERE account_id = ?) AS channels,
    (SELECT COUNT(*) FROM repost_routes WHERE account_id = ?) AS routes,
    (SELECT COUNT(*) FROM bridges WHERE account_id = ?) AS bridges`, [accountId, accountId, accountId]);
  return Object.fromEntries(["channels", "routes", "bridges"].map((key) => [key, Number(rows[0]?.[key] || 0)]));
}

function assertRecipientConsent(user, token, now) {
  const consent = payloadOf(user?.state_payload);
  if (user?.state !== "account_transfer_receive"
    || !/^[a-f0-9]{24}$/.test(String(token || "")) || consent.token !== token
    || !Number.isFinite(consent.expiresAt) || consent.expiresAt <= now) {
    throw invalid("На новом аккаунте откройте «Перенос данных» → «Получить данные». Отправьте сюда ID или @username получателя и его код через пробел. Код действует 10 минут.");
  }
}

export async function allowAccountTransferReceipt(query, platform, userId, { token, now = Date.now() } = {}) {
  const fields = platformFields(platform);
  if (!/^[a-f0-9]{24}$/.test(String(token || ""))) throw new TypeError("Invalid recipient authorization token.");
  const rows = await query(
    `SELECT id, is_blocked, telegram_blocked, max_blocked FROM linked_accounts WHERE ${fields.identity} = ? LIMIT 1 FOR UPDATE`,
    [String(userId)]
  );
  if (!rows[0] || rows[0].is_blocked || rows[0].telegram_blocked || rows[0].max_blocked) {
    throw invalid("Перенос заблокирован владельцем сервиса. Обратитесь к нему для проверки доступа.");
  }
  const consent = { token, expiresAt: now + TRANSFER_TTL_MS };
  await query(`UPDATE ${fields.table} SET state = 'account_transfer_receive', state_payload = ? WHERE ${fields.identity} = ?`, [JSON.stringify(consent), String(userId)]);
  return consent;
}

export async function resolveTransferRecipient(query, platform, input) {
  const fields = platformFields(platform);
  const value = String(input || "").trim();
  const numeric = /^[1-9]\d{0,18}$/.test(value);
  if (!numeric && !/^@[a-z\d_]{3,64}$/i.test(value)) {
    throw invalid("Отправьте числовой ID или @username нового аккаунта в этом боте.");
  }
  const rows = await query(
    `SELECT ${fields.identity} AS user_id, username, first_name${platform === "max" ? ", chat_id" : ""}
     FROM ${fields.table} WHERE ${numeric ? `${fields.identity} = ?` : "LOWER(username) = LOWER(?)"} LIMIT 2`,
    [numeric ? value : value.slice(1)]
  );
  if (rows.length > 1) throw invalid("Найдено несколько профилей с этим @username. Укажите числовой ID получателя.");
  if (!rows[0] || (platform === "max" && !rows[0].chat_id)) {
    throw invalid("Получатель не найден. Новый аккаунт должен сначала запустить этого бота командой /start. Затем укажите его ID или @username.");
  }
  return rows[0];
}

// The caller owns the transaction, including its fenced bot receipt result.
export async function prepareAccountTransfer(query, platform, sourceUserId, targetUserId, { token, receiverToken, now = Date.now() } = {}) {
  const fields = platformFields(platform);
  if (!/^[a-f0-9]{24}$/.test(String(token || ""))) throw new TypeError("Invalid transfer confirmation token.");
  const accounts = await lockAccounts(query, fields, sourceUserId, targetUserId);
  const users = await lockUsers(query, fields, sourceUserId, targetUserId);
  assertRecipientConsent(users.target, receiverToken, now);
  const counts = await transferCounts(query, accounts.source.id);
  const proposal = {
    token,
    receiverToken,
    sourceAccountId: String(accounts.source.id),
    targetAccountId: String(accounts.target.id),
    targetUserId: String(targetUserId),
    sourceOtherId: String(accounts.source[fields.other] || ""),
    targetOtherId: String(accounts.target[fields.other] || ""),
    targetLabel: Array.from(String(users.target.first_name || users.target.username || targetUserId)
      .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ").replace(/\s+/gu, " ").trim()).slice(0, 120).join(""),
    counterpartPlatform: fields.counterpart,
    counterpartUserId: String(accounts.source[fields.other] || ""),
    expiresAt: now + TRANSFER_TTL_MS,
    ...counts
  };
  await query(
    `UPDATE ${fields.table} SET state = 'account_transfer_confirm', state_payload = ? WHERE ${fields.identity} = ?`,
    [JSON.stringify(proposal), String(sourceUserId)]
  );
  return proposal;
}

export async function confirmAccountTransfer(query, platform, sourceUserId, token, { now = Date.now() } = {}) {
  const fields = platformFields(platform);
  // Read without a lock to discover the recipient, then re-read under the account/user locks.
  const initialRows = await query(`SELECT state, state_payload FROM ${fields.table} WHERE ${fields.identity} = ? LIMIT 1`, [String(sourceUserId)]);
  const initial = payloadOf(initialRows[0]?.state_payload);
  if (initialRows[0]?.state !== "account_transfer_confirm" || initial.token !== token || !/^[a-f0-9]{24}$/.test(String(token))) {
    throw invalid("Подтверждение переноса устарело. Откройте «Перенос данных» заново.");
  }
  const accounts = await lockAccounts(query, fields, sourceUserId, initial.targetUserId);
  const users = await lockUsers(query, fields, sourceUserId, initial.targetUserId);
  const proposal = payloadOf(users.source.state_payload);
  assertRecipientConsent(users.target, proposal.receiverToken, now);
  if (users.source.state !== "account_transfer_confirm" || proposal.token !== token
    || !Number.isFinite(proposal.expiresAt) || proposal.expiresAt <= now
    || String(proposal.targetUserId) !== String(initial.targetUserId)
    || String(accounts.source.id) !== proposal.sourceAccountId
    || String(accounts.target.id) !== proposal.targetAccountId
    || String(accounts.source[fields.other] || "") !== proposal.sourceOtherId
    || String(accounts.target[fields.other] || "") !== proposal.targetOtherId) {
    throw invalid("Подтверждение истекло или связь аккаунтов изменилась. Откройте «Перенос данных» заново.");
  }
  const conflicts = await query(
    `SELECT s.id FROM repost_routes s JOIN repost_routes t
       ON t.source_platform = s.source_platform AND t.source_chat_id = s.source_chat_id
     WHERE s.account_id = ? AND t.account_id = ? LIMIT 1 FOR UPDATE`,
    [accounts.source.id, accounts.target.id]
  );
  if (conflicts.length) throw invalid("Есть конфликт маршрутов одного канала. Обратитесь к владельцу сервиса; данные не изменены.");
  const counts = await transferCounts(query, accounts.source.id);
  if (accounts.source[fields.other]) {
    await query(`UPDATE linked_accounts SET ${fields.other} = NULL WHERE id = ?`, [accounts.source.id]);
    await query(`UPDATE linked_accounts SET ${fields.other} = ? WHERE id = ?`, [accounts.source[fields.other], accounts.target.id]);
  }
  const counterpartUserId = accounts.source[fields.other] || accounts.target[fields.other];
  if (counterpartUserId) {
    const other = platformFields(fields.counterpart);
    await query(`UPDATE ${other.table} SET state = NULL, state_payload = NULL WHERE ${other.identity} = ?`, [counterpartUserId]);
  }
  for (const table of ["account_channels", "repost_routes", "bridges"]) {
    await query(`UPDATE ${table} SET account_id = ? WHERE account_id = ?`, [accounts.target.id, accounts.source.id]);
  }
  const permissions = [...new Set([...permissionsOf(users.target.permissions), ...permissionsOf(users.source.permissions)])];
  await query(
    `UPDATE ${fields.table} SET is_admin = ?, permissions = ?, state = NULL, state_payload = NULL WHERE ${fields.identity} = ?`,
    [users.source.is_admin || users.target.is_admin ? 1 : 0, JSON.stringify(permissions), String(proposal.targetUserId)]
  );
  await query(
    `UPDATE ${fields.table} SET is_admin = 0, permissions = JSON_ARRAY(), state = NULL, state_payload = NULL WHERE ${fields.identity} = ?`,
    [String(sourceUserId)]
  );
  await query("DELETE FROM account_link_codes WHERE account_id IN (?, ?)", [accounts.source.id, accounts.target.id]);
  // Routes and target IDs, durable routing snapshots, leases and delivery history stay intact.
  return { ...proposal, ...counts, status: "transferred" };
}
