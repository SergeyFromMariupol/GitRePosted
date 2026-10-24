const PUBLIC_ACCESS_DISABLED = "Публичный доступ сейчас выключен владельцем сервиса.";

function accountIdOf(access) {
  const accountId = access?.account?.id;
  if (!accountId) throw new Error("Аккаунт пользователя не найден.");
  return accountId;
}

export function assertPublicAccountAccess(access, publicEnabled) {
  accountIdOf(access);
  if (access.blocked) {
    throw new Error(access.reason || "Доступ заблокирован владельцем сервиса.");
  }
  if (String(publicEnabled) !== "1") throw new Error(PUBLIC_ACCESS_DISABLED);
  return access.account;
}

export async function ownedRouteAccount(query, accountAccess, platform, userId, routeId) {
  const access = await accountAccess(platform, userId);
  const accountId = accountIdOf(access);
  if (access.blocked) {
    throw new Error(access.reason || "Доступ заблокирован владельцем сервиса.");
  }
  const rows = await query(
    "SELECT id FROM repost_routes WHERE id = ? AND account_id = ? LIMIT 1",
    [String(routeId), accountId]
  );
  if (!rows[0]) throw new Error("Пересылка не найдена.");
  return access.account;
}

export async function grantAccountChannelOwnership(query, linkedAccount, platform, userId, chatId) {
  const account = await linkedAccount(platform, userId, true);
  if (!account?.id) throw new Error("Аккаунт пользователя не найден.");
  const normalizedChatId = String(chatId);
  const ownerRows = await query(
    "SELECT account_id, is_blocked, block_reason FROM account_channels WHERE platform = ? AND chat_id = ? LIMIT 1",
    [platform, normalizedChatId]
  );
  if (ownerRows[0] && String(ownerRows[0].account_id) !== String(account.id)) {
    throw new Error("Этот канал уже закреплён за другим пользователем GitRePosted.");
  }
  if (ownerRows[0]?.is_blocked) {
    throw new Error(ownerRows[0].block_reason || "Этот канал заблокирован владельцем сервиса.");
  }
  await query(
    "INSERT IGNORE INTO account_channels (account_id, platform, chat_id) VALUES (?, ?, ?)",
    [account.id, platform, normalizedChatId]
  );
  const confirmedRows = await query(
    "SELECT account_id, is_blocked, block_reason FROM account_channels WHERE platform = ? AND chat_id = ? LIMIT 1",
    [platform, normalizedChatId]
  );
  if (!confirmedRows[0] || String(confirmedRows[0].account_id) !== String(account.id)) {
    throw new Error("Этот канал уже закреплён за другим пользователем GitRePosted.");
  }
  if (confirmedRows[0].is_blocked) {
    throw new Error(confirmedRows[0].block_reason || "Этот канал заблокирован владельцем сервиса.");
  }
  return account;
}

function identityColumns(platform) {
  if (platform === "telegram") {
    return {
      identityColumn: "telegram_user_id",
      blockedColumn: "telegram_blocked",
      otherIdentityColumn: "max_user_id"
    };
  }
  if (platform === "max") {
    return {
      identityColumn: "max_user_id",
      blockedColumn: "max_blocked",
      otherIdentityColumn: "telegram_user_id"
    };
  }
  throw new Error("Неизвестная платформа аккаунта.");
}

function accountIsBlocked(account, platform) {
  const { blockedColumn } = identityColumns(platform);
  return Boolean(account?.is_blocked || account?.[blockedColumn]);
}

async function detachIdentityToStandaloneAccount(query, account, platform) {
  const {
    identityColumn,
    blockedColumn,
    otherIdentityColumn
  } = identityColumns(platform);
  const detachedUserId = account?.[identityColumn];
  if (!detachedUserId) return false;
  const otherBlockedColumn = blockedColumn === "telegram_blocked"
    ? "max_blocked"
    : "telegram_blocked";
  const globallyBlocked = account.is_blocked ? 1 : 0;
  const platformBlocked = account[blockedColumn] ? 1 : 0;
  const reason = globallyBlocked || platformBlocked ? account.block_reason || null : null;

  await query(
    `UPDATE linked_accounts
     SET ${identityColumn} = NULL,
         ${blockedColumn} = 0,
         block_reason = CASE
           WHEN is_blocked = 0 AND ${otherBlockedColumn} = 0 THEN NULL
           ELSE block_reason
         END
     WHERE id = ?`,
    [account.id]
  );
  await query(
    `INSERT INTO linked_accounts
       (${identityColumn}, is_blocked, telegram_blocked, max_blocked, block_reason)
     VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       is_blocked = GREATEST(is_blocked, VALUES(is_blocked)),
       ${blockedColumn} = GREATEST(${blockedColumn}, VALUES(${blockedColumn})),
       block_reason = COALESCE(block_reason, VALUES(block_reason))`,
    [
      String(detachedUserId),
      globallyBlocked,
      platform === "telegram" ? platformBlocked : 0,
      platform === "max" ? platformBlocked : 0,
      reason
    ]
  );
  return true;
}

export async function unlinkLinkedAccountCounterpart(
  query,
  platform,
  userId,
  resetConfiguration,
  expectedCounterpartUserId = undefined
) {
  const source = identityColumns(platform);
  const targetPlatform = platform === "max" ? "telegram" : "max";
  const target = identityColumns(targetPlatform);
  const rows = await query(
    `SELECT id, telegram_user_id, max_user_id, is_blocked,
            telegram_blocked, max_blocked, block_reason
     FROM linked_accounts WHERE ${source.identityColumn} = ? LIMIT 1 FOR UPDATE`,
    [String(userId)]
  );
  const account = rows[0];
  if (!account?.[target.identityColumn]) return false;
  if (
    expectedCounterpartUserId !== undefined
    && String(account[target.identityColumn]) !== String(expectedCounterpartUserId)
  ) {
    return null;
  }
  if (accountIsBlocked(account, platform)) {
    throw new Error(account.block_reason || "Доступ заблокирован владельцем сервиса.");
  }
  await resetConfiguration(account.id);
  await query("DELETE FROM account_link_codes WHERE account_id = ?", [account.id]);
  await detachIdentityToStandaloneAccount(query, account, targetPlatform);
  return true;
}

export async function consumeAccountLinkCodeTransaction(query, platform, userId, code, resetConfiguration) {
  const current = identityColumns(platform);
  const rows = await query(
    `SELECT c.account_id, c.source_platform,
            a.telegram_user_id, a.max_user_id, a.is_blocked,
            a.telegram_blocked, a.max_blocked, a.block_reason
     FROM account_link_codes c
     JOIN linked_accounts a ON a.id = c.account_id
     WHERE c.code = ? AND c.expires_at > NOW()
     LIMIT 1 FOR UPDATE`,
    [String(code)]
  );
  const link = rows[0];
  if (!link) return { status: "invalid" };
  if (link.source_platform === platform) {
    return { status: "wrong_platform", sourcePlatform: link.source_platform };
  }
  if (accountIsBlocked(link, link.source_platform)) {
    return {
      status: "blocked",
      reason: link.block_reason || "Доступ заблокирован владельцем сервиса."
    };
  }

  const existingRows = await query(
    `SELECT id, telegram_user_id, max_user_id, is_blocked,
            telegram_blocked, max_blocked, block_reason
     FROM linked_accounts WHERE ${current.identityColumn} = ? LIMIT 1 FOR UPDATE`,
    [String(userId)]
  );
  const existing = existingRows[0];
  if (existing && accountIsBlocked(existing, platform)) {
    return {
      status: "blocked",
      reason: existing.block_reason || "Доступ заблокирован владельцем сервиса."
    };
  }
  if (existing && String(existing.id) !== String(link.account_id)) {
    if (existing[current.otherIdentityColumn]) {
      return { status: "already_linked" };
    }
    const occupied = await query(`SELECT
      (SELECT COUNT(*) FROM account_channels WHERE account_id = ?) AS channels,
      (SELECT COUNT(*) FROM repost_routes WHERE account_id = ?) AS routes,
      (SELECT COUNT(*) FROM bridges WHERE account_id = ?) AS bridges`, [
      existing.id,
      existing.id,
      existing.id
    ]);
    if (
      Number(occupied[0]?.channels || 0)
      || Number(occupied[0]?.routes || 0)
      || Number(occupied[0]?.bridges || 0)
    ) {
      return { status: "occupied" };
    }
    await query("DELETE FROM account_link_codes WHERE account_id = ?", [existing.id]);
    await query("DELETE FROM linked_accounts WHERE id = ?", [existing.id]);
  }

  const oldUserId = link[current.identityColumn];
  if (oldUserId && String(oldUserId) !== String(userId)) {
    await resetConfiguration(link.account_id);
    await detachIdentityToStandaloneAccount(query, {
      ...link,
      id: link.account_id
    }, platform);
  }
  const otherBlockedColumn = current.blockedColumn === "telegram_blocked"
    ? "max_blocked"
    : "telegram_blocked";
  await query(
    `UPDATE linked_accounts
     SET ${current.identityColumn} = ?,
         ${current.blockedColumn} = 0,
         block_reason = CASE
           WHEN is_blocked = 0 AND ${otherBlockedColumn} = 0 THEN NULL
           ELSE block_reason
         END
     WHERE id = ?`,
    [String(userId), link.account_id]
  );
  await query("DELETE FROM account_link_codes WHERE account_id = ?", [link.account_id]);
  return { status: "linked", accountId: link.account_id };
}

export async function upsertRepostRoute(query, proposedId, accountId, sourcePlatform, sourceChatId, enabled = true) {
  await query(
    `INSERT INTO repost_routes (id, account_id, source_platform, source_chat_id, enabled)
     VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), updated_at = CURRENT_TIMESTAMP`,
    [proposedId, accountId, sourcePlatform, String(sourceChatId), enabled ? 1 : 0]
  );
  const rows = await query(
    `SELECT id FROM repost_routes
     WHERE account_id = ? AND source_platform = ? AND source_chat_id = ?
     LIMIT 1 FOR UPDATE`,
    [accountId, sourcePlatform, String(sourceChatId)]
  );
  if (!rows[0]?.id) throw new Error("Не удалось сохранить пересылку.");
  return String(rows[0].id);
}

export async function syncRepostRouteTargets(query, routeId, targets) {
  const normalizedRouteId = String(routeId || "");
  if (!normalizedRouteId) throw new Error("Не указан маршрут пересылки.");
  const desired = new Map();
  for (const target of Array.isArray(targets) ? targets : []) {
    const platform = String(target?.platform || "");
    const chatId = String(target?.chat_id || "");
    if (!["telegram", "max"].includes(platform) || !chatId) continue;
    desired.set(`${platform}:${chatId}`, { platform, chatId });
  }
  const existing = await query(
    `SELECT id, platform, chat_id
     FROM repost_route_targets WHERE route_id = ?
     ORDER BY id FOR UPDATE`,
    [normalizedRouteId]
  );
  const existingKeys = new Set();
  for (const target of existing) {
    const key = `${target.platform}:${target.chat_id}`;
    if (desired.has(key)) {
      existingKeys.add(key);
      continue;
    }
    await query(
      "DELETE FROM repost_route_targets WHERE id = ? AND route_id = ?",
      [target.id, normalizedRouteId]
    );
  }
  for (const [key, target] of desired) {
    if (existingKeys.has(key)) continue;
    await query(
      "INSERT IGNORE INTO repost_route_targets (route_id, platform, chat_id) VALUES (?, ?, ?)",
      [normalizedRouteId, target.platform, target.chatId]
    );
  }
}

export async function retireLegacyRouteSource(query, accountId, sourcePlatform, sourceChatId) {
  const chatId = String(sourceChatId);
  if (sourcePlatform === "telegram") {
    await query(
      `UPDATE bridges SET direction = 'max_to_tg', updated_at = CURRENT_TIMESTAMP
       WHERE account_id = ? AND telegram_chat_id = ? AND direction = 'both'`,
      [accountId, chatId]
    );
    await query(
      "DELETE FROM bridges WHERE account_id = ? AND telegram_chat_id = ? AND direction = 'tg_to_max'",
      [accountId, chatId]
    );
    return;
  }
  if (sourcePlatform === "max") {
    await query(
      `UPDATE bridges SET direction = 'tg_to_max', updated_at = CURRENT_TIMESTAMP
       WHERE account_id = ? AND max_chat_id = ? AND direction = 'both'`,
      [accountId, chatId]
    );
    await query(
      "DELETE FROM bridges WHERE account_id = ? AND max_chat_id = ? AND direction = 'max_to_tg'",
      [accountId, chatId]
    );
    return;
  }
  throw new Error("Неизвестная платформа источника пересылки.");
}

export async function deleteRouteAndReleaseUnusedChannels(query, routeId, accountId) {
  const normalizedRouteId = String(routeId);
  const accountRows = await query(
    "SELECT id FROM linked_accounts WHERE id = ? LIMIT 1 FOR UPDATE",
    [accountId]
  );
  if (!accountRows[0]) return false;
  const routes = await query(
    `SELECT source_platform, source_chat_id
     FROM repost_routes WHERE id = ? AND account_id = ? LIMIT 1 FOR UPDATE`,
    [normalizedRouteId, accountId]
  );
  const route = routes[0];
  if (!route) return false;
  const targets = await query(
    "SELECT platform, chat_id FROM repost_route_targets WHERE route_id = ? FOR UPDATE",
    [normalizedRouteId]
  );
  await retireLegacyRouteSource(
    query,
    accountId,
    String(route.source_platform),
    String(route.source_chat_id)
  );
  await query("DELETE FROM repost_route_targets WHERE route_id = ?", [normalizedRouteId]);
  await query(
    "DELETE FROM repost_routes WHERE id = ? AND account_id = ?",
    [normalizedRouteId, accountId]
  );

  const candidates = new Map();
  for (const candidate of [
    { platform: route.source_platform, chat_id: route.source_chat_id },
    ...targets
  ]) {
    const platform = String(candidate.platform || "");
    const chatId = String(candidate.chat_id || "");
    if (!["telegram", "max"].includes(platform) || !chatId) continue;
    candidates.set(`${platform}:${chatId}`, { platform, chatId });
  }

  for (const candidate of candidates.values()) {
    const ownership = await query(
      `SELECT is_blocked FROM account_channels
       WHERE account_id = ? AND platform = ? AND chat_id = ?
       LIMIT 1 FOR UPDATE`,
      [accountId, candidate.platform, candidate.chatId]
    );
    if (!ownership[0] || ownership[0].is_blocked) continue;
    const bridgeColumn = candidate.platform === "max" ? "max_chat_id" : "telegram_chat_id";
    const sourceReferences = await query(
      `SELECT COUNT(*) AS total FROM repost_routes
       WHERE account_id = ? AND source_platform = ? AND source_chat_id = ?`, [
      accountId,
      candidate.platform,
      candidate.chatId
    ]);
    const targetReferences = await query(
      `SELECT COUNT(*) AS total
       FROM repost_route_targets t
       JOIN repost_routes r ON r.id = t.route_id
       WHERE r.account_id = ? AND t.platform = ? AND t.chat_id = ?`, [
      accountId,
      candidate.platform,
      candidate.chatId
    ]);
    const bridgeReferences = await query(
      `SELECT COUNT(*) AS total FROM bridges
       WHERE account_id = ? AND ${bridgeColumn} = ?`, [
      accountId,
      candidate.chatId
    ]);
    const total = Number(sourceReferences[0]?.total || 0)
      + Number(targetReferences[0]?.total || 0)
      + Number(bridgeReferences[0]?.total || 0);
    if (total === 0) {
      await query(
        "DELETE FROM account_channels WHERE account_id = ? AND platform = ? AND chat_id = ? AND is_blocked = 0",
        [accountId, candidate.platform, candidate.chatId]
      );
    }
  }
  return true;
}
