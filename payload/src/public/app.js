const state = {
  currentBot: localStorage.getItem("reposted_bot_view") || "telegram",
  currentSection: "users",
  page: 1,
  perPage: 10,
  totalPages: 1,
  channelsPage: 1,
  adminsPage: 1,
  channels: { telegram: [], max: [] },
  service: null,
  bridges: [],
  bridgeMap: new Map(),
  system: null,
  config: null,
  permissions: [],
  adminUsers: [],
  accounts: [],
  passkeys: [],
  selectedBridgeId: null
};

const $ = (id) => document.getElementById(id);
const $$ = (selector) => [...document.querySelectorAll(selector)];
let toastTimer = null;
let hcaptchaEnabled = true;
let hcaptchaScriptPromise = null;
let hcaptchaWidgetId = null;

function bufferToBase64Url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBuffer(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function botLabel(mode = state.currentBot) {
  return mode === "max" ? "МАКС" : "Telegram";
}

function setStatus(message, type = null) {
  const statusBox = $("statusBox");
  if (statusBox) statusBox.textContent = message;
  const toast = $("adminToast");
  if (!toast) return;
  const resolvedType = type || (/ошиб|невер|не удалось/i.test(message) ? "error" : "success");
  $("adminToastText").textContent = message;
  toast.classList.remove("success", "error", "info", "show");
  toast.classList.add(resolvedType);
  const icon = toast.querySelector(".admin-toast-icon i");
  icon.className = `fa-solid ${resolvedType === "error" ? "fa-xmark" : resolvedType === "info" ? "fa-circle-info" : "fa-check"}`;
  requestAnimationFrame(() => toast.classList.add("show"));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), resolvedType === "error" ? 6000 : 3500);
}

function closeToast() {
  clearTimeout(toastTimer);
  $("adminToast")?.classList.remove("show");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: {
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...(options.headers || {})
    }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    const error = new Error(data.message || data.error || `HTTP ${response.status}`);
    error.status = response.status;
    error.code = data.error;
    throw error;
  }
  return data;
}

function passkeySupported() {
  return Boolean(window.PublicKeyCredential && navigator.credentials);
}

function normalizeCreationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    user: { ...options.user, id: base64UrlToBuffer(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((item) => ({
      ...item,
      id: base64UrlToBuffer(item.id)
    }))
  };
}

function normalizeRequestOptions(options) {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((item) => ({
      ...item,
      id: base64UrlToBuffer(item.id)
    }))
  };
}

function serializePasskeyAssertion(credential) {
  return {
    credential_id: bufferToBase64Url(credential.rawId),
    response: {
      clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
      authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
      signature: bufferToBase64Url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : null
    }
  };
}

function showLogin(message = "") {
  document.body.classList.remove("auth-loading");
  document.body.classList.add("login-required");
  $("loginError").textContent = message;
  $("loginPassword").focus();
}

function hideLogin() {
  document.body.classList.remove("auth-loading");
  document.body.classList.remove("login-required");
  $("loginError").textContent = "";
  $("loginPassword").value = "";
}

async function setupHcaptcha() {
  const response = await fetch("/api/auth-config", { credentials: "same-origin" });
  if (!response.ok) throw new Error("Не удалось загрузить настройки входа.");
  const data = await response.json();
  hcaptchaEnabled = data.hcaptcha_enabled !== false;
  const widget = $("hcaptchaWidget");
  widget.dataset.sitekey = data.hcaptcha_sitekey || "";
  $("hcaptchaContainer").classList.toggle("hidden", !hcaptchaEnabled);
  $("loginPasskeyButton").classList.toggle("hidden", !data.passkey_available || !passkeySupported());
  if (hcaptchaEnabled) {
    if (!widget.dataset.sitekey) throw new Error("hCaptcha не настроена.");
    if (!hcaptchaScriptPromise) hcaptchaScriptPromise = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      const timer = setTimeout(() => reject(new Error("hCaptcha не ответила. Обновите страницу и повторите.")), 20000);
      window.gitRePostedHcaptchaReady = () => { clearTimeout(timer); resolve(); };
      script.src = "https://js.hcaptcha.com/1/api.js?onload=gitRePostedHcaptchaReady&render=explicit";
      script.async = true;
      script.onerror = () => { clearTimeout(timer); reject(new Error("Не удалось загрузить hCaptcha.")); };
      document.head.append(script);
    });
    await hcaptchaScriptPromise;
    if (hcaptchaWidgetId === null) hcaptchaWidgetId = window.hcaptcha.render(widget, { sitekey: widget.dataset.sitekey, theme: "dark" });
  }
}

function sectionMeta(section = state.currentSection) {
  const bot = botLabel();
  return {
    dashboard: {
      title: `Панель ${bot}`,
      subtitle: "Состояние и управление выбранным ботом"
    },
    bridges: {
      title: "Пересылки",
      subtitle: "Управление автоматической пересылкой публикаций между Telegram и МАКС"
    },
    channels: {
      title: `Каналы ${bot}`,
      subtitle: "Каналы, где выбранный бот имеет доступ"
    },
    admins: {
      title: `Админы ${bot}`,
      subtitle: "Права, владельцы и доступ к управлению"
    },
    users: {
      title: "Пользователи",
      subtitle: "Связанные аккаунты и модерация доступа"
    },
    config: {
      title: bot === "МАКС" ? "МАКС-бот" : "Telegram-бот",
      subtitle: "Подключение, доступ и состояние бота"
    },
    database: {
      title: "База данных",
      subtitle: "Защищённые параметры подключения"
    },
    security: {
      title: "Безопасность",
      subtitle: "Пароль доступа к веб-админке"
    },

  }[section];
}

function setSection(section) {
  state.currentSection = section;
  const meta = sectionMeta(section);
  $("pageTitle").textContent = meta.title;
  $("pageSubtitle").textContent = meta.subtitle;
  $("statsGrid").classList.toggle("hidden", section !== "dashboard");
  syncServicePanel();
  $$("[data-section]").forEach((node) => node.classList.toggle("hidden", node.dataset.section !== section));
  $$("[data-section-link]").forEach((node) => node.classList.toggle("active",
    node.dataset.sectionLink === section && (!node.dataset.botLink || node.dataset.botLink === state.currentBot)));
  document.body.classList.remove("menu-open");
}

function syncServicePanel() {
  $$('[data-service-bot]').forEach((button) => {
    button.classList.toggle("hidden", button.dataset.serviceBot !== state.currentBot);
  });
}

function bridgeVisibleForBot(row) {
  return true;
}

function botChannels() {
  return state.channels[state.currentBot] || [];
}

function renderMetrics() {
  $("metricBot").textContent = botLabel();
  $("metricChannels").textContent = String(botChannels().length);
  $("metricBridges").textContent = String(state.bridges.filter(bridgeVisibleForBot).length);
  $("metricPage").textContent = `${state.page} / ${state.totalPages}`;
}

function createListItem(title, subtitle, meta = [], actions = []) {
  return `
    <article class="list-item">
      <div class="list-item-head">
        <div>
          <h4 class="list-item-title">${title}</h4>
          <div class="list-item-subtitle">${subtitle}</div>
        </div>
        <div class="list-item-meta">${meta.join("")}</div>
      </div>
      ${actions.length ? `<div class="list-item-actions">${actions.join("")}</div>` : ""}
    </article>
  `;
}

function createBridgeItem(row) {
  const sourceIcon = row.source_platform === "telegram" ? "/assets/telegram.png" : "/assets/max.png";
  const targets = row.targets || [];
  const targetNames = targets.map((target) => `<span class="bridge-target"><img src="${target.platform === "telegram" ? "/assets/telegram.png" : "/assets/max.png"}" alt="">${escapeHtml(target.title || target.chat_id)}</span>`).join('<span class="bridge-target-separator">,</span>');
  return `
    <article class="list-item bridge-item ${String(state.selectedBridgeId) === String(row.id) ? "selected" : ""}">
      <button type="button" class="bridge-summary" data-select-bridge="${escapeHtml(row.id)}">
        <span class="bridge-route">
          <span class="bridge-channel"><img src="${sourceIcon}" alt="">${row.index}. ${escapeHtml(row.source_title)}</span>
          <i class="fa-solid fa-arrow-right bridge-arrow"></i>
          <span class="bridge-targets">${targetNames || "Получатели не выбраны"}</span>
        </span>
        <span class="bridge-summary-meta">
          <span class="status-icon ${row.enabled ? "ok" : "off"}" title="${row.enabled ? "Включено" : "Выключено"}">
            <i class="fa-solid ${row.enabled ? "fa-check" : "fa-xmark"}"></i>
          </span>
          <i class="fa-solid fa-chevron-right bridge-chevron"></i>
        </span>
      </button>
    </article>
  `;
}

function channelOptionValue(platform, chatId) {
  return `${platform}:${chatId}`;
}

function allChannelOptions() {
  return [
    ...state.channels.telegram.map((row, index) => ({ ...row, platform: "telegram", label: `Telegram ${index + 1}. ${row.title}` })),
    ...state.channels.max.map((row, index) => ({ ...row, platform: "max", label: `МАКС ${index + 1}. ${row.title}` }))
  ];
}

function fillRouteSelects() {
  const options = allChannelOptions();
  const html = options.map((row) => `<option value="${escapeHtml(channelOptionValue(row.platform, row.chat_id))}">${escapeHtml(row.label)}</option>`).join("");
  $("sourceChannel").innerHTML = html;
  $("targetChannels").innerHTML = html;
  syncTargetAvailability();
}

function syncTargetAvailability() {
  const source = $("sourceChannel").value;
  [...$("targetChannels").options].forEach((option) => {
    option.disabled = option.value === source;
    if (option.disabled) option.selected = false;
  });
}

function bridgeDirectionText(direction) {
  if (direction === "tg_to_max") return "из Telegram в МАКС";
  if (direction === "max_to_tg") return "из МАКС в Telegram";
  return "в обе стороны";
}

function renderChannels() {
  const platformName = state.currentBot === "telegram" ? "Telegram" : "МАКС";
  const iconPath = state.currentBot === "telegram" ? "/assets/telegram.png" : "/assets/max.png";
  $("channelsPanelTitle").textContent = state.currentBot === "telegram" ? "Каналы Telegram" : "Каналы МАКС";
  const channels = botChannels();
  const totalPages = Math.max(1, Math.ceil(channels.length / state.perPage));
  state.channelsPage = Math.min(state.channelsPage, totalPages);
  const offset = (state.channelsPage - 1) * state.perPage;
  const visibleChannels = channels.slice(offset, offset + state.perPage);
  $("channelsPageLabel").textContent = `${state.channelsPage} из ${totalPages}`;
  $("prevChannelsPage").disabled = state.channelsPage <= 1;
  $("nextChannelsPage").disabled = state.channelsPage >= totalPages;
  $("channelsList").innerHTML = visibleChannels.map((row, index) => createListItem(
    `<span class="channel-title"><img src="${iconPath}" alt="${platformName}"><span>${offset + index + 1}. ${escapeHtml(row.title)}</span></span>`,
    `${escapeHtml(row.chat_id)}${row.username ? ` • @${escapeHtml(row.username)}` : ""}`,
    [
      `<span class="status-icon ${row.is_active ? "ok" : "off"}" title="${row.is_active ? "Активен" : "Выключен"}"><i class="fa-solid ${row.is_active ? "fa-check" : "fa-xmark"}"></i></span>`
    ]
  )).join("") || createListItem("Нет каналов", "Для выбранного бота пока нет найденных каналов.");
}

function renderBridgeList() {
  state.bridgeMap.clear();
  const items = state.bridges.filter(bridgeVisibleForBot);
  $("bridgesList").innerHTML = items.map((row) => {
    state.bridgeMap.set(String(row.id), row);
    return createBridgeItem(row);
  }).join("") || createListItem("Нет пересылок", "Автоматические пересылки пока не настроены.");

  $$("[data-select-bridge]").forEach((button) => {
    button.onclick = () => {
      state.selectedBridgeId = button.dataset.selectBridge;
      renderBridgeList();
    };
  });

  const selected = state.bridgeMap.get(String(state.selectedBridgeId));
  $("selectedBridgeActions").classList.toggle("hidden", !selected);
  if (selected) {
    $("toggleSelectedBridge").innerHTML = `<i class="fa-solid ${selected.enabled ? "fa-bell-slash" : "fa-bell"}"></i>`;
  }
}

function fillBridgeForm(bridge) {
  $("bridgeId").value = bridge?.id || "";
  $("sourceChannel").value = bridge ? channelOptionValue(bridge.source_platform, bridge.source_chat_id) : $("sourceChannel").options[0]?.value || "";
  const selectedTargets = new Set((bridge?.targets || []).map((target) => channelOptionValue(target.platform, target.chat_id)));
  [...$("targetChannels").options].forEach((option) => { option.selected = selectedTargets.has(option.value); });
  syncTargetAvailability();
  $("enabled").checked = bridge ? Boolean(bridge.enabled) : true;
  $("bridgeEditorTitle").textContent = bridge ? `Редактировать: ${bridge.source_title}` : "Новая пересылка";
  $("deleteBridgeTop").classList.toggle("hidden", !bridge);
  $("bridgesBrowser").classList.add("hidden");
  $("bridgeEditor").classList.remove("hidden");
  setSection("bridges");
}

function closeBridgeEditor() {
  $("bridgeEditor").classList.add("hidden");
  $("bridgesBrowser").classList.remove("hidden");
  $("bridgeId").value = "";
  $("deleteBridgeTop").classList.add("hidden");
}

function renderConfig() {
  if (!state.config) return;
  $("cfgTelegramEnabled").checked = Boolean(state.config.telegram.enabled);
  $("cfgMaxEnabled").checked = Boolean(state.config.max.enabled);
  $("cfgRestartNotice").classList.toggle("hidden", !state.config.restart_required);
  $("setupTelegramWebhook").disabled = Boolean(state.config.restart_required) || !state.config.telegram.active_enabled;
  $("setupMaxWebhook").disabled = Boolean(state.config.restart_required) || !state.config.max.active_enabled;
  $("cfgTelegramBotUrl").value = state.config.telegram.bot_url || "";
  $("cfgTelegramPublic").checked = Boolean(state.config.telegram.public_enabled);
  $("cfgMaxBotUrl").value = state.config.max.bot_url || "";
  $("cfgMaxPublic").checked = Boolean(state.config.max.public_enabled);
  $("cfgMaxApiBaseUrl").value = state.config.max.api_base_url || "";
  const protectedBotFields = {
    cfgTelegramToken: state.config.telegram.bot_token_configured,
    cfgTelegramSecret: state.config.telegram.webhook_secret_configured,
    cfgMaxToken: state.config.max.bot_token_configured,
    cfgMaxSecret: state.config.max.webhook_secret_configured
  };
  Object.entries(protectedBotFields).forEach(([id, configured]) => {
    const input = $(id);
    input.value = "";
    input.placeholder = configured ? "Данные указаны" : "Данные не указаны";
  });
  const databaseFields = {
    serverDbHost: state.config.database.host_configured,
    serverDbPort: state.config.database.port_configured,
    serverDbName: state.config.database.name_configured,
    serverDbUser: state.config.database.user_configured,
    serverDbPassword: state.config.database.password_configured
  };
  Object.entries(databaseFields).forEach(([id, configured]) => {
    const input = $(id);
    input.value = "";
    input.placeholder = configured ? "Данные указаны" : "Данные не указаны";
  });

  $("telegramConfigCard").classList.toggle("hidden", state.currentBot !== "telegram");
  $("maxConfigCard").classList.toggle("hidden", state.currentBot !== "max");
  $("configPanelSubtitle").textContent = state.currentBot === "telegram"
    ? "Настройка Telegram бота и общих параметров сервиса."
    : "Настройка МАКС бота и общих параметров сервиса.";
}

function renderPermissions() {
  $("permissionsBox").innerHTML = state.permissions.map((permission) => `
    <label class="permission-chip">
      <span>${escapeHtml(permission.title)}</span>
      <input type="checkbox" data-permission="${escapeHtml(permission.key)}">
    </label>
  `).join("");
}

function clearAdminForm() {
  $("adminUserId").value = "";
  $("adminUserIdView").value = "";
  $("adminUsername").value = "";
  $("adminFirstName").value = "";
  $("adminChatId").value = "";
  $$("[data-permission]").forEach((node) => {
    node.checked = false;
  });
}

function fillAdminForm(user) {
  clearAdminForm();
  $("adminUserId").value = user.user_id || "";
  $("adminUserIdView").value = user.user_id || "";
  $("adminUsername").value = user.username || "";
  $("adminFirstName").value = user.first_name || "";
  $("adminChatId").value = user.chat_id || "";
  const allowed = new Set(user.permissions || []);
  $$("[data-permission]").forEach((node) => {
    node.checked = allowed.has(node.dataset.permission);
  });
  $("adminEditorTitle").textContent = `Редактировать: ${user.first_name || user.username || user.user_id}`;
  $("deleteAdminTop").classList.remove("hidden");
  $("adminsBrowser").classList.add("hidden");
  $("adminEditor").classList.remove("hidden");
}

function openNewAdminEditor() {
  clearAdminForm();
  $("adminEditorTitle").textContent = "Новый администратор";
  $("deleteAdminTop").classList.add("hidden");
  $("adminsBrowser").classList.add("hidden");
  $("adminEditor").classList.remove("hidden");
}

function closeAdminEditor() {
  $("adminEditor").classList.add("hidden");
  $("adminsBrowser").classList.remove("hidden");
  clearAdminForm();
}

function renderAdminUsers() {
  $("adminChatIdWrap").classList.toggle("hidden", state.currentBot !== "max");
  const totalPages = Math.max(1, Math.ceil(state.adminUsers.length / state.perPage));
  state.adminsPage = Math.min(state.adminsPage, totalPages);
  const offset = (state.adminsPage - 1) * state.perPage;
  const visibleUsers = state.adminUsers.slice(offset, offset + state.perPage);
  $("adminsPageLabel").textContent = `${state.adminsPage} из ${totalPages}`;
  $("prevAdminsPage").disabled = state.adminsPage <= 1;
  $("nextAdminsPage").disabled = state.adminsPage >= totalPages;
  $("adminUsersList").innerHTML = visibleUsers.map((user) => `
    <button type="button" class="admin-row" data-admin-edit="${escapeHtml(user.user_id)}">
      <span>
        <strong>${escapeHtml(user.first_name || user.username || user.user_id)}</strong>
        <small>${escapeHtml(user.user_id)}${user.username ? ` • @${escapeHtml(user.username)}` : ""}</small>
      </span>
      <span class="admin-row-meta">
        ${user.is_admin ? `<span class="tag">Админ</span>` : ""}
        <i class="fa-solid fa-chevron-right"></i>
      </span>
    </button>
  `).join("") || createListItem("Нет админов", "По этому боту пока ничего не найдено.");

  $$("[data-admin-edit]").forEach((button) => {
    button.onclick = () => {
      const user = state.adminUsers.find((item) => String(item.user_id) === String(button.dataset.adminEdit));
      if (user) fillAdminForm(user);
    };
  });
}

function renderAccountChannelRows(account, platform) {
  return (account.channels || []).filter((channel) => channel.platform === platform).map((channel) => `
    <div class="account-channel-row"><span><img src="/assets/${platform === "max" ? "max" : "telegram"}.png" alt="">${escapeHtml(channel.title)}</span><span>
      <button data-channel-action="block_channel" data-id="${account.id}" data-platform="${channel.platform}" data-chat="${escapeHtml(channel.chat_id)}" data-blocked="${channel.is_blocked ? "1" : "0"}" class="ghost icon-button" title="${channel.is_blocked ? "Разрешить канал" : "Запретить канал"}"><i class="fa-solid ${channel.is_blocked ? "fa-check" : "fa-ban"}"></i></button>
      <button data-channel-action="delete_channel" data-id="${account.id}" data-platform="${channel.platform}" data-chat="${escapeHtml(channel.chat_id)}" class="danger icon-button" title="Удалить канал и его пересылки"><i class="fa-solid fa-trash"></i></button>
    </span></div>`).join("") || `<div class="empty-channel-list">Каналов пока нет</div>`;
}

function renderAccountRoutes(account) {
  return (account.routes || []).map((route) => {
    const sourceIcon = route.source_platform === "max" ? "max" : "telegram";
    const targets = (route.targets || []).map((target) => `<span><img src="/assets/${target.platform === "max" ? "max" : "telegram"}.png" alt="">${escapeHtml(target.title || target.chat_id)}</span>`).join('<i class="fa-solid fa-plus"></i>');
    return `<div class="account-route-row">
      <div class="account-route-path"><span><img src="/assets/${sourceIcon}.png" alt="">${escapeHtml(route.source_title || route.source_chat_id)}</span><i class="fa-solid fa-arrow-right"></i><span class="account-route-targets">${targets}</span></div>
      <div class="account-route-actions">
        <button data-route-action="toggle" data-route-id="${escapeHtml(route.id)}" class="ghost icon-button" title="${route.enabled ? "Выключить" : "Включить"}"><i class="fa-solid ${route.enabled ? "fa-bell" : "fa-bell-slash"}"></i></button>
        <button data-route-action="delete" data-route-id="${escapeHtml(route.id)}" class="danger icon-button" title="Удалить"><i class="fa-solid fa-trash"></i></button>
      </div>
    </div>`;
  }).join("") || '<div class="empty-channel-list">Пересылок пока нет</div>';
}

function renderAccounts() {
  $("accountsList").innerHTML = state.accounts.map((account) => `
    <article class="list-item account-card">
      <div class="account-summary" data-account-toggle="${account.id}"><div>
        <div class="account-display-names">
          ${account.telegram_user_id ? `<span><img src="/assets/telegram.png" alt="Telegram"><strong>${escapeHtml(account.telegram_name || account.telegram_username || `Telegram ${account.telegram_user_id}`)}</strong></span>` : ""}
          ${account.telegram_user_id && account.max_user_id ? '<span class="account-name-join">и</span>' : ""}
          ${account.max_user_id ? `<span><img src="/assets/max.png" alt="МАКС"><strong>${escapeHtml(account.max_name || account.max_username || `МАКС ${account.max_user_id}`)}</strong></span>` : ""}
        </div>
      </div><div class="account-summary-actions">
        <button data-account-action="block_all" data-id="${account.id}" class="account-block-button ${account.is_blocked ? "is-blocked" : ""}" title="${account.is_blocked ? "Разблокировать полностью" : "Заблокировать полностью"}" aria-label="${account.is_blocked ? "Разблокировать полностью" : "Заблокировать полностью"}"><i class="fa-solid ${account.is_blocked ? "fa-lock-open" : "fa-user-lock"}"></i></button>
        <button data-account-action="block_tg" data-id="${account.id}" class="account-block-button platform-block-button ${account.telegram_blocked ? "is-blocked" : ""}" title="${account.telegram_blocked ? "Разблокировать Telegram" : "Заблокировать Telegram"}" aria-label="${account.telegram_blocked ? "Разблокировать Telegram" : "Заблокировать Telegram"}"><img src="/assets/telegram.png" alt=""><i class="fa-solid fa-ban"></i></button>
        <button data-account-action="block_max" data-id="${account.id}" class="account-block-button platform-block-button ${account.max_blocked ? "is-blocked" : ""}" title="${account.max_blocked ? "Разблокировать МАКС" : "Заблокировать МАКС"}" aria-label="${account.max_blocked ? "Разблокировать МАКС" : "Заблокировать МАКС"}"><img src="/assets/max.png" alt=""><i class="fa-solid fa-ban"></i></button>
        <button data-account-action="delete_bridges" data-id="${account.id}" class="ghost icon-button" title="Удалить все пересылки"><i class="fa-solid fa-link-slash"></i></button>
        <button data-account-action="delete_channel_links" data-id="${account.id}" class="danger icon-button" title="Удалить каналы и пересылки"><i class="fa-solid fa-trash-can"></i></button>
        <i class="fa-solid fa-chevron-down account-chevron"></i>
      </div></div>
      <div class="account-details hidden" data-account-details="${account.id}">
      <div class="account-profile-grid">
        <div class="account-profile-card">
          <div class="account-profile-title"><img src="/assets/telegram.png" alt="Telegram"><strong>Telegram</strong></div>
          <dl><div><dt>Имя</dt><dd>${escapeHtml(account.telegram_name || "Не указано")}</dd></div><div><dt>ID</dt><dd>${escapeHtml(account.telegram_user_id || "Не связан")}</dd></div><div><dt>Ник</dt><dd>${account.telegram_username ? `@${escapeHtml(account.telegram_username)}` : "Не указан"}</dd></div><div><dt>Каналов</dt><dd>${(account.channels || []).filter((channel) => channel.platform === "telegram").length}</dd></div></dl>
        </div>
        <div class="account-profile-card">
          <div class="account-profile-title"><img src="/assets/max.png" alt="МАКС"><strong>МАКС</strong></div>
          <dl><div><dt>Имя</dt><dd>${escapeHtml(account.max_name || "Не указано")}</dd></div><div><dt>ID</dt><dd>${escapeHtml(account.max_user_id || "Не связан")}</dd></div><div><dt>Ник</dt><dd>${account.max_username ? `@${escapeHtml(account.max_username)}` : "Не указан"}</dd></div><div><dt>Каналов</dt><dd>${(account.channels || []).filter((channel) => channel.platform === "max").length}</dd></div></dl>
        </div>
        <div class="account-bridge-total"><span>Пересылок между каналами</span><strong>${account.bridge_count}</strong></div>
      </div>
      <section class="account-routes-block account-subsection">
        <header data-account-section-toggle="routes-${account.id}"><span><i class="fa-solid fa-arrow-right-arrow-left"></i><strong>Пересылки пользователя</strong></span><span class="account-subsection-meta"><b>${(account.routes || []).length}</b><i class="fa-solid fa-chevron-down account-subsection-chevron"></i></span></header>
        <div class="account-routes-list hidden" data-account-section="routes-${account.id}">${renderAccountRoutes(account)}</div>
      </section>
      <div class="account-channel-columns">
        <section class="account-channel-column account-subsection"><header data-account-section-toggle="telegram-${account.id}"><span><img src="/assets/telegram.png" alt="Telegram"><strong>Каналы Telegram</strong></span><span class="account-subsection-meta"><b>${(account.channels || []).filter((channel) => channel.platform === "telegram").length}</b><i class="fa-solid fa-chevron-down account-subsection-chevron"></i></span></header><div class="account-channel-list hidden" data-account-section="telegram-${account.id}">${renderAccountChannelRows(account, "telegram")}</div></section>
        <section class="account-channel-column account-subsection"><header data-account-section-toggle="max-${account.id}"><span><img src="/assets/max.png" alt="МАКС"><strong>Каналы МАКС</strong></span><span class="account-subsection-meta"><b>${(account.channels || []).filter((channel) => channel.platform === "max").length}</b><i class="fa-solid fa-chevron-down account-subsection-chevron"></i></span></header><div class="account-channel-list hidden" data-account-section="max-${account.id}">${renderAccountChannelRows(account, "max")}</div></section>
      </div></div>
    </article>`).join("") || createListItem("Пользователей нет", "Связанные аккаунты появятся после запуска ботов.");
  $$('[data-account-toggle]').forEach((button) => button.onclick = () => {
    const details = document.querySelector(`[data-account-details="${button.dataset.accountToggle}"]`);
    if (!details) return;
    const expanded = !details.classList.toggle("hidden");
    button.classList.toggle("expanded", expanded);
  });
  $$('[data-account-section-toggle]').forEach((header) => header.onclick = () => {
    const content = document.querySelector(`[data-account-section="${header.dataset.accountSectionToggle}"]`);
    if (!content) return;
    const expanded = !content.classList.toggle("hidden");
    header.classList.toggle("expanded", expanded);
  });
  $$('[data-account-action]').forEach((button) => button.onclick = (event) => {
    event.stopPropagation();
    moderateAccount(button);
  });
  $$('[data-channel-action]').forEach((button) => button.onclick = () => moderateChannel(button));
  $$('[data-route-action]').forEach((button) => button.onclick = async () => {
    if (button.dataset.routeAction === "delete") {
      if (!confirm("Удалить пересылку пользователя?")) return;
      await api(`/api/bridges/${button.dataset.routeId}`, { method: "DELETE" });
      setStatus("Пересылка пользователя удалена.");
    } else {
      await api("/api/bridges/toggle", { method: "POST", body: JSON.stringify({ id: button.dataset.routeId }) });
      setStatus("Состояние пересылки пользователя изменено.");
    }
    await loadAccounts();
  });
}

async function loadAccounts() {
  const data = await api("/api/accounts");
  state.accounts = data.accounts || [];
  renderAccounts();
}

async function moderateAccount(button) {
  const account = state.accounts.find((row) => String(row.id) === button.dataset.id);
  if (!account) return;
  const action = button.dataset.accountAction;
  if (action.startsWith("delete") && !confirm("Подтвердите необратимое удаление данных пользователя.")) return;
  const body = { account_id: account.id, action: action.startsWith("delete") ? action : "update", is_blocked: Boolean(account.is_blocked), telegram_blocked: Boolean(account.telegram_blocked), max_blocked: Boolean(account.max_blocked) };
  if (action === "block_all") body.is_blocked = !body.is_blocked;
  if (action === "block_tg") body.telegram_blocked = !body.telegram_blocked;
  if (action === "block_max") body.max_blocked = !body.max_blocked;
  await api("/api/accounts/moderate", { method: "POST", body: JSON.stringify(body) });
  await loadAccounts();
}

async function moderateChannel(button) {
  const deleting = button.dataset.channelAction === "delete_channel";
  if (deleting && !confirm("Удалить канал пользователя и все настроенные для него пересылки?")) return;
  await api("/api/accounts/moderate", { method: "POST", body: JSON.stringify({
    account_id: button.dataset.id,
    action: button.dataset.channelAction,
    platform: button.dataset.platform,
    chat_id: button.dataset.chat,
    channel_blocked: button.dataset.blocked !== "1"
  }) });
  await loadAccounts();
}

async function loadChannels() {
  const data = await api("/api/channels");
  state.channels = data;
  fillRouteSelects();
  renderChannels();
  renderMetrics();
}

async function loadBridges() {
  const data = await api(`/api/bridges?page=${state.page}&per_page=${state.perPage}`);
  state.page = data.page;
  state.totalPages = data.total_pages;
  state.bridges = data.items || [];
  $("pageLabel").textContent = `${data.page} из ${data.total_pages}`;
  $("prevPage").disabled = data.page <= 1;
  $("nextPage").disabled = data.page >= data.total_pages;
  renderBridgeList();
  renderMetrics();
}

async function loadSystem() {
  state.system = await api("/api/system");
}

async function loadConfig() {
  const data = await api("/api/config");
  state.config = data.config;
  renderConfig();
}

function formatUptime(totalSeconds) {
  const seconds = Math.max(0, Number(totalSeconds || 0));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return [days ? `${days} дн.` : "", hours ? `${hours} ч.` : "", `${minutes} мин.`].filter(Boolean).join(" ");
}

function renderServiceStatus(mode = "running") {
  const badge = $("serviceStatusBadge");
  if (!badge) return;
  badge.classList.toggle("offline", mode === "offline");
  badge.classList.toggle("restarting", mode === "restarting");
  badge.innerHTML = mode === "running"
    ? '<i class="fa-solid fa-check"></i>'
    : mode === "restarting"
      ? '<i class="fa-solid fa-arrows-rotate fa-spin"></i>'
      : '<i class="fa-solid fa-xmark"></i>';
  if (mode === "running" && state.service) {
    $("serviceStatusText").textContent = `Работает ${formatUptime(state.service.uptime_seconds)} · процесс ${state.service.pid}`;
  } else if (mode === "restarting") {
    $("serviceStatusText").textContent = "Служба перезапускается, ожидаем восстановление...";
  } else {
    $("serviceStatusText").textContent = "Служба не отвечает.";
  }
}

async function loadServiceStatus() {
  try {
    const data = await api("/api/service");
    state.service = data.service;
    renderServiceStatus("running");
  } catch (error) {
    renderServiceStatus("offline");
    throw error;
  }
}

async function loadPermissions() {
  const data = await api("/api/admin/permissions");
  state.permissions = data.permissions || [];
  renderPermissions();
}

async function loadAdminUsers(query = "") {
  const data = await api(`/api/admin/users?platform=${state.currentBot}&query=${encodeURIComponent(query)}`);
  state.adminUsers = data.users || [];
  renderAdminUsers();
}

function renderPasskeys() {
  const list = $("passkeyList");
  if (!list) return;
  $("addPasskeyButton").disabled = state.passkeys.length >= 3 || !passkeySupported();
  list.innerHTML = state.passkeys.map((passkey) => {
    const created = passkey.created_at ? new Date(passkey.created_at).toLocaleString("ru-RU") : "";
    const used = passkey.last_used_at ? `Последний вход: ${new Date(passkey.last_used_at).toLocaleString("ru-RU")}` : `Добавлен: ${created}`;
    return `
      <div class="passkey-row">
        <div class="passkey-row-main">
          <span class="passkey-row-icon"><i class="fa-solid fa-key"></i></span>
          <span class="passkey-row-copy">
            <strong>${escapeHtml(passkey.name)}</strong>
            <small>${escapeHtml(used)}</small>
          </span>
        </div>
        <button class="passkey-delete" type="button" data-passkey-delete="${escapeHtml(passkey.id)}" title="Удалить ключ доступа"><i class="fa-solid fa-trash"></i></button>
      </div>`;
  }).join("") || createListItem("Ключей доступа нет", "Добавьте Windows Hello, Face ID, отпечаток или аппаратный ключ.");
  $$("[data-passkey-delete]").forEach((button) => {
    button.onclick = async () => {
      if (!confirm("Удалить этот ключ доступа?")) return;
      const result = await api(`/api/passkeys/${encodeURIComponent(button.dataset.passkeyDelete)}`, { method: "DELETE" });
      state.passkeys = result.passkeys || [];
      renderPasskeys();
      await setupHcaptcha();
      setStatus("Ключ доступа удалён.");
    };
  });
}

async function loadPasskeys() {
  const data = await api("/api/passkeys");
  state.passkeys = data.passkeys || [];
  renderPasskeys();
}

async function addPasskey() {
  if (!passkeySupported()) throw new Error("Этот браузер не поддерживает ключи доступа.");
  if (state.passkeys.length >= 3) throw new Error("Можно добавить не более трёх ключей доступа.");
  const data = await api("/api/passkeys/register/options", { method: "POST" });
  const credential = await navigator.credentials.create({
    publicKey: normalizeCreationOptions(data.options)
  });
  if (!credential) throw new Error("Добавление ключа доступа отменено.");
  const publicKey = credential.response.getPublicKey?.();
  const authenticatorData = credential.response.getAuthenticatorData?.();
  const publicKeyAlgorithm = credential.response.getPublicKeyAlgorithm?.();
  if (!publicKey || !authenticatorData || typeof publicKeyAlgorithm !== "number") {
    throw new Error("Браузер не предоставил данные открытого ключа.");
  }
  const transports = credential.response.getTransports?.() || [];
  const name = state.passkeys.length === 0
    ? "Developer"
    : `Developer ${state.passkeys.length + 1}`;
  const result = await api("/api/passkeys/register/verify", {
    method: "POST",
    body: JSON.stringify({
      name,
      credential_id: bufferToBase64Url(credential.rawId),
      response: {
        clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
        authenticatorData: bufferToBase64Url(authenticatorData),
        publicKey: bufferToBase64Url(publicKey),
        publicKeyAlgorithm,
        transports
      }
    })
  });
  state.passkeys = result.passkeys || [];
  renderPasskeys();
  await setupHcaptcha();
  setStatus("Ключ доступа добавлен.");
}

async function loginWithPasskey() {
  if (!passkeySupported()) throw new Error("Этот браузер не поддерживает ключи доступа.");
  const data = await api("/api/passkeys/auth/options", { method: "POST" });
  const credential = await navigator.credentials.get({
    publicKey: normalizeRequestOptions(data.options)
  });
  if (!credential) throw new Error("Вход по ключу доступа отменён.");
  await api("/api/passkeys/auth/verify", {
    method: "POST",
    body: JSON.stringify(serializePasskeyAssertion(credential))
  });
  hideLogin();
  await bootstrap();
}

async function bootstrap() {
  const session = await fetch("/api/session", { credentials: "same-origin" });
  if (!session.ok) {
    showLogin();
    return;
  }
  hideLogin();
  setSection(state.currentSection);
  await Promise.all([
    loadPermissions(),
    loadChannels(),
    loadBridges(),
    loadSystem(),
    loadConfig(),
    loadServiceStatus(),
    loadAdminUsers($("adminSearchQuery").value.trim()),
    loadAccounts(),
    loadPasskeys()
  ]);
}

$("loginForm").onsubmit = async (event) => {
  event.preventDefault();
  const captchaToken = hcaptchaEnabled ? window.hcaptcha?.getResponse(hcaptchaWidgetId) || "" : "";
  if (hcaptchaEnabled && !captchaToken) {
    showLogin("Подтвердите, что вы не робот.");
    return;
  }
  const response = await fetch("/api/login", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: $("loginUsername").value, password: $("loginPassword").value, hcaptcha_token: captchaToken })
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    showLogin(data.message || "Неверный пароль.");
    window.hcaptcha?.reset();
    return;
  }
  hideLogin();
  await bootstrap();
};

$("loginPasskeyButton").onclick = async () => {
  $("loginError").textContent = "";
  try {
    await loginWithPasskey();
  } catch (error) {
    showLogin(error.message || "Не удалось войти по ключу доступа.");
  }
};

$("logoutButton").onclick = async () => {
  await api("/api/logout", { method: "POST" });
  document.body.classList.remove("menu-open");
  window.hcaptcha?.reset();
  showLogin();
};

async function selectBot(bot) {
  state.currentBot = bot;
  state.channelsPage = 1;
  state.adminsPage = 1;
  closeAdminEditor();
  localStorage.setItem("reposted_bot_view", state.currentBot);
  setSection(state.currentSection);
  renderChannels();
  renderBridgeList();
  renderConfig();
  renderAdminUsers();
  renderMetrics();
  await loadAdminUsers($("adminSearchQuery").value.trim());
}

$("sourceChannel").onchange = syncTargetAvailability;

$("prevChannelsPage").onclick = () => {
  state.channelsPage = Math.max(1, state.channelsPage - 1);
  renderChannels();
};

$("nextChannelsPage").onclick = () => {
  const totalPages = Math.max(1, Math.ceil(botChannels().length / state.perPage));
  state.channelsPage = Math.min(totalPages, state.channelsPage + 1);
  renderChannels();
};

$("prevAdminsPage").onclick = () => {
  state.adminsPage = Math.max(1, state.adminsPage - 1);
  renderAdminUsers();
};

$("nextAdminsPage").onclick = () => {
  const totalPages = Math.max(1, Math.ceil(state.adminUsers.length / state.perPage));
  state.adminsPage = Math.min(totalPages, state.adminsPage + 1);
  renderAdminUsers();
};

$("prevPage").onclick = async () => {
  state.page = Math.max(1, state.page - 1);
  await loadBridges();
};

$("nextPage").onclick = async () => {
  state.page = Math.min(state.totalPages, state.page + 1);
  await loadBridges();
};

$("bridgeForm").onsubmit = async (event) => {
  event.preventDefault();
  const [sourcePlatform, ...sourceIdParts] = $("sourceChannel").value.split(":");
  const targets = [...$("targetChannels").selectedOptions].map((option) => {
    const [platform, ...chatIdParts] = option.value.split(":");
    return { platform, chat_id: chatIdParts.join(":") };
  });
  await api("/api/bridges", {
    method: "POST",
    body: JSON.stringify({
      id: $("bridgeId").value || null,
      source_platform: sourcePlatform,
      source_chat_id: sourceIdParts.join(":"),
      targets,
      enabled: $("enabled").checked
    })
  });
  $("bridgeId").value = "";
  $("enabled").checked = true;
  await loadBridges();
  await loadSystem();
  closeBridgeEditor();
  setStatus("Пересылка сохранена.");
};

$("closeBridgeEditor").onclick = closeBridgeEditor;
$("saveBridgeTop").onclick = () => $("bridgeForm").requestSubmit();
$("deleteBridgeTop").onclick = async () => {
  const id = $("bridgeId").value;
  if (!id || !confirm("Удалить пересылку?")) return;
  await api(`/api/bridges/${id}`, { method: "DELETE" });
  await loadBridges();
  await loadSystem();
  closeBridgeEditor();
  setStatus("Пересылка удалена.");
};

$("resetFormTop").onclick = () => {
  fillBridgeForm(null);
};

$("editSelectedBridge").onclick = () => {
  const selected = state.bridgeMap.get(String(state.selectedBridgeId));
  if (selected) fillBridgeForm(selected);
};

$("toggleSelectedBridge").onclick = async () => {
  if (!state.selectedBridgeId) return;
  await api("/api/bridges/toggle", { method: "POST", body: JSON.stringify({ id: state.selectedBridgeId }) });
  await loadBridges();
  await loadSystem();
  setStatus("Состояние пересылки обновлено.");
};

$("deleteSelectedBridge").onclick = async () => {
  if (!state.selectedBridgeId || !confirm("Удалить выбранную пересылку?")) return;
  await api(`/api/bridges/${state.selectedBridgeId}`, { method: "DELETE" });
  state.selectedBridgeId = null;
  await loadBridges();
  await loadSystem();
  setStatus("Пересылка удалена.");
};

$("configForm").onsubmit = async (event) => {
  event.preventDefault();
  await api("/api/config", {
    method: "POST",
    body: JSON.stringify({
      telegram: {
        enabled: $("cfgTelegramEnabled").checked,
        bot_token: $("cfgTelegramToken").value.trim(),
        webhook_secret: $("cfgTelegramSecret").value.trim(),
        bot_url: $("cfgTelegramBotUrl").value.trim(),
        public_enabled: $("cfgTelegramPublic").checked
      },
      max: {
        enabled: $("cfgMaxEnabled").checked,
        bot_token: $("cfgMaxToken").value.trim(),
        webhook_secret: $("cfgMaxSecret").value.trim(),
        bot_url: $("cfgMaxBotUrl").value.trim(),
        public_enabled: $("cfgMaxPublic").checked,
        api_base_url: $("cfgMaxApiBaseUrl").value.trim()
      }
    })
  });
  $("cfgTelegramToken").value = "";
  $("cfgTelegramSecret").value = "";
  $("cfgMaxToken").value = "";
  $("cfgMaxSecret").value = "";
  await loadConfig();
  setStatus(state.config.restart_required
    ? "Настройки сохранены. Нажмите «Применить и перезапустить», затем подключите webhook бота."
    : `Конфиг ${botLabel()} сохранён.`);
};

$("databaseForm").onsubmit = async (event) => {
  event.preventDefault();
  await api("/api/config", {
    method: "POST",
    body: JSON.stringify({
      database: {
        host: $("serverDbHost").value.trim(),
        port: $("serverDbPort").value.trim(),
        name: $("serverDbName").value.trim(),
        user: $("serverDbUser").value.trim(),
        password: $("serverDbPassword").value
      }
    })
  });
  await loadConfig();
  setStatus("Настройки базы данных сохранены. Новое подключение применится после перезапуска службы.");
};

$("securityForm").onsubmit = async (event) => {
  event.preventDefault();
  const currentPassword = $("currentAdminPassword").value;
  const newPassword = $("newAdminPassword").value;
  const confirmPassword = $("confirmAdminPassword").value;
  if (!currentPassword) throw new Error("Укажите текущий пароль.");
  if (newPassword.length < 12) throw new Error("Новый пароль должен содержать не менее 12 символов.");
  if (newPassword !== confirmPassword) throw new Error("Подтверждение нового пароля не совпадает.");
  await api("/api/change-password", { method: "POST", body: JSON.stringify({
    current_password: currentPassword,
    new_password: newPassword,
    confirm_password: confirmPassword
  }) });
  $("currentAdminPassword").value = "";
  $("newAdminPassword").value = "";
  $("confirmAdminPassword").value = "";
  setStatus("Пароль веб-админки изменён.");
};

$("adminSearchButton").onclick = async () => {
  state.adminsPage = 1;
  await loadAdminUsers($("adminSearchQuery").value.trim());
  setStatus(`Список админов ${botLabel()} обновлён.`);
};

$("addPasskeyButton").onclick = addPasskey;
$("newAdminButton").onclick = openNewAdminEditor;
$("closeAdminEditor").onclick = closeAdminEditor;
$("saveAdminTop").onclick = () => $("adminAccessForm").requestSubmit();

$("adminAccessForm").onsubmit = async (event) => {
  event.preventDefault();
  const permissions = $$("[data-permission]").filter((node) => node.checked).map((node) => node.dataset.permission);
  const payload = {
    platform: state.currentBot,
    user_id: $("adminUserId").value.trim() || $("adminUserIdView").value.trim(),
    username: $("adminUsername").value.trim(),
    first_name: $("adminFirstName").value.trim(),
    chat_id: $("adminChatId").value.trim(),
    is_admin: true,
    permissions
  };
  if (!payload.user_id) {
    throw new Error("Укажите user ID для администратора.");
  }
  await api("/api/admin/users", { method: "POST", body: JSON.stringify(payload) });
  await loadAdminUsers("");
  closeAdminEditor();
  setStatus(`Права для ${botLabel()} сохранены.`);
};

$("deleteAdminTop").onclick = async () => {
  const userId = $("adminUserId").value.trim() || $("adminUserIdView").value.trim();
  if (!userId) return;
  await api("/api/admin/users", {
    method: "DELETE",
    body: JSON.stringify({ platform: state.currentBot, user_id: userId })
  });
  await loadAdminUsers("");
  closeAdminEditor();
  setStatus(`Права для ${botLabel()} сняты.`);
};

async function setupPlatformWebhook(platform) {
  const path = `/api/setup/${platform}-webhook`;
  try {
    await api(path, { method: "POST", body: JSON.stringify({ takeover: false }) });
  } catch (error) {
    if (error.status !== 409 || error.code !== "takeover_required") throw error;
    if (!confirm("У этого бота уже настроен webhook другого приложения. Переключить его на эту установку? Прежнее приложение перестанет получать события бота.")) {
      setStatus("Переключение отменено. Прежний webhook сохранён.", "info");
      return;
    }
    await api(path, { method: "POST", body: JSON.stringify({ takeover: true }) });
  }
  setStatus(`${platform === "telegram" ? "Telegram" : "МАКС"} webhook установлен.`);
}

const setupTelegramWebhook = () => setupPlatformWebhook("telegram");
const setupMaxWebhook = () => setupPlatformWebhook("max");

$("setupTelegramWebhook").onclick = setupTelegramWebhook;
$("setupMaxWebhook").onclick = setupMaxWebhook;

$("restartService").onclick = async () => {
  if (!confirm("Перезапустить службу GitRePosted? Telegram и МАКС будут недоступны несколько секунд.")) return;
  const button = $("restartService");
  button.disabled = true;
  try { await api("/api/service/restart", { method: "POST" }); }
  catch (error) { button.disabled = false; throw error; }
  renderServiceStatus("restarting");
  setStatus("Перезапуск GitRePosted запущен.");
  await new Promise((resolve) => setTimeout(resolve, 2500));
  let restored = false;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      const response = await fetch(`/health?restart=${Date.now()}`, { cache: "no-store" });
      if (response.ok) {
        const session = await fetch("/api/session", { credentials: "same-origin" });
        if (session.status === 401) {
          button.disabled = false;
          window.hcaptcha?.reset();
          showLogin("Служба перезапущена. Войдите снова, чтобы продолжить настройку.");
          return;
        }
        await loadServiceStatus();
        restored = true;
        break;
      }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  button.disabled = false;
  if (!restored) {
    renderServiceStatus("offline");
    throw new Error("Служба не ответила после перезапуска. Проверьте журнал сервера.");
  }
  await Promise.all([loadSystem(), loadConfig(), loadChannels(), loadBridges()]);
  setStatus("GitRePosted успешно перезапущен и снова принимает события.");
};

$("applyConfigRestart").onclick = () => $("restartService").click();

$("reconcileTelegram").onclick = async () => {
  await api("/admin/reconcile-telegram-bridges", { method: "POST" });
  await loadBridges();
  await loadSystem();
  setStatus("Данные Telegram в пересылках обновлены.");
};

$$("[data-section-link]").forEach((button) => {
  button.onclick = async () => {
    if (button.dataset.botLink && button.dataset.botLink !== state.currentBot) {
      await selectBot(button.dataset.botLink);
    }
    if (button.dataset.sectionLink === "bridges") closeBridgeEditor();
    setSection(button.dataset.sectionLink);
  };
});

$("sidebarToggle").onclick = () => document.body.classList.toggle("menu-open");
$("overlay").onclick = () => document.body.classList.remove("menu-open");
$("adminToastClose").onclick = closeToast;

window.addEventListener("unhandledrejection", (event) => {
  setStatus(`Ошибка: ${event.reason?.message || event.reason || "Не удалось выполнить действие"}`, "error");
});


setupHcaptcha().then(() => bootstrap()).catch((error) => {
  showLogin(error.message || "Не удалось загрузить настройки входа.");
});
