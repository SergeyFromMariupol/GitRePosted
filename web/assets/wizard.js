(function (root) {
    'use strict';

    const PLATFORMS = ['telegram', 'max'];
    const STEP_TITLES = ['Сервер', 'Администратор', 'Боты', 'Дополнительно', 'Проверка'];
    const JOB_STATUSES = ['idle', 'running', 'failed', 'complete'];
    const STEP_STATUSES = ['pending', 'running', 'done', 'skipped', 'failed'];

    function setupCodeFromFragment(value) {
        const match = /^#setup=([A-Za-z0-9_-]{32,160})$/.exec(String(value || ''));
        return match ? match[1] : null;
    }

    // A fragment never reaches the HTTP request. Remove it before any API call.
    let enrollmentCode = root.location ? setupCodeFromFragment(root.location.hash) : null;
    let invalidSetupLink = Boolean(root.location && root.location.hash && !enrollmentCode);
    if (root.location && root.location.hash) {
        try { root.history.replaceState(null, '', '/install/'); }
        catch (_) { enrollmentCode = null; invalidSetupLink = true; }
    }

    function safeHttpsUrl(value, suffix) {
        try {
            const url = new URL(String(value));
            if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return null;
            if (suffix) url.pathname = url.pathname.replace(/\/+$/, '') + '/' + suffix.replace(/^\/+/, '');
            return url.href;
        } catch (_) {
            return null;
        }
    }

    function visibleWebhookUrl(value) {
        try {
            const url = new URL(String(value));
            if (!['https:', 'http:'].includes(url.protocol)) return 'Адрес другого подключения';
            return url.origin + url.pathname.slice(0, 400) + (url.search ? ' [параметры скрыты]' : '');
        } catch (_) {
            return 'Адрес другого подключения';
        }
    }

    function foreignWebhookUrls(urls, platform, baseUrl) {
        const expected = safeHttpsUrl(baseUrl, platform === 'max' ? 'webhooks/max' : 'webhooks/telegram');
        return [...new Set((Array.isArray(urls) ? urls : []).filter((value) => {
            if (typeof value !== 'string' || value === '') return false;
            // The root helper compares exact endpoint strings. Browser URL
            // canonicalization must not silently bypass its consent check.
            return value !== expected;
        }))];
    }

    function normalizedJob(value) {
        const job = value && typeof value === 'object' ? value : {};
        return {
            id: typeof job.id === 'string' || typeof job.id === 'number' ? String(job.id) : '',
            type: job.type === 'host' ? 'host' : 'install',
            status: JOB_STATUSES.includes(job.status) ? job.status : 'idle',
            canRevise: job.can_revise === true,
            steps: (Array.isArray(job.steps) ? job.steps : []).map((step, index) => ({
                id: typeof step.id === 'string' ? step.id : String(index),
                title: typeof step.title === 'string' ? step.title : 'Этап установки',
                status: STEP_STATUSES.includes(step.status) ? step.status : 'pending'
            })),
            error: typeof job.error === 'string' ? job.error : (job.error && typeof job.error.message === 'string' ? job.error.message : '')
        };
    }

    function buildSettings(values) {
        const settings = {
            admin: { username: values.adminUsername.trim(), password: values.adminPassword, password_confirm: values.adminPasswordConfirm },
            telegram: { enabled: Boolean(values.telegramEnabled) },
            max: { enabled: Boolean(values.maxEnabled) },
            timezone: values.timezone.trim(),
            support_username: values.supportUsername.trim().replace(/^@/, ''),
            hcaptcha: { enabled: Boolean(values.hcaptchaEnabled) }
        };
        for (const platform of PLATFORMS) {
            if (settings[platform].enabled) {
                settings[platform].token = values[platform + 'Token'].trim();
                settings[platform].takeover = Boolean(values[platform + 'Takeover']);
            }
        }
        if (settings.hcaptcha.enabled) {
            settings.hcaptcha.sitekey = values.hcaptchaSitekey.trim();
            settings.hcaptcha.secret = values.hcaptchaSecret.trim();
        }
        return settings;
    }

    function validateSettings(settings, checks, step) {
        const errors = [];
        const add = (field, message) => errors.push({ field, message });
        if (step === undefined || step === 1) {
            if (!/^[A-Za-z0-9_.@-]{3,64}$/.test(settings.admin.username)) add('admin-username', 'Логин: от 3 до 64 латинских букв, цифр или символов _ . @ -');
            if ([...settings.admin.password].length < 12 || new TextEncoder().encode(settings.admin.password).length > 72) add('admin-password', 'Пароль должен содержать не менее 12 символов и занимать не более 72 байт.');
            if (settings.admin.password !== settings.admin.password_confirm) add('admin-password-confirm', 'Пароли не совпадают.');
            try { new Intl.DateTimeFormat('ru', { timeZone: settings.timezone }); } catch (_) { add('timezone', 'Укажите существующий часовой пояс, например Europe/Moscow.'); }
            if (!settings.timezone) add('timezone', 'Укажите часовой пояс сервиса.');
            if (settings.support_username && !/^[A-Za-z0-9_]{5,32}$/.test(settings.support_username)) add('support-username', 'Username поддержки: от 5 до 32 латинских букв, цифр или _.');
        }
        if (step === undefined || step === 2) {
            for (const platform of PLATFORMS) {
                if (!settings[platform].enabled) continue;
                const title = platform === 'telegram' ? 'Telegram' : 'МАКС';
                const check = checks[platform];
                if (!settings[platform].token) add(platform + '-token', 'Введите токен бота ' + title + ' или пропустите эту платформу.');
                else if (!check || check.token !== settings[platform].token || !check.identity) add(platform + '-token', 'Сначала проверьте текущий токен бота ' + title + '.');
                else if (check.foreignUrls.length > 0 && !settings[platform].takeover) add(platform + '-takeover', 'Подтвердите замену существующего подключения ' + title + ' или пропустите платформу.');
            }
        }
        if (step === undefined || step === 3) {
            if (settings.hcaptcha.enabled) {
                if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(settings.hcaptcha.sitekey)) add('hcaptcha-sitekey', 'Проверьте site key hCaptcha: нужен ключ в формате UUID.');
                if (!/^ES_[A-Za-z0-9_-]{20,128}$/.test(settings.hcaptcha.secret)) add('hcaptcha-secret', 'Проверьте secret key hCaptcha: нужен полный ключ, начинающийся с ES_.');
            }
        }
        return errors;
    }

    const helpers = { safeHttpsUrl, visibleWebhookUrl, foreignWebhookUrls, normalizedJob, buildSettings, validateSettings, setupCodeFromFragment };
    if (typeof module !== 'undefined' && module.exports) module.exports = helpers;
    if (!root.document) return;

    const document = root.document;
    const $ = (id) => document.getElementById(id);
    const state = {
        status: null, csrf: '', step: 0, maxStep: 0, busy: false, pendingMutation: null,
        poll: null, refreshId: 0, checks: {}, secretHistory: [], hostReady: false, loginPending: false,
        editingJobId: '', reviseJobId: '',
        entryError: invalidSetupLink ? 'Ссылка недействительна. Получите новую ссылку командой --resume в SSH-консоли сервера.' : ''
    };
    for (const platform of PLATFORMS) state.checks[platform] = { token: '', identity: null, foreignUrls: [], sequence: 0, checking: false };

    function rememberSecret(value) {
        if (typeof value === 'string' && value.length > 0 && !state.secretHistory.includes(value)) state.secretHistory.push(value);
    }

    function safeMessage(value) {
        let text = typeof value === 'string' ? value : 'Не удалось выполнить действие. Проверьте состояние сервера.';
        const secrets = state.secretHistory.concat(['admin-password', 'admin-password-confirm', 'telegram-token', 'max-token', 'hcaptcha-secret'].map((id) => $(id).value));
        for (const secret of secrets.sort((a, b) => b.length - a.length)) {
            if (secret) text = text.split(secret).join('[скрыто]');
        }
        return text.replace(/\b[0-9]{6,12}:[A-Za-z0-9_-]{20,}\b/g, '[токен скрыт]').slice(0, 1200);
    }

    function setText(id, value) { $(id).textContent = String(value); }
    function setError(id, message) { const element = $(id); element.textContent = safeMessage(message); element.hidden = !message; }
    function showScreen(id) {
        for (const screen of ['loading-screen', 'http-screen', 'login-screen', 'wizard-screen', 'job-screen', 'complete-screen']) $(screen).hidden = screen !== id;
    }
    function setConnection(text, mode) {
        const element = $('connection-status');
        element.className = 'status-pill' + (mode ? ' is-' + mode : '');
        element.replaceChildren();
        const dot = document.createElement('span'); dot.className = 'status-dot';
        element.append(dot, document.createTextNode(text));
    }
    function setBusy(busy) {
        state.busy = busy;
        $('settings-form').inert = busy;
        $('settings-form').setAttribute('aria-busy', String(busy));
        for (const id of ['login-refresh', 'logout-button', 'host-submit', 'job-retry', 'job-edit']) $(id).disabled = busy;
        updateNavigation();
    }

    async function api(action, payload) {
        if (payload !== undefined && action !== 'login' && !state.csrf) {
            const error = new Error('Сеанс настройки истёк. Откройте новую ссылку из SSH-консоли сервера.'); error.code = 'AUTH_REQUIRED'; throw error;
        }
        const controller = new AbortController();
        const timer = root.setTimeout(() => controller.abort(), action === 'check_bot' ? 50000 : (action === 'revise' ? 30000 : 12000));
        try {
            const headers = { Accept: 'application/json' };
            const options = { method: payload === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers, signal: controller.signal };
            if (payload !== undefined) {
                if (root.location.protocol !== 'https:' || !state.status || state.status.secure !== true) throw new Error('Для ввода настроек нужно защищённое соединение HTTPS.');
                headers['Content-Type'] = 'application/json';
                if (action !== 'login') headers['X-CSRF-Token'] = state.csrf;
                options.body = JSON.stringify(payload);
            }
            const response = await root.fetch('api.php?action=' + encodeURIComponent(action), options);
            let data;
            try { data = await response.json(); } catch (_) { throw new Error('Сервер вернул неполный ответ. Проверьте состояние установки.'); }
            if (!response.ok || !data || data.ok !== true) {
                const error = new Error(safeMessage(data && data.error && data.error.message));
                error.code = data && data.error && typeof data.error.code === 'string' ? data.error.code : 'REQUEST_FAILED';
                // A server error can follow a committed root operation whose
                // reply was lost. Reconcile its status before offering retry.
                error.definitive = response.status < 500;
                error.status = response.status;
                if (response.status === 401 || error.code === 'AUTH_REQUIRED' || error.code === 'UNAUTHENTICATED') {
                    state.csrf = '';
                    if (state.status) state.status.authenticated = false;
                    showScreen('login-screen');
                }
                throw error;
            }
            return data.result && typeof data.result === 'object' ? data.result : {};
        } finally { root.clearTimeout(timer); }
    }

    function clearSecrets() {
        for (const id of ['admin-password', 'admin-password-confirm', 'telegram-token', 'max-token', 'hcaptcha-secret']) {
            const input = $(id); rememberSecret(input.value); input.value = ''; input.type = 'password';
        }
        for (const button of document.querySelectorAll('[data-secret-target]')) {
            button.textContent = 'Показать'; button.setAttribute('aria-pressed', 'false');
        }
        for (const platform of PLATFORMS) {
            state.checks[platform].token = ''; state.checks[platform].identity = null; state.checks[platform].sequence++;
        }
    }

    function cancelPoll() { if (state.poll !== null) root.clearTimeout(state.poll); state.poll = null; }
    function schedulePoll(delay) { cancelPoll(); state.poll = root.setTimeout(() => refreshStatus(false), delay || 2500); }

    function applyStatus(status) {
        state.status = status;
        state.csrf = status.authenticated === true && typeof status.csrf === 'string' ? status.csrf : '';
        const secure = root.location.protocol === 'https:' && status.secure === true;
        if (!secure) {
            state.csrf = '';
            enrollmentCode = null;
            clearSecrets();
            setConnection('Нужен HTTPS', 'error');
            const href = safeHttpsUrl(status.base_url, 'install/');
            $('https-link').hidden = !href;
            if (href) $('https-link').href = href; else $('https-link').removeAttribute('href');
            showScreen('http-screen');
            return;
        }
        setConnection('Защищённое соединение', 'secure');
        if (status.installed === true) {
            enrollmentCode = null;
            clearSecrets(); cancelPoll();
            const href = safeHttpsUrl(status.admin_url) || safeHttpsUrl(status.site_url || status.base_url, 'control/');
            if (href) $('control-link').href = href; else $('control-link').removeAttribute('href');
            $('control-link').hidden = !href;
            showScreen('complete-screen');
            return;
        }
        if (status.authenticated !== true) {
            clearSecrets();
            cancelPoll();
            if (enrollmentCode && !state.loginPending) {
                showScreen('loading-screen'); setText('loading-title', 'Открываем безопасную настройку'); loginFromLink();
            } else { setError('login-error', state.entryError); showScreen('login-screen'); }
            return;
        }
        enrollmentCode = null;
        const job = normalizedJob(status.job);
        let unstartedMutation = null;
        if (job.status === 'failed' && state.editingJobId === job.id && state.pendingMutation) {
            // A lost edit response can describe either an unchanged failed job
            // or an accepted revision which failed quickly with the same id.
            // The server has confirmed a terminal state: preserve the entered
            // form for an explicit correction instead of polling it forever.
            unstartedMutation = state.pendingMutation;
            state.pendingMutation = null;
        }
        if (job.status === 'running' || (job.status === 'failed' && (state.editingJobId !== job.id ||
            (job.type === 'install' && !job.canRevise)))) {
            state.editingJobId = ''; state.reviseJobId = '';
            state.pendingMutation = null; renderJob(job); showScreen('job-screen');
            if (job.status === 'running') schedulePoll(); else cancelPoll();
            return;
        }
        // Completion is committed by root before the public HTTP view is materialized.
        // Keep polling a terminal install until the matching installed metadata arrives.
        if (job.type === 'install' && job.status === 'complete') {
            state.pendingMutation = null; renderJob(job); showScreen('job-screen'); schedulePoll(); return;
        }
        if (state.pendingMutation && state.pendingMutation.type === 'host' && job.type === 'host' && job.status === 'complete' &&
            (!job.id || job.id === state.pendingMutation.previousJobId || status.site_host !== state.pendingMutation.host)) {
            // A previously completed domain job does not acknowledge a new
            // request whose reply was lost. Keep the form for manual retry.
            unstartedMutation = state.pendingMutation;
            state.pendingMutation = null;
        }
        if (state.pendingMutation && (job.status === 'idle' ||
            (state.pendingMutation.type === 'install' && job.type === 'host' && job.status === 'complete'))) {
            // The server reports no matching install. Offer an explicit retry;
            // never automatically repeat a start with an uncertain result.
            // Root's lock/settings guard also rejects a late duplicate request.
            unstartedMutation = state.pendingMutation;
            state.pendingMutation = null;
        }
        if (job.type === 'host' && job.status === 'complete') state.hostReady = true;
        if (job.status === 'complete') state.pendingMutation = null;
        if (state.pendingMutation) {
            renderJob(job); showScreen('job-screen'); schedulePoll(4000); return;
        }
        cancelPoll();
        setText('server-base-url', status.site_url || status.base_url || '—');
        setText('server-public-ip', status.public_ip || status.host || '—');
        $('domain-details').hidden = Boolean(state.reviseJobId);
        if (state.hostReady || (status.site_host && status.site_host !== status.host)) {
            $('host-ready').hidden = false;
            setText('host-ready-url', status.site_url || status.base_url || '');
        }
        showScreen('wizard-screen'); showStep(state.step, false);
        if (unstartedMutation) setError(unstartedMutation.type === 'host' ? 'host-error' : 'settings-error', job.status === 'failed'
            ? 'Задание остановлено: ' + (job.error || 'сервер не сообщил причину.') + ' Ответ на запрос изменения не подтверждён. Проверьте настройки и повторите действие вручную; автоматически запрос не повторялся.'
            : unstartedMutation.type === 'host' && job.type === 'host' && job.status === 'complete'
                ? 'Настройка домена ' + unstartedMutation.host + ' не подтверждена. Проверьте состояние и повторите запрос вручную. Автоматического повтора не было.'
                : 'Сервер не сообщает о запущенном задании. Проверьте настройки и повторите запуск вручную. Повтор автоматически не выполнялся.');
    }

    async function refreshStatus(manual) {
        const id = ++state.refreshId;
        if (manual) { $('job-refresh').disabled = true; $('loading-retry').disabled = true; }
        try {
            const result = await api('status');
            if (id !== state.refreshId) return;
            $('loading-retry').hidden = true;
            $('job-offline').hidden = true;
            $('global-message').hidden = true;
            applyStatus(result);
        } catch (_) {
            if (id !== state.refreshId) return;
            setConnection('Нет связи с сервером', 'error');
            if (state.pendingMutation || (state.status && normalizedJob(state.status.job).status === 'running')) {
                $('job-offline').hidden = false; $('job-retry').hidden = true;
                showScreen('job-screen'); schedulePoll(6000);
            } else {
                setText('loading-title', 'Не удалось проверить сервер');
                $('loading-retry').hidden = false; showScreen('loading-screen');
            }
        } finally {
            if (manual) { $('job-refresh').disabled = false; $('loading-retry').disabled = false; }
        }
    }

    function updateNavigation() {
        for (const button of document.querySelectorAll('[data-go-step]')) {
            const step = Number(button.dataset.goStep);
            button.disabled = state.busy || step > state.maxStep;
            button.classList.toggle('is-complete', step < state.step);
            if (step === state.step) button.setAttribute('aria-current', 'step'); else button.removeAttribute('aria-current');
            if (step === state.step && root.innerWidth <= 760) button.scrollIntoView({ block: 'nearest', inline: 'nearest' });
        }
        $('previous-step').hidden = state.step === 0;
        $('previous-step').disabled = state.busy;
        $('next-step').disabled = state.busy || Object.values(state.checks).some((check) => check.checking);
        $('next-step').textContent = state.step === 4 ? (state.reviseJobId ? 'Сохранить и продолжить →' : 'Установить GitRePosted →') : 'Далее →';
        $('next-step').setAttribute('aria-busy', String(state.busy));
        setText('step-caption', 'Шаг ' + (state.step + 1) + ' из 5');
    }

    function showStep(step, focus) {
        state.step = Math.max(0, Math.min(4, step));
        state.maxStep = Math.max(state.maxStep, state.step);
        for (const panel of document.querySelectorAll('[data-step-panel]')) panel.hidden = Number(panel.dataset.stepPanel) !== state.step;
        setError('settings-error', '');
        for (const input of $('settings-form').querySelectorAll('[aria-invalid]')) input.removeAttribute('aria-invalid');
        updateNavigation();
        if (state.step === 4) renderReview();
        if (focus !== false) {
            const panel = document.querySelector('[data-step-panel="' + state.step + '"]');
            const heading = panel.querySelector('h1'); heading.setAttribute('tabindex', '-1'); heading.focus();
        }
    }

    function settings() {
        const value = (id) => $(id)?.value || '';
        const enabled = (id) => Boolean($(id)?.checked);
        return buildSettings({
            adminUsername: value('admin-username'), adminPassword: value('admin-password'), adminPasswordConfirm: value('admin-password-confirm'),
            telegramEnabled: enabled('telegram-enabled'), telegramToken: value('telegram-token'), telegramTakeover: enabled('telegram-takeover'),
            maxEnabled: enabled('max-enabled'), maxToken: value('max-token'), maxTakeover: enabled('max-takeover'),
            timezone: value('timezone'), supportUsername: value('support-username'),
            hcaptchaEnabled: enabled('hcaptcha-enabled'), hcaptchaSitekey: value('hcaptcha-sitekey'), hcaptchaSecret: value('hcaptcha-secret')
        });
    }

    function showValidationErrors(errors) {
        if (!errors.length) return false;
        const first = errors[0];
        const field = $(first.field);
        const panel = field.closest('[data-step-panel]');
        if (panel) showStep(Number(panel.dataset.stepPanel), false);
        setError('settings-error', errors.map((error) => error.message).join(' '));
        for (const error of errors) $(error.field).setAttribute('aria-invalid', 'true');
        field.focus();
        return true;
    }

    function addFact(target, title, value) {
        const row = document.createElement('div'); const term = document.createElement('dt'); const description = document.createElement('dd');
        term.textContent = title; description.textContent = value; row.append(term, description); target.append(row);
    }

    function renderReview() {
        const config = settings(); const target = $('review-facts'); target.replaceChildren();
        addFact(target, 'Адрес сервиса', state.status.site_url || state.status.base_url || '—');
        addFact(target, 'Администратор', config.admin.username);
        addFact(target, 'Часовой пояс', config.timezone);
        for (const platform of PLATFORMS) {
            const identity = state.checks[platform].identity;
            addFact(target, platform === 'telegram' ? 'Telegram' : 'МАКС', config[platform].enabled && identity ? (identity.username ? '@' + String(identity.username).replace(/^@/, '') : String(identity.name || 'Бот проверен')) : 'Пропущен — можно подключить позже');
        }
        addFact(target, 'hCaptcha', config.hcaptcha.enabled ? 'Включена' : 'Выключена');
        if (config.support_username) addFact(target, 'Поддержка', '@' + config.support_username);
        $('review-takeover').hidden = !PLATFORMS.some((platform) => config[platform].enabled && state.checks[platform].foreignUrls.length > 0 && config[platform].takeover);
    }

    function togglePlatform(platform) {
        const enabled = $(platform + '-enabled').checked;
        $(platform + '-fields').hidden = !enabled;
        $(platform + '-skipped').hidden = enabled;
        document.querySelector('[data-platform-card="' + platform + '"]').classList.toggle('is-enabled', enabled);
        if (!enabled) {
            rememberSecret($(platform + '-token').value);
            $(platform + '-token').value = ''; invalidateCheck(platform);
        }
    }

    function invalidateCheck(platform) {
        const check = state.checks[platform];
        check.token = ''; check.identity = null; check.foreignUrls = []; check.sequence++; check.checking = false;
        $(platform + '-identity').hidden = true; $(platform + '-takeover-panel').hidden = true;
        $(platform + '-takeover').checked = false;
        setError(platform + '-error', '');
        const button = document.querySelector('[data-check-platform="' + platform + '"]');
        button.disabled = false; button.setAttribute('aria-busy', 'false'); button.textContent = 'Проверить токен';
        updateNavigation();
    }

    async function checkBot(platform) {
        const token = $(platform + '-token').value.trim();
        if (!token) { setError(platform + '-error', 'Введите токен бота.'); $(platform + '-token').focus(); return; }
        invalidateCheck(platform);
        const check = state.checks[platform]; const sequence = check.sequence;
        rememberSecret(token); check.checking = true;
        const button = document.querySelector('[data-check-platform="' + platform + '"]');
        button.disabled = true; button.setAttribute('aria-busy', 'true'); button.textContent = 'Проверяем бота'; updateNavigation();
        try {
            const result = await api('check_bot', { platform, token });
            if (sequence !== check.sequence || !$(platform + '-enabled').checked || token !== $(platform + '-token').value.trim()) return;
            if (!result.identity || typeof result.identity !== 'object' || !result.identity.id) throw new Error('Сервер не подтвердил бота. Повторите проверку токена.');
            check.token = token; check.identity = result.identity;
            check.foreignUrls = foreignWebhookUrls(result.existing_urls, platform, state.status.site_url || state.status.base_url);
            const identity = result.identity;
            const name = identity.username ? '@' + String(identity.username).replace(/^@/, '') : String(identity.name || 'Бот');
            setText(platform + '-identity', '✓ ' + name + ' — токен проверен'); $(platform + '-identity').hidden = false;
            const urls = $(platform + '-existing-urls'); urls.replaceChildren();
            for (const value of check.foreignUrls) { const code = document.createElement('code'); code.textContent = visibleWebhookUrl(value); urls.append(code); }
            $(platform + '-takeover-panel').hidden = check.foreignUrls.length === 0;
        } catch (error) {
            if (sequence === check.sequence) setError(platform + '-error', error.message);
        } finally {
            if (sequence === check.sequence) { check.checking = false; button.disabled = false; button.setAttribute('aria-busy', 'false'); button.textContent = check.identity ? 'Проверить ещё раз' : 'Проверить токен'; updateNavigation(); }
        }
    }

    function renderJob(job) {
        const host = job.type === 'host' || (state.pendingMutation && state.pendingMutation.type === 'host');
        setText('job-title', job.status === 'failed' ? (host ? 'Подготовка домена остановилась' : 'Установка остановилась') : (host ? 'Готовим домен и HTTPS' : 'Готовим ваш GitRePosted'));
        setText('job-description', state.pendingMutation && job.status === 'idle' ? 'Ответ на запрос пока не подтверждён. Проверяем состояние на сервере; повторный запуск не выполняется.' : (job.status === 'failed' ? 'Исправьте указанную причину и повторите неуспешный этап.' : 'Можно оставить эту страницу открытой. Состояние сохраняется на сервере.'));
        const done = job.steps.filter((step) => step.status === 'done' || step.status === 'skipped').length;
        const running = job.steps.find((step) => step.status === 'running');
        setText('job-caption', running ? running.title : (job.status === 'failed' ? 'Нужно ваше внимание' : 'Ожидаем состояние сервера'));
        setText('job-step-count', job.steps.length ? done + ' из ' + job.steps.length : '');
        $('job-progress-bar').style.width = job.steps.length ? String(done / job.steps.length * 100) + '%' : '0%';
        if (job.steps.length) {
            $('job-progress').setAttribute('aria-valuemin', '0'); $('job-progress').setAttribute('aria-valuemax', String(job.steps.length)); $('job-progress').setAttribute('aria-valuenow', String(done));
        } else $('job-progress').removeAttribute('aria-valuenow');
        const list = $('job-steps'); list.replaceChildren();
        const labels = { pending: 'Ожидает', running: 'Выполняется', done: 'Готово', skipped: 'Пропущен', failed: 'Ошибка' };
        for (const step of job.steps) {
            const item = document.createElement('li'); item.className = 'job-step job-step--' + step.status;
            const icon = document.createElement('span'); icon.className = 'job-step-icon'; icon.setAttribute('aria-hidden', 'true'); icon.textContent = ({ done: '✓', skipped: '—', failed: '!' })[step.status] || '';
            const title = document.createElement('span'); title.className = 'job-step-title'; title.textContent = safeMessage(step.title);
            const label = document.createElement('span'); label.className = 'job-step-label'; label.textContent = labels[step.status];
            item.append(icon, title, label); list.append(item);
        }
        setError('job-error', job.status === 'failed' ? job.error || 'Не удалось завершить этап. Проверьте состояние сервера и повторите.' : '');
        $('job-retry').hidden = job.status !== 'failed' || !job.id;
        $('job-retry').disabled = state.busy;
        $('job-edit').hidden = job.status !== 'failed' || !job.id || (!host && !job.canRevise);
        $('job-edit').disabled = state.busy;
        $('job-edit').textContent = host ? 'Изменить домен или продолжить по IP' : 'Изменить настройки';
    }

    async function mutationFailed(error, field, type) {
        if (error.definitive && error.status !== 410) {
            state.pendingMutation = null;
            // A rejection can also describe an existing job. Reconcile it, but
            // retain the new explanation when the edited job did not advance.
            await refreshStatus(false);
            if (state.status && state.status.authenticated === true && state.status.installed !== true) {
                const job = normalizedJob(state.status.job);
                if (job.status === 'failed' && state.editingJobId !== job.id) setError('job-error', error.message);
                else if (job.status !== 'running') setError(field, error.message);
            }
        } else {
            renderJob(normalizedJob({ type })); showScreen('job-screen');
            $('job-offline').hidden = false; schedulePoll(1000);
        }
    }

    async function startInstall() {
        const config = settings();
        if (showValidationErrors(validateSettings(config, state.checks))) return;
        setBusy(true); cancelPoll(); setError('settings-error', '');
        for (const secret of [config.admin.password, config.admin.password_confirm, config.telegram.token, config.max.token, config.hcaptcha.secret]) rememberSecret(secret);
        state.pendingMutation = { type: 'install' };
        try {
            const result = await api(state.reviseJobId ? 'revise' : 'start', state.reviseJobId ? { job_id: state.reviseJobId, settings: config } : { settings: config });
            clearSecrets();
            state.editingJobId = ''; state.reviseJobId = '';
            if (result.job) { state.status.job = result.job; state.pendingMutation = null; renderJob(normalizedJob(result.job)); showScreen('job-screen'); }
            else { renderJob(normalizedJob({})); showScreen('job-screen'); }
            await refreshStatus(false);
        } catch (error) {
            await mutationFailed(error, 'settings-error', 'install');
        } finally { setBusy(false); }
    }

    async function loginFromLink() {
        if (!enrollmentCode || state.loginPending) return;
        const code = enrollmentCode;
        enrollmentCode = null; state.loginPending = true;
        rememberSecret(code); state.entryError = ''; setBusy(true);
        try {
            const result = await api('login', { code });
            if (result.csrf) state.csrf = result.csrf;
            await refreshStatus(false);
        } catch (error) {
            state.entryError = error.code === 'INVALID_CODE' ? 'Ссылка уже использована или срок её действия закончился. Получите новую ссылку в SSH-консоли командой --resume.' : (error.definitive ? safeMessage(error.message) : 'Ответ на вход не получен. Проверяем доступ; если сеанс не открылся, получите новую ссылку в SSH-консоли.');
            await refreshStatus(false);
        } finally { state.loginPending = false; setBusy(false); }
    }

    function acceptSetupFragment() {
        const fragment = root.location.hash;
        // Same-document navigation does not rerun initialization. Leave ordinary
        // anchors alone, including the keyboard navigation link to #main.
        if (!/^#setup(?:=|$)/.test(fragment)) return;
        const code = setupCodeFromFragment(fragment);
        let scrubbed = false;
        try { root.history.replaceState(null, '', '/install/'); scrubbed = true; }
        catch (_) { /* Never submit a code still visible in the address bar. */ }
        // Opening another setup link must not reset entered settings, interrupt
        // an active job, or replay enrollment while its outcome is pending.
        if (state.loginPending || state.busy || state.pendingMutation ||
            (state.status && (state.status.installed === true || normalizedJob(state.status.job).status === 'running'))) return;
        enrollmentCode = scrubbed ? code : null;
        state.entryError = !scrubbed ? 'Не удалось безопасно открыть ссылку. Откройте её в новой вкладке.' :
            (code ? '' : 'Ссылка недействительна. Получите новую ссылку командой --resume в SSH-консоли сервера.');
        if (!scrubbed) { setError('login-error', state.entryError); showScreen('login-screen'); return; }
        // Reuse status reconciliation and its HTTPS check before enrollment.
        // Cached authentication may have expired; a confirmed live session
        // discards the code without changing the entered form values.
        refreshStatus(false);
    }

    $('settings-form').addEventListener('submit', (event) => {
        event.preventDefault(); if (state.busy) return;
        if (state.step === 4) { startInstall(); return; }
        if (!showValidationErrors(validateSettings(settings(), state.checks, state.step))) showStep(state.step + 1);
    });
    $('previous-step').addEventListener('click', () => { if (!state.busy) showStep(state.step - 1); });
    for (const button of document.querySelectorAll('[data-go-step]')) button.addEventListener('click', () => { if (!state.busy && Number(button.dataset.goStep) <= state.maxStep) showStep(Number(button.dataset.goStep)); });
    for (const button of document.querySelectorAll('[data-secret-target]')) button.addEventListener('click', () => {
        const input = $(button.dataset.secretTarget); const reveal = input.type === 'password';
        input.type = reveal ? 'text' : 'password'; button.textContent = reveal ? 'Скрыть' : 'Показать'; button.setAttribute('aria-pressed', String(reveal));
    });
    for (const platform of PLATFORMS) {
        $(platform + '-enabled').addEventListener('change', () => togglePlatform(platform));
        $(platform + '-token').addEventListener('input', () => invalidateCheck(platform));
        document.querySelector('[data-check-platform="' + platform + '"]').addEventListener('click', () => checkBot(platform));
    }
    for (const option of ['hcaptcha']) $(option + '-enabled').addEventListener('change', () => {
        $(option + '-fields').hidden = !$(option + '-enabled').checked;
        setError('settings-error', '');
    });

    $('host-submit').addEventListener('click', async () => {
        const host = $('domain-host').value.trim().toLowerCase(); const email = $('domain-email').value.trim();
        if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) { setError('host-error', 'Введите домен без протокола, пути и порта, например posts.example.com.'); $('domain-host').focus(); return; }
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { setError('host-error', 'Проверьте email для уведомлений.'); $('domain-email').focus(); return; }
        setError('host-error', ''); setBusy(true); cancelPoll(); $('host-progress').hidden = false;
        state.pendingMutation = { type: 'host', host, previousJobId: normalizedJob(state.status && state.status.job).id };
        try {
            const result = await api('host', email ? { host, email } : { host });
            if (result.job) { state.status.job = result.job; state.pendingMutation = null; renderJob(normalizedJob(result.job)); showScreen('job-screen'); }
            await refreshStatus(false);
        } catch (error) {
            await mutationFailed(error, 'host-error', 'host');
        } finally { $('host-progress').hidden = true; setBusy(false); }
    });

    $('job-retry').addEventListener('click', async () => {
        const job = normalizedJob(state.status && state.status.job);
        if (state.busy || job.status !== 'failed' || !job.id) return;
        setBusy(true); $('job-retry').hidden = true;
        try { await api('retry', { job_id: job.id }); await refreshStatus(false); }
        catch (error) { setError('job-error', error.definitive ? error.message : 'Ответ о повторе этапа не получен. Сначала проверьте состояние задания.'); await refreshStatus(false); }
        finally { setBusy(false); }
    });
    $('job-edit').addEventListener('click', () => {
        const job = normalizedJob(state.status && state.status.job);
        if (state.busy || job.status !== 'failed' || !job.id || (job.type !== 'host' && !job.canRevise)) return;
        cancelPoll(); clearSecrets();
        for (const platform of PLATFORMS) invalidateCheck(platform);
        state.pendingMutation = null; state.editingJobId = job.id;
        state.reviseJobId = job.type === 'install' ? job.id : '';
        state.step = job.type === 'host' ? 0 : 1;
        state.maxStep = state.step;
        applyStatus(state.status);
        if (job.type === 'install') setError('settings-error', 'Введите пароль и выбранные токены заново. База сохранится. Если подключение бота уже начиналось, оставьте его включённым; можно указать новый токен того же бота. Сменить бота можно после установки в админке.');
    });
    $('logout-button').addEventListener('click', async () => {
        if (state.busy) return;
        setBusy(true); cancelPoll(); ++state.refreshId;
        try { await api('logout', {}); state.csrf = ''; clearSecrets(); state.step = 0; state.maxStep = 0; await refreshStatus(false); }
        catch (error) { setError('settings-error', error.message); }
        finally { setBusy(false); }
    });
    for (const id of ['loading-retry', 'http-retry', 'job-refresh', 'login-refresh']) $(id).addEventListener('click', () => refreshStatus(true));
    root.addEventListener('hashchange', acceptSetupFragment);
    root.addEventListener('online', () => refreshStatus(false));
    refreshStatus(false);
})(typeof window !== 'undefined' ? window : globalThis);
