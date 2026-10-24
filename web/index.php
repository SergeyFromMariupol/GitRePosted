<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <meta name="referrer" content="no-referrer">
    <meta name="robots" content="noindex, nofollow">
    <title>Установка GitRePosted</title>
    <link rel="stylesheet" href="assets/wizard.css">
    <script src="assets/wizard.js" defer></script>
</head>
<body>
<a class="skip-link" href="#main">К настройке</a>
<div class="shell">
    <header class="header">
        <a class="brand" href="./" aria-label="GitRePosted — установка">
            <span class="brand-mark" aria-hidden="true">G</span>
            <span>GitRePosted<span class="brand-caption">Установка на вашем сервере</span></span>
        </a>
        <span id="connection-status" class="status-pill"><span class="status-dot"></span>Проверяем соединение</span>
    </header>

    <main id="main" tabindex="-1">
        <div id="global-message" class="notice" role="status" aria-live="polite" hidden></div>

        <section id="loading-screen" class="center-card" aria-labelledby="loading-title">
            <span class="spinner spinner--large" aria-hidden="true"></span>
            <h1 id="loading-title">Готовим настройку</h1>
            <p class="muted">Проверяем защищённое соединение и состояние установки.</p>
            <button id="loading-retry" class="button button--secondary" type="button" hidden>Проверить ещё раз</button>
        </section>

        <section id="http-screen" class="center-card" aria-labelledby="http-title" hidden>
            <span class="section-icon" aria-hidden="true">↗</span>
            <p class="eyebrow">ПЕРВЫЙ ШАГ</p>
            <h1 id="http-title">Продолжим по защищённому адресу</h1>
            <p class="muted">Для ввода кода доступа, пароля и токенов нужен HTTPS.
                Установщик подготовил защищённый адрес сервера.</p>
            <a id="https-link" class="button button--primary" hidden>Открыть безопасную настройку <span aria-hidden="true">→</span></a>
            <p id="https-hint" class="small muted">Адрес HTTPS и результат подготовки сертификата также указаны в терминале сервера.</p>
            <button id="http-retry" class="button button--quiet" type="button">Проверить готовность HTTPS</button>
        </section>

        <section id="login-screen" class="login-layout" aria-labelledby="login-title" hidden>
            <div class="welcome-panel">
                <p class="eyebrow">ВАШИ КАНАЛЫ. ВАШИ МАРШРУТЫ.</p>
                <h1>Настроим GitRePosted<br>за несколько шагов</h1>
                <p class="muted">Подключите Telegram, МАКС или начните только с панели управления.
                    Каждый бот настраивается независимо.</p>
                <div class="welcome-points">
                    <div><span aria-hidden="true">01</span><p>Создайте администратора</p></div>
                    <div><span aria-hidden="true">02</span><p>Выберите нужных ботов</p></div>
                    <div><span aria-hidden="true">03</span><p>Проверьте и запустите сервис</p></div>
                </div>
                <p class="privacy-note"><span aria-hidden="true">◇</span> Секреты вводятся по HTTPS и не сохраняются в браузере.</p>
            </div>
            <div class="card login-card">
                <span class="section-icon" aria-hidden="true">↳</span>
                <p class="eyebrow">БЕЗОПАСНЫЙ ДОСТУП</p>
                <h2 id="login-title">Откройте ссылку из SSH-консоли</h2>
                <p class="muted">Установщик показывает в терминале личную одноразовую ссылку.
                    Откройте её в этом браузере — доступ подтвердится автоматически.</p>
                <p id="login-error" class="field-error" role="alert" hidden></p>
                <div class="resume-help"><p class="small muted">Чтобы получить новую ссылку, выполните на сервере:</p><code class="resume-command">sudo bash /opt/gitreposted-installer/bootstrap.sh --resume</code></div>
                <button id="login-refresh" class="button button--secondary button--full" type="button">Проверить доступ</button>
                <p class="small muted">Ничего копировать в форму не нужно. Ссылку не передавайте другим людям.
                    Пароль администратора вы зададите на следующем шаге.</p>
            </div>
        </section>

        <section id="wizard-screen" class="wizard-layout" aria-label="Настройка GitRePosted" hidden>
            <aside class="sidebar">
                <p class="eyebrow">НАСТРОЙКА</p>
                <nav aria-label="Шаги установки">
                    <ol id="step-navigation" class="step-nav">
                        <li><button type="button" data-go-step="0"><span>1</span><div>Сервер<small>Адрес и HTTPS</small></div></button></li>
                        <li><button type="button" data-go-step="1"><span>2</span><div>Администратор<small>Доступ к панели</small></div></button></li>
                        <li><button type="button" data-go-step="2"><span>3</span><div>Боты<small>Telegram и МАКС</small></div></button></li>
                        <li><button type="button" data-go-step="3"><span>4</span><div>Дополнительно<small>Необязательные функции</small></div></button></li>
                        <li><button type="button" data-go-step="4"><span>5</span><div>Проверка<small>Всё готово к запуску</small></div></button></li>
                    </ol>
                </nav>
                <div class="sidebar-footer"><span class="status-dot status-dot--green"></span> Секреты остаются на сервере</div>
                <button id="logout-button" class="button button--quiet" type="button">Выйти из настройки</button>
            </aside>

            <form id="settings-form" class="wizard-content" novalidate>
                <section class="step-panel" data-step-panel="0" aria-labelledby="server-title">
                    <p class="eyebrow">ШАГ 1 ИЗ 5</p>
                    <h1 id="server-title">Сервер готов к настройке</h1>
                    <p class="lead muted">Можно использовать защищённый IP-адрес или подключить свой домен.</p>
                    <div class="card server-card">
                        <div class="card-heading"><span class="section-icon section-icon--small" aria-hidden="true">✓</span><div><h2>Защищённое соединение</h2><p class="muted">Сертификат обеспечивает HTTPS для ввода настроек.</p></div><span class="tag tag--green">HTTPS</span></div>
                        <dl class="facts"><div><dt>Адрес сервиса</dt><dd id="server-base-url">—</dd></div><div><dt>Сервер</dt><dd id="server-public-ip">—</dd></div></dl>
                    </div>
                    <details class="card option-details" id="domain-details">
                        <summary><div><h2>Подключить домен</h2><span class="muted">Необязательно — HTTPS по IP уже доступен</span></div><span aria-hidden="true">+</span></summary>
                        <div class="details-body">
                            <p class="muted">Направьте A-запись домена на IP этого сервера. Если есть AAAA-запись,
                                она также должна вести на этот сервер. После проверки установщик подготовит сертификат.</p>
                            <div class="field"><label for="domain-host">Домен без https://</label><input id="domain-host" type="text" placeholder="posts.example.com" autocomplete="off" spellcheck="false" autocapitalize="none"></div>
                            <div class="field"><label for="domain-email">Email для уведомлений о сертификате <span class="optional">необязательно</span></label><input id="domain-email" type="email" placeholder="admin@example.com" autocomplete="email"></div>
                            <p id="host-error" class="field-error" role="alert" hidden></p>
                            <button id="host-submit" class="button button--secondary" type="button">Проверить домен и настроить HTTPS</button>
                            <p id="host-progress" class="small muted" aria-live="polite" hidden>Проверяем домен и сертификат. Это может занять несколько минут.</p>
                            <div id="host-ready" class="notice notice--success" hidden><strong>Домен готов</strong><p>Продолжайте настройку на этой странице. Панель будет доступна по адресу:</p><code id="host-ready-url"></code></div>
                        </div>
                    </details>
                </section>

                <section class="step-panel" data-step-panel="1" aria-labelledby="admin-title" hidden>
                    <p class="eyebrow">ШАГ 2 ИЗ 5</p>
                    <h1 id="admin-title">Доступ к вашей панели</h1>
                    <p class="lead muted">Эти данные понадобятся для управления сервисом после установки.</p>
                    <div class="card">
                        <div class="field"><label for="admin-username">Логин администратора</label><input id="admin-username" type="text" value="admin" autocomplete="username" spellcheck="false" autocapitalize="none" maxlength="64" required></div>
                        <div class="field"><label for="admin-password">Пароль</label><div class="secret-field"><input id="admin-password" type="password" autocomplete="new-password" minlength="12" required><button class="reveal" type="button" data-secret-target="admin-password" aria-label="Показать пароль" aria-pressed="false">Показать</button></div><p class="field-help">Не менее 12 символов. Используйте отдельный пароль для этой панели.</p></div>
                        <div class="field"><label for="admin-password-confirm">Повторите пароль</label><div class="secret-field"><input id="admin-password-confirm" type="password" autocomplete="new-password" required><button class="reveal" type="button" data-secret-target="admin-password-confirm" aria-label="Показать повтор пароля" aria-pressed="false">Показать</button></div></div>
                    </div>
                    <div class="card">
                        <div class="field"><label for="timezone">Часовой пояс сервиса</label><input id="timezone" type="text" value="Europe/Moscow" list="timezone-options" autocomplete="off" spellcheck="false" required><datalist id="timezone-options"><option value="Europe/Moscow"><option value="UTC"><option value="Europe/Kyiv"><option value="Europe/Berlin"><option value="Asia/Yekaterinburg"><option value="Asia/Novosibirsk"><option value="Asia/Vladivostok"></datalist><p class="field-help">Часовой пояс процесса сервиса.</p></div>
                    </div>
                </section>

                <section class="step-panel" data-step-panel="2" aria-labelledby="bots-title" hidden>
                    <p class="eyebrow">ШАГ 3 ИЗ 5</p>
                    <h1 id="bots-title">Какие боты подключим?</h1>
                    <p class="lead muted">Можно выбрать одну платформу, обе или подключить их позже через панель.</p>
                    <article class="card platform-card" data-platform-card="telegram">
                        <div class="platform-heading"><span class="platform-icon platform-icon--telegram" aria-hidden="true">↗</span><div><h2>Telegram</h2><p class="muted">Публикации и управление каналами</p></div><label class="switch"><input id="telegram-enabled" type="checkbox" aria-label="Подключить Telegram"><span></span></label></div>
                        <div id="telegram-fields" class="platform-fields" hidden>
                            <div class="field"><label for="telegram-token">Токен бота из BotFather</label><div class="secret-field"><input id="telegram-token" type="password" autocomplete="off" spellcheck="false" autocapitalize="none"><button class="reveal" type="button" data-secret-target="telegram-token" aria-label="Показать токен Telegram" aria-pressed="false">Показать</button></div></div>
                            <button class="button button--secondary bot-check" type="button" data-check-platform="telegram">Проверить токен</button>
                            <p id="telegram-error" class="field-error" role="alert" hidden></p>
                            <div id="telegram-identity" class="identity-result" aria-live="polite" hidden></div>
                            <div id="telegram-takeover-panel" class="takeover-panel" hidden><h3>У бота уже есть другое подключение</h3><p>После установки обновления этого бота будут приходить сюда. Текущий сервис перестанет их получать.</p><div id="telegram-existing-urls" class="existing-urls"></div><label class="check-label"><input id="telegram-takeover" type="checkbox"><span>Разрешаю заменить существующее подключение этого бота</span></label></div>
                        </div>
                        <p id="telegram-skipped" class="platform-skipped">Сейчас пропущен. Подключить можно после установки.</p>
                    </article>
                    <article class="card platform-card" data-platform-card="max">
                        <div class="platform-heading"><span class="platform-icon platform-icon--max" aria-hidden="true">М</span><div><h2>МАКС</h2><p class="muted">Публикации и управление каналами</p></div><label class="switch"><input id="max-enabled" type="checkbox" aria-label="Подключить МАКС"><span></span></label></div>
                        <div id="max-fields" class="platform-fields" hidden>
                            <div class="field"><label for="max-token">Токен бота МАКС</label><div class="secret-field"><input id="max-token" type="password" autocomplete="off" spellcheck="false" autocapitalize="none"><button class="reveal" type="button" data-secret-target="max-token" aria-label="Показать токен МАКС" aria-pressed="false">Показать</button></div></div>
                            <button class="button button--secondary bot-check" type="button" data-check-platform="max">Проверить токен</button>
                            <p id="max-error" class="field-error" role="alert" hidden></p>
                            <div id="max-identity" class="identity-result" aria-live="polite" hidden></div>
                            <div id="max-takeover-panel" class="takeover-panel" hidden><h3>У бота уже есть другое подключение</h3><p>После установки обновления этого бота будут приходить сюда. Текущий сервис перестанет их получать.</p><div id="max-existing-urls" class="existing-urls"></div><label class="check-label"><input id="max-takeover" type="checkbox"><span>Разрешаю заменить существующее подключение этого бота</span></label></div>
                        </div>
                        <p id="max-skipped" class="platform-skipped">Сейчас пропущен. Подключить можно после установки.</p>
                    </article>
                    <div class="notice"><strong>Можно начать без ботов</strong><p>Панель будет установлена, а очереди пересылок останутся выключены до подключения платформ.</p></div>
                </section>

                <section class="step-panel" data-step-panel="3" aria-labelledby="options-title" hidden>
                    <p class="eyebrow">ШАГ 4 ИЗ 5</p>
                    <h1 id="options-title">Дополнительные возможности</h1>
                    <p class="lead muted">Этот шаг можно полностью пропустить. Базовая установка от него не зависит.</p>
                    <article class="card optional-card">
                        <div class="option-heading"><div><h2>hCaptcha</h2><p class="muted">Дополнительная проверка при входе в панель</p></div><label class="switch"><input id="hcaptcha-enabled" type="checkbox" aria-label="Включить hCaptcha"><span></span></label></div>
                        <div id="hcaptcha-fields" class="details-body" hidden>
                            <p class="muted">Создайте ключи для адреса этого сервиса в hCaptcha. Если ключей пока нет, оставьте функцию выключенной.</p>
                            <div class="field"><label for="hcaptcha-sitekey">Site key</label><input id="hcaptcha-sitekey" type="text" autocomplete="off" spellcheck="false" autocapitalize="none"></div>
                            <div class="field"><label for="hcaptcha-secret">Secret key</label><div class="secret-field"><input id="hcaptcha-secret" type="password" autocomplete="off" spellcheck="false" autocapitalize="none"><button class="reveal" type="button" data-secret-target="hcaptcha-secret" aria-label="Показать секрет hCaptcha" aria-pressed="false">Показать</button></div></div>
                        </div>
                    </article>
                    <div class="notice"><strong>Файлы большого размера</strong><p>Сначала используется обычный Telegram Bot API. Локальный Bot API для больших файлов подключается отдельно по инструкции после установки.</p></div>
                </section>

                <section class="step-panel" data-step-panel="4" aria-labelledby="review-title" hidden>
                    <p class="eyebrow">ШАГ 5 ИЗ 5</p>
                    <h1 id="review-title">Проверим перед запуском</h1>
                    <p class="lead muted">Установщик сохранит настройки, подготовит приложение и подключит только выбранные платформы.</p>
                    <div class="card"><h2>Ваши настройки</h2><dl id="review-facts" class="facts review-facts"></dl></div>
                    <div id="review-takeover" class="notice notice--warning" hidden><strong>Подключения выбранных ботов будут заменены</strong><p>Вы разрешили перенести обновления указанных ботов с другого сервиса на этот сервер.</p></div>
                    <p class="small muted">Пароли и токены не отображаются в обзоре. Установка не отправляет публикации в каналы.</p>
                </section>

                <p id="settings-error" class="field-error form-error" role="alert" hidden></p>
                <footer class="wizard-actions"><button id="previous-step" class="button button--quiet" type="button">← Назад</button><span id="step-caption" class="small muted">Шаг 1 из 5</span><button id="next-step" class="button button--primary" type="submit">Далее <span aria-hidden="true">→</span></button></footer>
            </form>
        </section>

        <section id="job-screen" class="job-layout" aria-labelledby="job-title" hidden>
            <div class="job-header"><span id="job-symbol" class="section-icon" aria-hidden="true">↻</span><p class="eyebrow">УСТАНОВКА</p><h1 id="job-title">Готовим ваш GitRePosted</h1><p id="job-description" class="lead muted">Можно оставить эту страницу открытой. Состояние сохраняется на сервере.</p></div>
            <div class="card job-card"><div class="progress-caption"><strong id="job-caption">Получаем этапы установки</strong><span id="job-step-count" class="small muted"></span></div><div id="job-progress" class="progress-track" role="progressbar" aria-label="Выполненные этапы"><span id="job-progress-bar"></span></div><ol id="job-steps" class="job-steps" aria-live="polite"></ol></div>
            <div id="job-error" class="notice notice--error" role="alert" hidden></div>
            <div id="job-offline" class="notice notice--warning" role="status" hidden><strong>Связь с сервером прервалась</strong><p>Установка могла продолжиться. Сначала проверим состояние уже запущенного задания.</p></div>
            <div class="job-actions"><button id="job-refresh" class="button button--secondary" type="button">Проверить состояние</button><button id="job-edit" class="button button--secondary" type="button" hidden>Изменить настройки</button><button id="job-retry" class="button button--primary" type="button" hidden>Повторить неуспешный этап</button></div>
        </section>

        <section id="complete-screen" class="center-card complete-card" aria-labelledby="complete-title" hidden>
            <span class="section-icon section-icon--success" aria-hidden="true">✓</span><p class="eyebrow">ВСЁ ГОТОВО</p><h1 id="complete-title">GitRePosted установлен</h1>
            <p class="lead muted">Перейдите в панель управления с логином и паролем, которые вы задали.</p>
            <a id="control-link" class="button button--primary">Открыть панель управления <span aria-hidden="true">→</span></a>
            <div class="complete-notes"><p>Подключайте каналы и настраивайте маршруты пересылок в выбранных ботах.</p><p class="small muted">Если вы пропустили платформы, их можно подключить в панели. Доступ к мастеру установки после завершения закрывается.</p></div>
        </section>
    </main>
    <footer class="page-footer"><span>GitRePosted</span><span>Публикации под вашим управлением</span></footer>
</div>
<noscript><div class="noscript-message">Для безопасной пошаговой настройки включите JavaScript и обновите страницу.</div></noscript>
</body>
</html>
