# Проверки rc.1

Это предварительный выпуск. До публикации готового установщика требуются
проверка на свежем Ubuntu Server 24.04, проверка свежей MySQL-схемы и реальные
проверки выбранных платформ. На момент подготовки этого документа эти live
сценарии **ещё не выполнены**. Успех offline suites не означает, что VPS,
сертификат, webhook и доставка проверены.

Проверен экспортированный комплект: runtime **91 PASS, 1 Windows symlink
permission skip** из 92; packaging **11 PASS, 1 такой же host skip** из 12;
Node provisioning **11 PASS**. Отдельный синтетический Windows review
подтвердил отказ для junction sources/destinations и hardlinked source files.
Для этих suites используйте Node.js 24, Python 3 и PHP CLI для PHP-проверок.

В экспортированном checkout или распакованном полном комплекте:

```bash
python3 -B tests/package_test.py
node --test tests/runtime/*.test.mjs
php tests/application-test.php
python3 -B tests/broker-node-test.py
python3 -B tests/provision-node-test.py
php tests/wizard-test.php
php tests/wizard-audit-test.php
node --test tests/ui.test.cjs tests/url-consent.test.cjs
```

Runtime suites используют Node built-ins и временные fixtures: форматирование,
media splitting, streaming, idempotency, lease heartbeat, auth и rate limits.
Module suites не запускают сервер. portable-server запускает копию настоящего
entrypoint в временном каталоге с fake MySQL и запрещённым provider fetch;
HTTP-запросы идут только на loopback. Он проверяет CLI schema contract,
авторизацию, смену пароля, durable enqueue и подключение платформ после
установки. Эти проверки не читают рабочую конфигурацию, не меняют реальные
webhook и не отправляют публикации. Python package tests проверяют детерминированность,
manifest, allowlist, секреты, symlink и защиту чужих файлов при экспорте.
Остальные suites тестируют соответствующий компонент через fixtures; их
наличие не заменяет выполнения. Для Node runtime установка зависимостей
проводится только через `npm ci --omit=dev` по package-lock.json.

## Browser suites

Для браузерных fixtures нужен Playwright с Chromium. Это dev-инструмент;
он не входит в dependencies приложения и не нужен работающему боту. На Linux
установите его в отдельный временный или developer-каталог вне checkout:

```bash
GITREPOSTED_DEV_DIR="$(mktemp -d -t gitreposted-browser-dev.XXXXXXXX)"
npm install --prefix "$GITREPOSTED_DEV_DIR" --no-save --package-lock=false playwright
"$GITREPOSTED_DEV_DIR/node_modules/.bin/playwright" install chromium
export NODE_PATH="$GITREPOSTED_DEV_DIR/node_modules"
node --test tests/ui-browser.test.cjs tests/wizard-audit-ui.test.cjs tests/deep-wizard-ui.test.cjs
```

Node.js, npm и системные зависимости Chromium должны быть доступны в среде
разработки. Системные библиотеки браузера при необходимости подготавливаются
отдельно администратором; не запускайте installer ради подготовки dev-среды.
Вместо NODE_PATH можно задать `PLAYWRIGHT_MODULE` абсолютным путём к модулю
Playwright. Если Chromium уже установлен, `UI_BROWSER_EXECUTABLE` задаёт путь
к его исполняемому файлу Chrome/Chromium; иначе Playwright использует скачанный
браузер. Не задавайте DEEP_WIZARD_SCRIPT для штатной проверки комплекта:
это необязательный override отдельного script fixture. Browser suites
перехватывают все запросы и не обращаются к bot API.

Сборка и проверка распакованного архива:

```bash
python3 -B scripts/build.py --output ../release-artifacts
tar -xzf ../release-artifacts/gitreposted-installer.tar.gz -C ../verification
python3 -B scripts/build.py --verify-manifest ../verification/gitreposted-installer
```

Каталог `../verification` создайте заранее. Артефакты и распаковка должны
находиться вне исходников. Не запускайте bootstrap или provision на рабочей
машине ради unit-теста: эти команды меняют систему.

Контрольный сценарий свежей VPS: установка по полному выпуску, HTTPS по IP и
домену, выключенные платформы, Telegram-only, MAX-only, обе платформы, restart
на каждом этапе мастера, вход/выход/смена пароля, закрытие `/install/`, свежая
схема, включение workers только в конце, передача текста/фото/альбома,
проверка прав на чужие каналы, обратное эхо и неопределённый provider response.
Реальные публикации выполняются только с разрешения владельца и в названные
тестовые каналы. Нельзя для этого запускать копию production-очереди.
