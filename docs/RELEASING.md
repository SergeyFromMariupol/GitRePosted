# Сборка и выпуск

Публичный комплект создаётся из проверенных исходников по точному списку
scripts/build.py. Экспорт не выполняет Git-команды, не создаёт репозиторий и
не публикует данные. Installer source не обязан содержать вторую копию
runtime: maintainer явно передаёт authoritative application directory.

```bash
python3 -B scripts/export.py --runtime-source /path/to/reviewed-application --destination /path/to/generated-checkout
```

Входной каталог runtime должен содержать только ожидаемые application targets;
экспорт читает исключительно перечисленные имена. Реальные env, DB, sessions,
серверные конфиги, история, logs и private инструкции не читаются и не
копируются. LICENSE публичного комплекта должен быть заранее сверенным MIT
оригиналом. Новые файлы добавляются в allowlist после проверки.

Exporter выполняет ограниченные изменения distribution metadata: добавляет
`license: MIT` в package.json и корневую запись package-lock.json, а также
меняет npm test на `node --test ../../tests/runtime/*.test.mjs`. Это позволяет
запускать включённые offline suites из payload/src. Версии зависимостей,
resolved URLs и integrity не меняются; authoritative application не правится.
Repository/homepage/issues metadata указывает на фактически созданный
`https://github.com/SergeyFromMariupol/GitRePosted`.
Text files нормализуются в LF в соответствии с .gitattributes; бинарные assets
не меняются. Исходные файлы при этом остаются на месте с исходными байтами.

Первый destination должен быть пустым. Допускается существующая обычная `.git`
директория; её содержимое не просматривается и не изменяется. Экспорт создаёт
собственный marker с SHA256 каждого принадлежащего ему файла. Последующий
экспорт откажется при чужом файле или ручной правке. Не удаляйте marker и не
перезаписывайте чужие изменения ради обхода проверки. `install.sh` может быть
добавлен отдельно как зафиксированный release loader; exporter его сохраняет.

Из generated checkout выполните проверки в TESTING.md, затем:

```bash
python3 -B scripts/build.py --output /path/to/release-artifacts
```

Для maintainer также поддерживается сборка непосредственно из installer
source с явным `--runtime-source /path/to/reviewed-application`. Команда
проверяет каждый файл, строит детерминированный tar.gz и внешний SHA256.
Распакуйте в отдельный пустой каталог и выполните `--verify-manifest`.
Два запуска при одинаковых байтах исходников должны дать одинаковый SHA256.

Перед выпуском подтвердите: весь allowlist проверен; examples содержат только
общие пути и placeholders; lockfile согласован; Node/PHP/Python suites прошли;
свежая VPS и реальные тестовые каналы проверены; docs честно отражают результат.
В rc.1 свежая VPS пока не подтверждена — не обозначайте его stable.

Публикация GitHub — отдельное действие. Сначала создайте настоящий repository,
проверьте URL и permissions. Затем опубликуйте соответствующий tag, архив и
checksum. Подставьте фактический HTTPS asset URL и SHA256 в копию
scripts/release-loader.sh; шаблон с placeholders запускаться не должен.
`install.sh` не входит в архив, поэтому его pin не создаёт циклический hash.
Проверенную curl-команду добавляют в README только после проверки реальных
ссылок. Не меняйте assets уже выпущенного tag незаметно для пользователей.
