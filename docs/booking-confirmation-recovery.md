# SERVER: ошибка подтверждения на HTTP-origin

Основа — main после PR №16 (`7d712aa`), ветка `fix/server-booking-confirmation`.
Изменения не развёртывались на VPS.

## Установленная воспроизводимая причина

`createServerService()` создавал requestId через `crypto.randomUUID()` до POST,
вне блока обработки HTTP-ошибок. В браузере этот метод требует secure context.
HTTP localhost/loopback считается доверенным исключением, обычный HTTP-IP — нет.
TypeError попадал в общий catch UI с текстом «Результат бронирования не удалось
подтвердить. Повторите отправку той же заявки».

До исправления пройден путь Welcome → Calendar → Time → Contacts на production
SERVER-сборке с настоящими API/SQLite в закрытом временном каталоге. Origin — HTTP
TEST-NET IP `192.0.2.10`, все запросы направлены только к локальному Next через
тестовый loopback proxy. К настоящему VPS не обращались. Результат:

```json
{
  "isSecureContext": false,
  "typeof crypto.randomUUID": "undefined",
  "typeof crypto.getRandomValues": "function",
  "POST /api/bookings": 0,
  "test SQLite bookings": 0,
  "test SQLite booking_events": 0,
  "notice": "Результат бронирования не удалось подтвердить. Повторите отправку той же заявки."
}
```

Нули относятся **только к воспроизведению**, не к прежней заявке заказчика. Боевой
файл SQLite, записи и установленный SHA не читались. По одному сообщению нельзя
заключать, что прежняя заявка не сохранена: потеря ответа после COMMIT тоже возможна.
Никакого удаления/отката/повторного создания боевых заявок не выполнялось.

## Почему прежний CI пропустил сбой

| Окружение | UUID |
| --- | --- |
| Unit transport-тесты | В основном подставляли готовый UUID |
| API/техническая приёмка установщика | Node crypto.randomUUID доступен, формы/браузера нет |
| Backend browser CI | Loopback, isSecureContext=true, randomUUID существует |
| SERVER на временном публичном HTTP-IP | isSecureContext=false, randomUUID отсутствует |

Origin-policy API не менялась: установщик задаёт явный literal-IP HTTP test flag
и фиксированный Origin, произвольный insecure domain запрещён. 403, 400, 429,
SQLite/503, конфликты и неверный ответ имеют отдельные ветви. Схема SQLite, WAL,
FULL synchronous, writer-транзакция, защита пересечений и событие не менялись.
Повтор ID проверяется до ограничения периода новых броней, возвращает прежний
результат без второго события; изменённый payload и отмена не подтверждаются заново.

## Исправление и сохранность повторов

`request-id.ts`: native randomUUID при наличии, иначе UUID v4 из 16 байтов
crypto.getRandomValues с version/variant bits (122 случайных бита). Нет Math.random,
ID по времени/телефону, платных библиотек и серверных импортов в клиенте.
Если криптографическая случайность полностью недоступна, до POST показывается
ошибка подготовки номера, а не сообщение о потерянном ответе. Ранее неизвестная
попытка сохраняет свой UUID/uncertainty даже при ошибке подготовки нового ID.

Проверка HTTP 201 и совпадения ID/даты/времени/ресурса не ослаблена. Потеря ответа
не открывает Confirmation: ручной повтор с тем же ID получает результат прежнего
COMMIT. Автоматических повторов, browser storage и сохранения контактов вне памяти
вкладки нет. После reload in-memory ID, как и раньше, теряется; это ограничение
не исправляется скрытым сохранением персональных данных.

HTTP остаётся только техническим режимом с вымышленными контактами. Совместимость
UUID с ним не заменяет HTTPS перед обработкой реальных персональных данных.

## Обязательный release browser gate

`installer-package.yml` на native Ubuntu 24.04 x64 и ARM64:

1. Сохраняет прежние unit/integration/typecheck/lint, SERVER build и HTTP-тесты.
2. Собирает native SERVER root filesystem для точного source SHA.
3. Проверяет SHA256 и извлекает пакет в закрытый временный каталог.
4. Запускает упакованные Node/Next, не checkout-сборку.
5. Выполняет `npm run test:server:browser`: весь SERVER suite desktop/mobile в
   localhost и в настоящем insecure HTTP context. Для каждого — новая отдельная SQLite.
6. Выполняет прежнюю systemd/rollback приёмку CI. Публикация возможна только после
   всех проверок; нет skip/continue-on-error. Установка использует тот же workflow.

Проверка main сохраняет требование успешного Check universal installer для точного
SHA. Новый код сам не запускает install/deploy/SSH. В приложении нет дополнительного
процесса: loopback proxy — временный fixture, закрываемый после тестов. Не меняются
firewall, SSH, VPN, DNS и существующие службы.

Тесты проверяют isSecureContext=false, отсутствие native randomUUID и наличие
getRandomValues без подделки crypto и без флага «считать HTTP безопасным». Proxy
допускает только TEST-NET authority, upstream всегда loopback, Origin/Host сохраняются.
Контакты вымышленные, PII в console/pageerrors запрещены. Для stress/rate-limit тестов
сохраняется доверенный тестовый IP-header; отдельные реальные HTTP-тесты проверяют
API_TRUST_PROXY=false и игнорирование поддельных forwarded headers.

Проверка потерянного ответа сначала получает настоящий 201 и сверяет ID/status
в тестовой SQLite, затем намеренно теряет ответ. После повтора остаются **одна
бронь и одно событие**. Проверяются двойной клик, конкурирующие клиенты, 400/409/429,
настоящая readonly SQLite/503 и восстановление, reload/занятость, пять экранов и 320–1440 px.

## Проверка без production-данных

```bash
npm ci
npm test
npm run test:integration
npm run typecheck
npm run lint
npm run build:server
npx playwright install --with-deps chromium
# Системный Chromium можно выбрать через CHROMIUM_PATH.
npm run test:server:browser
npm run test:server:http
npm run test:api:http
npm run test:server:http:failure
npm run test:demo:isolation
# Прежние SERVER + экспортированный DEMO browser suites:
npm run test:server:ui
```

Harness создаёт свои studio-server-ui-* каталоги, базы и loopback listeners.
Переданные SQLITE_PATH/SERVER_BASE_URL не становятся рабочей базой/удалённым сервером.
Browser outputs временные и не входят в SERVER archive. STUDIO_E2E_RELEASE_ROOT
принимает только распакованный fixture studio-browser-package-* внутри temp/
runner-temp, а не установленное приложение.

Production SQLite не читалась. Отдельный workflow для её чтения не потребовался:
client-side дефект воспроизведён до POST. Нового публичного диагностического API нет.
Результаты и ограничения проверки — в [отчёте PR](acceptance/server-booking-confirmation/PR.md).

## Проверка упакованного приложения и архитектур CPU

Локальная x64-сборка выполнена в Ubuntu 24.04 с закреплённым Node 24.12.0 и
исходным packager. SHA256 тестового архива:
`e8df0b0f0855e14e9ea9ddd2aeb9233dc963b82a240bfe71391d81c71938d3be`.
После распаковки запускались именно его Node/Next с отдельными SQLite; все 40
SERVER browser-проверок прошли. Это локальная проверка, не запуск systemd на VPS.

ARM64 SERVER production build также прошёл в Ubuntu 24.04 с Node 24.12.0 через
user-space эмуляцию ARM-инструкций. Нативный ARM64 better-sqlite3 открыл настоящую
in-memory SQLite и выполнил запрос версии (3.53.4). Эмуляция не заменяет native
ARM64 GitHub runner, его browser/systemd проверки или проверку CI на итоговом SHA.

ARM64 packager прошёл проверки native-зависимостей, allowlist и создание manifest.
Node и better-sqlite3 имеют ELF machine AArch64 (183). Для локального fixture
архивирование этого неизменённого staging-каталога выполнено Python на x64-хосте;
дублирующее медленное сжатие под эмуляцией остановлено. SHA256 ARM64 fixture:
`679ce591ec739d77db8a7916c7767526fb2ad5b0862a03eec80d049cff311416`.
Это не результат полного native ARM64 release workflow; браузерные проверки этого
ARM64-архива локально не запускались.

Эти временные fixture-пакеты имеют тестовый version marker, не опубликованы и не
предназначены для установки. Docker/rootfs использовались только как локальные
инструменты сборки/эмуляции; дополнительных компонентов на VPS или в архитектуру
приложения не добавлено. Kernel binfmt, сервисы хоста и настройки VPS не менялись.
