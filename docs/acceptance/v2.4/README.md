# Приёмка SERVER-клиента 2.4

Основание — `main` `756c9e153bd52ba1d0e23bdb191005e8e4beaa13` после PR №9. Ветка `feat/booking-server-ui-v2.4`. Проверки 19 октября 2026, Node 24.19.0, Next 16.4.2, SQLite 3.53.4 / better-sqlite3 13.0.3. CI/SHA и итоговый статус PR указаны в описании Pull Request.

## Результат

Те же пять экранов в SERVER читают занятость из SQLite через GET и подтверждают POST только после сохранения. Нет фиктивной свободной сетки при ошибке, двойной отправки или ложного подтверждения. Unknown-попытка сохраняется в памяти с UUID; Retry-After учитывается, ручной повтор безопасен. Контакты/дата сохраняются при ошибках, занятое время сбрасывается. На SERVER Confirmation нет контактов, показаны дата/время/длительность/UUID. [Путь, диаграмма состояний, ошибки и запуск](../../server-client-v2.4.md).

DEMO по прежнему адресу https://jurist77.github.io/loft-booking/ сохраняет fixtures/предупреждения и прежний путь. Его 26 браузерных проверок прошли; HTTP-транспорт SERVER удаляется из сборки, все прежние audit-assertions сохранены. При съёмке DEMO отправил **0 API-запросов** и создал **0 строк**. SERVER действительно создал по одной записи на каждом из двух устройств в private temp SQLite. Тестовые данные/процессы очищены; локальная рабочая БД не использовалась.

## Автоматические проверки

| Проверка | Результат локально |
|---|---|
| Unit | 151 passed, включая 17 HTTP-client проверок |
| Integration | 57 passed, настоящая SQLite, прежние проверки сохранены |
| API HTTP | 18 групп passed: настоящий production Next + SQLite |
| SERVER E2E | 20 passed: 10 сценариев × desktop/mobile |
| DEMO E2E | Все прежние 26 passed на статическом экспорте |
| TypeScript / lint | Passed |
| SERVER build | Passed |
| Node DEMO / static DEMO | Passed; неверные DB/API-настройки игнорируются |
| Health HTTP | Три 200→503→200, readonly→503→200, прежний persistent-failure negative control passed |
| Audit static | 29 файлов, все локальные ресурсы существуют, нет секретов/server/native/SQLite; audit не изменён |
| Снимки | 20 PNG; 5 экранов × SERVER/DEMO × компьютер/телефон; телефон скрыт |

E2E: полный путь и повторное открытие занятости после reload, двойное нажатие, два клиента на один интервал, Back со свежим GET и сбросом stale-выбора, другая дата, ошибка загрузки/повтор, 400 и изменение UUID при исправлении, фактический COMMIT с потерей HTTP-ответа и повтором того же ID, реальный readonly SQLite/503/восстановление, 429/Retry-After без автоматических POST, осознанное изменение unknown-попытки. Все пять экранов проверены на ширинах **320, 360, 375, 390, 430, 768, 1024, 1440** без горизонтальной прокрутки. Клиентские логи не содержат контактов/необработанных ошибок.

Unit дополнительно проверяет тайм-аут/abort, отсутствие автоматических повторов, UUID/canonical phone, неизвестный/неправильный успешный ответ, failed GET без подмены пустым днём, HTTP-date Retry-After, общий send-lock и запрет неосознанного изменения unknown-попытки. Route interception в UI-тестах моделирует ошибки транспорта/400/429; реальные запись, конфликт двух клиентов, потеря ответа после COMMIT и отказ SQLite проверяются на настоящем Next/SQLite. API HTTP/Integration используют настоящие запросы/базу. Не заявляется, что все транспортные сбои воспроизведены физическим обрывом сети.

## Визуальное сравнение

Все контакты вымышленные; телефоны скрыты. Полный UUID относится только к удалённой тестовой записи. Существующий логотип владельца/фото не менялись. Снимки — браузерные, без генерации изображений.

| Экран | SERVER компьютер | DEMO компьютер | SERVER телефон | DEMO телефон |
|---|---|---|---|---|
| Welcome | [Открыть](server-desktop-01-welcome.png) | [Открыть](demo-desktop-01-welcome.png) | [Открыть](server-mobile-01-welcome.png) | [Открыть](demo-mobile-01-welcome.png) |
| Calendar | [Открыть](server-desktop-02-calendar.png) | [Открыть](demo-desktop-02-calendar.png) | [Открыть](server-mobile-02-calendar.png) | [Открыть](demo-mobile-02-calendar.png) |
| Time | [Открыть](server-desktop-03-time.png) | [Открыть](demo-desktop-03-time.png) | [Открыть](server-mobile-03-time.png) | [Открыть](demo-mobile-03-time.png) |
| Contacts | [Открыть](server-desktop-04-contacts.png) | [Открыть](demo-desktop-04-contacts.png) | [Открыть](server-mobile-04-contacts.png) | [Открыть](demo-mobile-04-contacts.png) |
| Confirmation | [Открыть](server-desktop-05-confirmation.png) | [Открыть](demo-desktop-05-confirmation.png) | [Открыть](server-mobile-05-confirmation.png) | [Открыть](demo-mobile-05-confirmation.png) |

Воспроизводимость: после SERVER и static builds выполнить `npm run test:server:ui -- --capture-only`. Проверки съёмки — [checks.json](checks.json). Публичный SERVER/встроенный preview не публиковался; локальные адреса runner не являются ссылками для заказчика.

## Изменённые файлы

- `src/lib/server-booking-service.ts`, `.test.ts`: HTTP-клиент и проверки.
- `src/lib/booking-service.ts`: общий контракт и discriminated confirmation, прежний DEMO-адаптер сохранён.
- `src/components/booking-client.tsx`, `booking.tsx`: выбор адаптера, загрузка/ошибки, переходы и безопасная отправка.
- `src/components/contact-form.tsx`, `confirmation.tsx`, `welcome.tsx`: блокировка во время отправки, SERVER-итог без контактов, корректные тексты режима.
- `src/app/page.tsx`, `globals.css`: SERVER-маркировка и перенос UUID; цвета/логотип/структура не меняются.
- `e2e-server/flows.ts`, `booking.spec.ts`, `playwright.server.config.ts`: браузерная приёмка SERVER.
- `scripts/verify-server-ui.mjs`, `capture-v24.mjs`: отдельное временное окружение и снимки.
- `scripts/verify-server.mjs`: прежние health-проверки сохранены, утверждение о выключенной записи заменено проверкой нового SERVER Welcome без demo slots.
- `package.json`, `.github/workflows/backend-checks.yml`: команда UI-тестов и браузерный CI. Новых зависимостей нет.
- `README.md`, `docs/backend-architecture.md`, `backend-local-setup.md`, `demo-deployment.md`, `server-client-v2.4.md`, эта папка: актуальный запуск, отчёт и материалы.

`src/server`, API, миграции 0001/0002, общие правила времени/контактов/выбора, изображения, AGENTS.md, lockfile и Pages workflow не изменены. Проверки не отключены.

## Ограничения

Перезагрузка очищает память попытки, но не отменяет уже сохранённую/отправленную бронь; до ответа повторять в той же вкладке. Для восстановления потерянного ID нет публичного lookup API. Администратор пока с заглушкой контакта. Правовые основания обработки данных, HTTPS/proxy/edge limits/backup и защита от ложных заявок необходимы до production. Local limiter сбрасывается при рестарте, без trusted proxy общий для клиентов; Origin не аутентифицирует ботов. Эти ограничения этапа 2.3 не скрыты и здесь не заменены дополнительными сервисами.

Нет публичной отмены/изменения, админки, уведомлений, оплаты и VPS. Визуальная приёмка требуется; merge и следующие этапы не выполняются автоматически.
