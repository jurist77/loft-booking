# Приёмка: Telegram-подписки и владелец

Основа: main `204be076503355aa031ac206b4e73250fe4cdb92` (после PR31). Ветка `feat/telegram-subscriptions`. Нет merge, deploy, подключения к VPS, настоящего токена или отправок Telegram. Изменены только Telegram, добавочная миграция, workflow настройки, тесты и документация.

## Что реализовано

- Manage Studio Telegram: configure / rotate-token / bootstrap-owner / diagnose, только main и проверенный SHA.
- Первичное подтверждение по временному Secret с кодом, выданным в приватный чат конкретного Telegram-аккаунта. Start и знание username не дают прав.
- Заявки и решения, самостоятельное отключение, подтверждаемое удаление, повторная подписка с новым одобрением; меню с пагинацией без ограничения числа сотрудников.
- Один владелец, независимая подписка; пауза, технический тест, статус; передача роли после двух подтверждений.
- Live-проверка роли, actor/epoch/version/TTL и HMAC/одноразовые callbacks. Курсор и изменения от Telegram update сохраняются одной транзакцией.
- Существующие outbox/24ч/WAL/FULL/worker, дополнительные управляющие ответы в той же SQLite и том же worker. Нет HTTP admin API/веб-панели.
- Проверка getMe и bot ID до атомарной записи; проверка polling текущей конфигурации до SUCCESS. Получатели и очередь не сбрасываются.
- Защита поддержанного переноса через host binding и уже существующие GitHub Deployment metadata. Вторая независимая восстановленная копия не начинает polling сама.

## Подтверждённые локальные проверки

Среда разработки Linux x64, Node24.19.0; для браузеров установленный `/usr/bin/chromium`. Все данные вымышленные; Telegram API подменён. Native Ubuntu/systemd/ARM-проверки выполняет неизменённый обязательный CI, а не production VPS.

| Проверка | Результат |
| --- | --- |
| `npm test` | 165 passed |
| `npm run test:integration` | 96 passed, реальная SQLite; 19 новых Telegram сценариев |
| Installer/security Python | 89 passed, включая 14 сценариев Actions/SSH и GPG backup/restore v1/v2 |
| HTTPS Python | 88 passed |
| VPS audit Python | 11 passed |
| Firewall Python | 45 passed, 6 kernel-сценариев не выполнены локально; реальные изолированные kernel-проверки обязательны в HTTPS CI |
| `npm run typecheck`, `npm run lint` | Passed, без предупреждений |
| `npm run build:server` | Passed; прежние availability/bookings/health routes |
| `npm run test:server:http` | 3 цикла200→503→200, запрет записи/восстановление, Next не падает |
| `npm run test:server:http:failure` | Ожидаемая постоянная503 даёт ненулевой exit; cleanup подтверждён |
| `npm run test:api:http` | 19 passed; настоящие HTTP/SQLite, Origin/idempotency/lock/recovery |
| `npm run test:server:browser` | 40 passed, localhost и insecure-test HTTP; desktop/mobile, ширины320–1440 |
| `npm run test:demo:isolation` | Node DEMO + static DEMO + audit passed при невалидных SQLite/API/Telegram env; canary/секреты отсутствуют |
| `npm run test:e2e` против статического DEMO | 26 passed, desktop/mobile, без реального API |

Коды/статусы Github CI нужно смотреть на **итоговом SHA** во вкладке Checks отдельного PR, не переносить успех прежних запусков. Обязательны Backend, Installer x64/ARM64 (native package/browser/Caddy/systemd/update/restore/rollback), HTTPS x64/ARM64/kernel и VPS Audit. Этот документ фиксирует выполненные локальные проверки; фактические CI run URLs и SHA приводятся в итоговом отчёте PR.

## Что покрывают новые тесты

- Невозможность first-Start/self-admin, чужого/просроченного/повторного bootstrap; group/bot/spoof отбрасываются; в SQLite только хеши.
- Одна pending-заявка/одно уведомление, одобрение/отказ, no historic booking backfill, подтверждённые подписчики, disable/cancel/rejoin.
- Owner unsubscribe не удаляет роль; pause/status/test работают независимо. Две стороны передачи роли, старые кнопки/ожидающие owner-ответы аннулируются; удалённый кандидат не принимает старое предложение.
- Временные ошибки/429/24ч/backup/restart, бронь остаётся confirmed при ошибке Telegram, отсутствие дублей booking jobs.
- Откат request/outbox/update offset при искусственной ошибке SQLite; настоящий long-poll session проводит update через меню и контролирует конфигурацию.
- Валидный/невалидный/чужой bot ID, v2 атомарный private-файл, неизменные пользователи/key после ротации; heartbeat прежнего токена не подтверждает готовность нового.
- Native Node CLI со stdin, реальная SQLite, безопасная JSON-ошибка; официальный API контракт кнопок/plaintext без parse_mode.
- Restore другого instance блокирует worker; защищённые settings и signing key переживают реальный GPG round-trip. Существующие installer restore/rollback тесты сохранены.
- Actions: повторный configure, same/different instance, незавершённая запись GitHub/SSH, неверный пароль, timeout/cleanup, Summary schema/redaction, root-bridge под существующим service UID без рестартов и конфигурационных изменений.

## Приёмка владельцем после PR

Полная пошаговая инструкция: [Telegram](../../telegram-notifications.md). После отдельного согласования: штатно обновить Studio, добавить Secret токена, configure, получить код в личном чате, подтвердить через временный Secret/bootstrap-owner, удалить временный Secret, включить рассылку в меню, выполнить технический тест и проверить заявки/передачу. В рамках разработки эти действия не выполнялись.

Ограничения: exactly-once Telegram невозможен при потере ответа; уже принятые сообщения не отозвать. Поддержанная межсерверная координация действует в рамках одного репозитория; не защищает от намеренного обхода root/ручного клонирования. Для ранее использованного бота и переноса на другой VPS требуется перевыпуск токена BotFather. После штатного restore даже на прежнем VPS Telegram требует перевыпуска токена и rotate-token: restore заменяет DATA и не переносит host nonce; подписчики/роль/очередь сохранены. Старый v1-файл сохраняется, но требует configure v2. Настоящие Telegram/VPS проверки остаются на отдельно согласованное включение. До production владелец определяет законное основание передачи контактов клиентов в Telegram.
