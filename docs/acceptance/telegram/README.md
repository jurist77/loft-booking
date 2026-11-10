# Приёмка Telegram-уведомлений

Изменения подготовлены в `feat/telegram-booking-notifications`. Production, VPS, реальные Telegram-чаты, рабочая база и backup-репозиторий не использовались. Merge/deploy не выполняются этим этапом.

## Проверенное поведение

| Проверка | Доказательство |
|---|---|
| Новая бронь → все активные получатели, повтор POST без дублей | SQL trigger/unique index; настоящая SQLite; HTTP lost-reply/replay через production Next |
| Атомарность booking/event/outbox | Инъекция ошибки outbox: вся транзакция откатывается |
| Отключение до/во время обработки | Два реальных SQLite connection, writer serialization на старте и свободная БД во время HTTP ожидания; pending/claimed отменяются |
| Независимость получателей и бронирований от Telegram | Постоянная ошибка одного recipient, успешный второй, бронь остаётся confirmed |
| Повторы, общий 429 retry_after, срок 24 часа | Управляемые часы + подмена Telegram; граница deadline, pause/resume и отказ повторять просроченное |
| Аварийный перезапуск | Настоящий дочерний Node-процесс: claim COMMIT → SIGKILL → lease expiry → новый sender, одна строка задания |
| Durable polling | Stop/restart с новой lease, одноразовое подключение и cursor; ошибка записи cursor откатывает привязку |
| Приглашения | SHA-256, TTL, replay, spoofed identity, group/bot sender, ограничение попыток, 40 recipients |
| Локальный оператор и будущие права | Реальный Node CLI subprocess; отказ мутации без local-operator, private invite file, авторизатор/permission на каждом методе server layer |
| Формат/секреты | Москва, длительность, plain text без markup/control injection; token/PII не попадают в технические ошибки; private config отклоняет unsafe permissions/links |
| Существующие данные и копии | Upgrade 0002→0003 без backfill/изменения старых SQL; настоящий SQLite Backup API/restore; GPG archive roundtrip защищённого synthetic bot config |
| Обновление/restore пакета | В обязательный real-systemd сценарий Installer CI добавлена проверка сохранности pending job и packaged Node CLI после update/restore/rollback |
| DEMO | Node/static builds с невалидной SERVER/Telegram конфигурацией; private-value canaries и аудит экспортированных файлов; существующие E2E запрещают передачу контактов |

## Локальные результаты

- `npm test`: 165 passed.
- `npm run test:integration`: 77 passed (настоящая SQLite, включая 20 Telegram integration).
- `npm run typecheck`, `npm run lint`: passed.
- `npm run build:server`: passed.
- `npm run test:api:http`: 19 checks passed, в том числе notification outbox после потери HTTP-ответа; настоящий Next/SQLite, подменён только Telegram.
- `npm run test:server:http`: три цикла 200→503→200 и write-denied/recovery прошли. Negative control `test:server:http:failure` подтвердил ненулевой выход при постоянной недоступности БД.
- `npm run test:demo:isolation`: Node DEMO, static DEMO, секретные canaries и экспорт прошли; `npm run audit:demo`: 29 файлов, утечек не обнаружено.
- `npm run test:server:ui`: 20 SERVER localhost + 20 SERVER insecure-test HTTP + 26 DEMO browser cases passed. Только изолированная тестовая SQLite/вымышленные контакты.
- Python installer/security tests: 68 passed; HTTPS: 63 passed. Диагностика: 65 passed; quarantine: 16 passed; VPS audit: 11 passed; firewall: 45 passed, 5 root-only checks пропущены локально и остаются обязательными на CI runner.

Сценарии root/systemd, нативные пакеты и TLS выполняются только на одноразовых GitHub runners Ubuntu 24.04, x64 и ARM64. Локальная Cloud-среда не заменяет эти проверки. Итоговые статусы **Backend foundation**, **Universal installer x64/ARM64**, HTTPS/network/firewall/audit находятся в checks соответствующего PR и проверяются на итоговом SHA перед отчётом заказчику. Автоматическая публикация DEMO из main не меняется.

## Границы доказательств

Транспорт Telegram в тестах подменён; реальная доставка не заявляется проверенной. Получатели/токен production не созданы. Первая настройка, защищённое приглашение владельца и техническое тестовое сообщение описаны в [инструкции](../../telegram-notifications.md). Авторизация веб-панели, её UI и публичные admin endpoints отсутствуют.

Нет гарантии exactly-once после потери ответа Telegram/аварии после принятия сообщения. Уже начатую отправку нельзя гарантированно отозвать. Восстановленная на другом VPS база не должна работать параллельно с исходным ботом. Эти ограничения и правила обработки персональных данных требуют принятия владельцем перед включением.
