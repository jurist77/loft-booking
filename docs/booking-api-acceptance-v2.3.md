# Проверка API — этап 2.3

19 октября 2026. Основание `main` `c4da080bb267735eec54eb540e5c3c0eed0225dd` (PR №8 объединён); ветка `feat/booking-api-v2.3`. Контракт, примеры, HTTP-коды и безопасность: [booking-api-v2.3.md](booking-api-v2.3.md).

## Изменения

- Два SERVER Route Handlers: `src/app/api/availability/route.server.ts`, `src/app/api/bookings/route.server.ts`.
- `src/server/bookings.ts`: чтение только публичных интервалов в read-транзакции, общая проверка ID. Создание/отмена/пересечения/идемпотентность модели сохранены. Миграции 0001/0002 не меняются.
- `src/server/booking-api.ts`: транспорт, безопасный результат после COMMIT, отменённый повтор без реактивации.
- `src/server/api-input.ts`: строгий плоский текстовый JSON, UUID, длины/поля, 4096 байт и 5 секунд, защита от дублированных ключей, формат даты/времени. Бизнес-правила остаются общими.
- `src/server/api-security.ts`: фиксированный Origin, явное доверие proxy, bounded per-client/global limiter в памяти одного процесса.
- `src/server/api-errors.ts`: безопасные коды/HTTP, no-store, Retry-After, без SQL/путей/контактов.
- `src/server/api.test.ts`, `tests/integration/booking-model.test.ts`, `scripts/verify-booking-api.mjs`: автоматические проверки безопасности, SQLite и настоящего HTTP.
- `.env.example`: только примеры Origin/proxy, без секретов. `package.json`: команда `test:api:http`, без новых зависимостей.
- `.github/workflows/backend-checks.yml`: добавлен API HTTP-тест, прежние шаги сохранены.
- `scripts/verify-demo-isolation.mjs`: дополнительно проверяет Node DEMO 200/404 с невалидной серверной конфигурацией; прежняя static build/audit сохранена. `scripts/audit-demo.mjs`: дополнительные серверные маркеры/канарейка Origin.
- `README.md`, `docs/backend-architecture.md`, `docs/backend-local-setup.md`, `docs/demo-deployment.md`, два документа этапа 2.3: контракт/запуск/ограничения/отчёт.

Клиентские компоненты, src/lib, логотип, изображения, стили, page/layout, next.config и Pages workflow не менялись. Реальные контакты не используются. Внешние компоненты/платные сервисы/VPS отсутствуют.

## Результаты локальной проверки

Node **24.19.0**, SQLite **3.53.4**, better-sqlite3 **13.0.3**, Next **16.4.2**.

| Команда/проверка | Результат |
|---|---|
| `npm test` | 134 passed, включая 19 новых проверок API/security |
| `npm run test:integration` | 57 passed, настоящая SQLite; прежние 55 сохранены |
| `npm run test:e2e` | 26 passed: desktop/mobile, пять экранов, контакты не передаются/не сохраняются |
| `npm run test:api:http` | 18 групп passed; настоящий production Next и private temp SQLite |
| `npm run typecheck`, `npm run lint` | Passed |
| `npm run build:server` | Passed; availability/bookings/health — динамические SERVER-маршруты |
| `npm run test:server:http` | Passed: три 200→503→200 и readonly→503→200, один процесс |
| `npm run test:server:http:failure` | Passed: постоянная недоступность даёт ожидаемый exit 1; восстановление/cleanup успешны |
| `npm run build` | Node DEMO build passed |
| `npm run test:demo:isolation` | Node DEMO: главная 200, все API 404; static build/audit passed с недоступной SQLite и невалидным Origin/proxy |
| Аудит static DEMO | 29 файлов, local assets существуют, нет private/server-файлов, credential patterns или канареек |

Итоговый GitHub Backend CI подтверждается в PR после завершения запуска; этот документ не заменяет статус CI. Приёмка не означает merge/публичный запуск.

18 HTTP-групп включают пустую/занятую доступность, сортировку и приватность GET, ресурс/дату/границу +3 месяца, создание и нормализацию контактов, повтор UUID/изменённый payload, потерянный HTTP-ответ, конкурентные POST/повторы, соседство/разные ресурсы, отменённые и прошедшие записи, закрытую схему JSON/UTF-8/дубли ключей, actual-byte limit/chunked/slow-body timeout, фиксированный Origin, блокировку SQLite/безопасный 503/восстановление, пропажу файла/readonly, перезапуск настоящего Next, per-client/global rate limits и режим без доверия IP-заголовкам. GET остаётся доступен при writer-lock; health обнаруживает отказ записи и восстанавливается. Имена и телефоны отсутствуют в ответах и захваченных логах Next.

Модульные проверки дополнительно подтверждают reset окна limiter через 60 секунд и канонизацию IPv6. Нагрузки/ошибки проверяются реальными запросами; моки SQLite или HTTP не используются. Все тестовые Next-процессы и временные базы очищаются; рабочая локальная БД не затрагивается.

## Ограничения и готовность 2.4

API готов для отдельной приёмки и последующего подключения интерфейса в 2.4. Без публичных отмены/изменения/списка/получения контактов по ID, без авторизации/админки, уведомлений или оплаты. UI остаётся DEMO, API к нему не подключён. Backend CI не публикует DEMO; Pages workflow по-прежнему работает после согласованного merge main.

До реального запуска нужны правовые основания обработки контактов и настройка HTTPS/reverse proxy: Next только loopback, trusted header **перезаписывается** proxy, прямой доступ закрыт, точный Origin, edge limits/тайм-ауты и защита health. Здесь настоящий Nginx/VPS не настраивался: HTTP-тесты проверяют контракт trusted header, не подтверждают безопасность будущей инфраструктуры.

Limiter локальный и сбрасывается при перезапуске. Общий fallback ограничивает всех вместе, NAT/смена IP и глобальное исчерпание бюджета могут мешать клиентам; Origin не останавливает бот с произвольными заголовками. Полноценная защита от ложных заявок/DDoS не заявляется. SQLite — один писатель на локальном диске, FULL не заменяет внешние backup и проверку восстановления. Эти ограничения не скрываются и не требуют Redis/дополнительных компонентов на данном этапе.
