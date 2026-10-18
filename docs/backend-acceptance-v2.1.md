# Приёмка backend foundation 2.1

> Исторический отчёт PostgreSQL-этапа. Текущая SQLite-архитектура и проверки: [sqlite-acceptance.md](sqlite-acceptance.md). Исправления HTTP из PR №6 сохранены при адаптации.


Дата локальной проверки: 18 октября 2026. Ветка: `feat/backend-foundation-v2.1`, основание — актуальный на начало работы `origin/main`, `06dea2426dd421a0aa8c2b398aaf19518b841fa1`. Изменения предназначены для отдельного PR; merge и VPS-развёртывание не выполняются.

## Фактическая среда

- Node.js **24.19.0**, npm **11.9.0**.
- Docker Engine **28.4.0**, Docker Compose **2.40.3**.
- Официальный образ **postgres:17-alpine**, запущенный PostgreSQL **17.11**. Основная версия закреплена; patch-обновления образа допускаются, точный будущий patch не фиксируется этим тегом.
- Два локальных Compose projects: `studio1925-dev` и `studio1925-test`. Разные базы, роли, случайные пароли и именованные volumes; host-порты только **127.0.0.1:54329/54330**.
- Браузерные проверки — Chromium на desktop 1440 px и mobile 390 px; тест Welcome также проверяет 320/375 px и короткие экраны. Физические iPhone/Mac и Safari в этой среде не проверялись.

## Результаты

| Проверка | Результат |
|---|---|
| `npm test` | **115 passed**, 9 файлов; прежние 104 клиентских теста сохранены |
| `npm run test:integration` | **9 passed**, настоящая отдельная PostgreSQL, без mock БД |
| `npm run test:e2e` на Node DEMO | **26 passed**, desktop/mobile, полный путь |
| `npm run test:e2e` на static DEMO `/loft-booking/` | **26 passed**, desktop/mobile, полный путь |
| `npm run typecheck` | Успех |
| `npm run lint` | Успех |
| `npm run build` | Успешная Node DEMO-сборка |
| `DATABASE_URL= MIGRATION_DATABASE_URL= npm run build:server` | Успех без подключения к БД; `/api/health` — динамический Route Handler |
| `npm run test:demo:isolation` | Успешный static export при остановленных dev/test БД и недоступной canary-строке подключения; явный DEMO переопределяет входной APP_MODE=server |
| `npm run audit:demo` с canary-секретами и отдельно с локальным env | **29 файлов**, 762773 байта; секреты, серверный код/API и source maps не найдены; локальные ресурсы существуют |
| HTTP static `/loft-booking/api/health` | **404**, серверный endpoint не экспортирован |
| `npm run db:up` / `db:test:up` | Реальные контейнеры healthy; authenticated healthcheck от имени приложения |
| `npm run db:check` / `db:test:check` | Настоящий `pg` + `SELECT 1`, соединение ready |
| Миграции dev до/после остановки/запуска | Первая версия применена один раз; повтор после перезапуска — **0**, volume/история сохранены |
| `npm run test:server:http` | Реальный собранный Next.js: **200 → остановка тестовой БД → 503 → перезапуск → 200** |
| Compose / init script / workflows | YAML разобран, ссылки jobs проверены; `docker compose ... config --quiet`, `bash -n` и `git diff --check` успешны |
| Сохранение Pages / AGENTS / изображений / стилей | Байтовый diff с базовым main отсутствует для Pages workflow, AGENTS.md, `public/` и `src/app/globals.css` |

SHA-256 проверенного локального статического артефакта: `92da6daa1a14a238aad44e550bf6d68c4b120c58073156b22350edefbb0517fc`. Это fingerprint локального `out/`, а не коммит и не доказательство публикации этой ветки.

## Что проверяет реальная БД

1. Приложение подключается ограниченной ролью без superuser/DDL/доступа к миграционному журналу; миграционная роль также не superuser.
2. Первая миграция применяется, повтор не дублирует историю.
3. Изменение checksum применённого SQL и исчезновение применённого файла приводят к `HISTORY_MISMATCH` без изменения истории; CLI возвращает ненулевой exit code.
4. Два **отдельных процесса CLI** конкурируют за настоящий PostgreSQL advisory lock: один применяет pending-версию, другой получает `MIGRATION_LOCKED`; дублирования нет.
5. SQL-ошибка даёт `MIGRATION_FAILED`/exit 1, новая запись истории не фиксируется. Таблицы бронирований/событий не создаются.
6. Health возвращает только минимальные `{"status":"ok"}` / `{"status":"unavailable"}` и `Cache-Control: no-store`; ни URL, ни пароль, ни SQL, ни пути в ответ не включены.
7. Ограничение времени запроса проверено реальным `pg_sleep`.

Тестовые временные SQL-файлы находятся в OS temp и удаляются. Очистка служебной истории ограничена локальной изолированной `_test` базой; рабочая БД не используется. Тест HTTP останавливает исключительно тестовый Compose project и восстанавливает его даже при ошибке проверки.

## GitHub Pages и CI

Существующий `.github/workflows/demo-pages.yml` **не изменён**, не имеет сервиса PostgreSQL и по-прежнему публикует только DEMO из `main` по https://jurist77.github.io/loft-booking/. Static export подтверждён без работающей БД, серверные зависимости в публичный bundle не попали. Новый отдельный `backend-checks.yml` запускается для PR/main и использует только собственную временную тестовую БД; production/VPS не требуется.

Результаты GitHub CI отражаются непосредственно в Checks PR. Локальный успех не называется успешным GitHub deployment. Ветка 2.1 до согласованного merge не публикуется; публичный сайт этой работой не обновлялся. После merge существующий Pages workflow должен пройти build → deploy → verify-published; фактический будущий запуск нужно проверить отдельно.

## Основные изменения

- `compose.yaml`, `docker/postgres/init-roles.sh`, `.env.example`, `.gitignore`: локальная БД, роли, healthcheck, сохранность и исключение секретов.
- `src/server/{config,database,health,migrations}.ts`: приватная конфигурация, пул, ограниченные тайм-ауты, безопасный health и SQL-миграции.
- `src/app/api/health/route.server.ts`, `next.config.ts`, `src/lib/app-mode.ts`: явные режимы и исключение API из DEMO.
- `migrations/0001_foundation.sql`, `migrations/README.md`, `.gitattributes`: первая служебная версия и правила истории/LF.
- `scripts/{local-env,database-compose,database-check,migrate,next-mode,verify-server,verify-demo-isolation}.mjs`: воспроизводимые команды и реальные проверки.
- `scripts/{build-demo,audit-demo}.mjs`: принудительный DEMO и расширенный аудит экспорта.
- `package.json`, `package-lock.json`, TypeScript/ESLint/Vitest configs: `pg`, `server-only`, типы, scripts и тестовая граница.
- `tests/integration/postgres.test.ts`, серверные модульные тесты, `.github/workflows/backend-checks.yml`: автоматизация проверок.
- Минимальные изменения `page.tsx`, `booking-client.tsx`, deployment-конфигурации: SERVER не запускает демонстрационную запись; DEMO сохраняет прежнее поведение.
- README и документация архитектуры/локального запуска/DEMO обновлены.

## Ограничения и приёмка

Все обязательные локальные категории проверок выполнены; невыполненных из-за отсутствия Docker/БД нет. GitHub Checks и будущую публикацию следует отличать от локальных результатов.

Это инфраструктурный этап: нет `bookings`, `booking_events`, операций бронирования, реальной занятости, авторизации, административных аккаунтов приложения, уведомлений, платежей и обработки настоящих контактов. SERVER показывает Welcome с отключённой записью. DEMO остаётся вымышленным пятиэкранным прототипом. Следующий этап 2.2 не начат.

Локальные пароли — только development/test, не production. Compose init выполняется один раз на пустом volume. Нельзя считать изменение env автоматической ротацией уже созданных паролей. Не удалять volume для штатной остановки. Миграции — доверенный reviewed SQL, не sandbox; применённые версии неизменяемы. Production HTTPS, секреты, бэкапы/восстановление, мониторинг и юридический режим реальных контактов ещё предстоит согласовать и реализовать.

[Архитектура](backend-architecture.md) · [Пошаговый локальный запуск](backend-local-setup.md) · [Обновление DEMO](demo-deployment.md).
