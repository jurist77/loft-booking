# Приёмка перехода на SQLite

18 октября 2026. Основание — актуальный `main` **17851598865ec8f3aa4c835d5965a36a2d5c4349**, включая объединённые PR №5 и №6. Открытых PR при аудите не было. Рабочая ветка — `feat/sqlite-backend-simplification`; merge и VPS deployment не выполняются.

## Итоговая архитектура

Одно Next.js/TypeScript-приложение и одна локальная SQLite через **better-sqlite3 13.0.3**, SQLite **3.53.4**. WAL, synchronous=FULL, foreign keys, ограниченный busy timeout; отдельного DB-сервиса, сетевого порта, пула и паролей нет. Native-библиотека и SQLite бесплатны. UI, изображения и GitHub Pages по прежнему адресу сохранены.

Есть SQL-миграции с SHA-256 и BEGIN IMMEDIATE, минимальная SQL-таблица интервалов с CHECK и overlap INSERT/UPDATE triggers, безопасный health с реальной зафиксированной записью и онлайн-копирование/восстановление. Клиентских API бронирования, реальной занятости, контактов в БД, админ-панели и уведомлений нет.

## Подтверждённые проверки

| Проверка | Результат |
|---|---|
| Frozen install | `npm ci` успешно, native-модуль собран; в Codex SDK cache вынесен в `/tmp/studio-node-gyp` поддерживаемой переменной node-gyp |
| `npm test` | **115 passed**, 9 файлов, существующие клиентские тесты сохранены |
| `npm run test:integration` | **17 passed**, реальная SQLite на диске, настоящие независимые процессы, без mock БД |
| `npm run typecheck` / `lint` | Успех, без предупреждений lint |
| SERVER build | Успех, включая build с пустым SQLITE_PATH: подключение не требуется во время сборки |
| Node DEMO build | Успех |
| Static DEMO + audit | Успех с недоступным SQLite path и неверным timeout; режим принудительно DEMO, DB/API/серверный код/canary в out не попали |
| Playwright static DEMO | **26 passed**, desktop/mobile, пять экранов и приватность |
| HTTP health Node 24.19.0 / Undici 7.29.0 | **3 цикла 200→503→200**, один PID Next.js; затем readonly→503→200 |
| HTTP health Node 24.12.0 / Undici 7.16.0 | **3 цикла 200→503→200**, один PID Next.js; затем readonly→503→200 |
| Постоянный отказ, обе версии Node | Реальный дочерний CLI **exit 1** по 503/timeout; восстановление файла проверено HTTP 200, затем Next.js завершён |
| Команды с нуля | db:env → init → migrate (**1**) → migrate (**0**) → check — успешно |
| Backup/restore CLI | Онлайн-копия → другой новый файл → integrity + committed write → migrate (**0**) — успешно |
| Сохранение PR №6 | Общий fresh-socket health-probe, bounded wait, PID-контроль и отрицательный CLI сохранены; PostgreSQL stop/start заменён реальным отказом доступа к тестовому файлу |
| Отсутствие UI/Pages изменений | Diff с main пуст для src/components, src/lib, src/app, public, AGENTS.md, demo-pages.yml и общего health-probe |

После замены старые **локальные** PostgreSQL dev/test контейнеры этого проекта остановлены; volumes и старые игнорируемые env сохранены. Чужие проекты/VPN/VPS не затронуты. Финальные SQLite-проверки выполнялись при остановленном PostgreSQL. Backend CI больше не запускает Docker и сам создаёт временные SQLite-файлы.

Результат удалённого Backend CI следует проверять непосредственно в Checks нового PR. Локальная сборка не означает публикацию этой ветки на Pages; она произойдёт только после отдельно согласованного merge существующим workflow.

## Что проверено на реальной SQLite

1. WAL/FULL, timeout, private permissions, переоткрытие соединения и повторный init/migrate без потери записей.
2. Изменённый checksum, исчезнувший применённый SQL, SQL-ошибка с rollback DDL/истории и ненулевым CLI exit.
3. Настоящий writer lock и ограниченный MIGRATION_LOCKED; два параллельных мигратора без дублирования истории.
4. Два независимых SQL-процесса на один интервал: фиксируется только один. Смежные разрешены; overlap/конфликтующее изменение/возврат cancelled отклоняются. Cancellation сохраняет строку и освобождает время.
5. 09:00–23:00 по Москве, минимум час, получасовой шаг и последний час до 23:00.
6. Missing path, readonly/широкие права, readonly-каталог, symlink/hardlink, повреждённый файл: безопасный отказ, без создания пустой замены/утечки путей.
7. **SQLITE_FULL** вызван настоящим ограничением max_page_count, не mock и не заполнением диска общей среды. Ранее зафиксированные данные целы. Аппаратный EIO/реальное заполнение VPS не провоцировались.
8. Committed WAL входит в snapshot без остановки connection. Snapshot читается/восстанавливается; параллельный writer не повреждает копию. Источник/готовая копия не перезаписываются. Повреждение текущей базы обнаруживается; восстановление из реально созданной копии возвращает данные и health 200.

Все тестовые записи вымышлены и находятся в собственных temp-каталогах. Автотесты не используют/не удаляют локальную рабочую базу. Полные командные логи не публикуют контакты, SQL, private пути или сырые ошибки native-модуля.

## Основные изменения

- `src/server/{config,database,health,migrations,backup}.ts`: SQLite, приватный путь, file identity/permissions, integrity, write probe, SQL history, online snapshots.
- `migrations/sqlite/0001_foundation.sql`, README и LF rules: отдельная SQLite история, SQL-защита интервалов; исходный PG SQL сохранён без изменения в `docs/archive/postgresql/`.
- `scripts/database.mjs`, local-env, next-mode: init/migrate/check/backup/restore и отдельный локальный SQLite env.
- `scripts/verify-server.mjs`, negative control, demo isolation/audit, серверные unit/integration тесты: реальные файловые отказы, восстановление, конкурентные записи и сохранённые проверки UI/DEMO.
- `package.json`/lock: удалены pg/@types/pg и их зависимости, добавлены better-sqlite3/типы. Остальные версии lock не обновлены.
- Удалены compose.yaml, PG init-roles, database-compose/check/migrate PG scripts; исходные этапы остаются в Git и исторических отчётах.
- Backend CI адаптирован без ослабления health/negative tests; Pages workflow не менялся.
- README, архитектура, локальные инструкции и [эксплуатационный runbook](sqlite-operations.md).

## Ограничения и оставшиеся решения владельца

- Подготовка systemd/HTTPS/offsite/alert — **документация**, не установленная эксплуатационная инфраструктура. На VPS ничего не запускалось.
- Требуются домен/DNS, независимый доступный offsite-носитель, отдельное хранение recovery-пароля и согласованный канал уведомлений. До проверенного внешнего backup/restore rehearsal реальный запуск преждевременен.
- Пример RPO до суток/RTO не измерены; native-драйвер устанавливается под целевую ОС/Node. Проверки браузера — Chromium, не физический Safari/iPhone.
- SQLite рассчитан на один VPS, локальный диск и короткие записи. WAL не защищает от потери диска/всего VPS. Содержимое SQLite на диске не шифруется библиотекой; ОС-права защищают доступ, restic шифрует внешние копии. При необходимости дискового шифрования его отдельно настраивает владелец VPS.
- SQL CHECK использует текущий UTC+3 Москвы; динамические даты/окно проверит будущий API через существующие Europe/Moscow-правила. API, контакты, идемпотентность и юридические основания реального хранения не реализованы.
- PG→SQLite конвертация production-данных не выполнялась: в прежнем фундаменте реальных броней не было. Старые volumes/env сохранены до приёмки.

[Сравнение архитектур](backend-architecture.md) · [Локальный запуск](backend-local-setup.md) · [Восстановление/эксплуатация](sqlite-operations.md).
