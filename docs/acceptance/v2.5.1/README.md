# Приёмка 2.5.1 — подготовка инструмента аудита и проекта размещения

Дата: 20.10.2026. Основа — `main` `7d746f940b1e96f699a512e54e93438b85444c6f`, PR №10 подтверждён как MERGED. Рабочая ветка: `feat/vps-deployment-audit-v2.5.1`. Merge этой ветки не выполняется.

**Завершена подготовка инструментов. Сам аудит VPS, ресурсная рекомендация и развёртывание не выполнены.** В среде нет настроенного SSH/VPN-доступа к Швеции и Финляндии. Их показатели в [таблице](../../vps-comparison-v2.5.1.md) оставлены неизвестными. Ни cloud host, ни GitHub runner не выдаются за VPS.

## Изменённые файлы

| Файл | Назначение |
| --- | --- |
| `scripts/vps-audit.py` | Read-only snapshot, обезличенные JSON-данные, числовые показатели `/proc`, фиксированные безопасные команды |
| `tests/vps-audit/test_audit.py` | Парсинг, обезличивание, отсутствие write API/опасных команд, denied/missing/timeout/error cases |
| `.github/workflows/vps-audit-checks.yml` | Отдельная бесплатная Ubuntu 24.04 CI-проверка инструмента, без SSH/VPS secrets |
| `docs/vps-audit-runbook.md` | Точные команды для Mac/SSH, необязательный существующий sudo, приватная передача JSON |
| `docs/vps-comparison-v2.5.1.md` | Шаблон обоих серверов, метод бюджета ресурсов, условия выбора/отказа |
| `docs/vps-deployment-plan.md` | Изоляция, artifact build/delivery, HTTPS/tunnel, systemd, VPN safeguards, backup/restore/update/rollback и приёмка |
| `docs/acceptance/v2.5.1/README.md` | Этот отчёт |
| `README.md` | Ссылки на материалы этапа |

Функциональный код `src`, Next-конфигурация, lockfile, изображения, миграции, существующие тесты и GitHub Pages workflow **не изменены**. Скрипты установки/SSH-деплоя не добавлены. Systemd приведён как проект, который требует аудита путей/ресурсов и отдельного согласования; его нельзя считать уже установленным или готовым без проверки sandbox.

## Проверки в cloud, не на VPS

Среда: Node 24.19.0, Linux, существующий Chromium. Все проверки используют собственные временные тестовые SQLite, не рабочую БД и не VPS.

| Проверка | Результат |
| --- | --- |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/vps-audit -v` | 11 тестов; обезличивание/неизвестные сервисы, IPv4/IPv6/UDP, firewall summaries, CPU/PSI/RAM/OOM, degraded, отсутствие/отказ/timeout инструментов, safe errors, неизменность fixtures и отсутствие чтения argv/environ/configs/logs, запрет write API/команд |
| `python3 scripts/vps-audit.py --label local-validation` + JSON parse | Успешный настоящий запуск на cloud; systemd/firewall недоступности корректно отмечены; результат не включён в Git и не используется для оценки VPS |
| `npm test` | 151 passed |
| `npm run test:integration` | 57 passed, настоящая SQLite |
| `npm run typecheck`, `npm run lint` | Успешно |
| `npm run build:server` | Успешно, health/availability/bookings остаются SERVER routes |
| `npm run test:server:http` | 3 цикла 200 → 503 → 200, readonly/write-restored; один живой Next.js процесс |
| `npm run test:api:http` | 18 групп успешно, настоящие HTTP/SQLite, включая конкурентность/идемпотентность/отказы |
| `npm run test:server:http:failure` | Успешный negative control: постоянный 503 даёт exit 1 внутреннего теста, корректный cleanup |
| `npm run test:demo:isolation` | Node DEMO build/runtime, static DEMO build и аудит 29 файлов успешны; API 404 в Node DEMO, canary/server values отсутствуют |
| `npm run test:server:ui` | 20 SERVER + 26 DEMO E2E passed, desktop/mobile, пять экранов и ширины 320–1440 |
| YAML нового workflow, triggers/permissions/jobs, ссылки документации | Успешно проверены Python/PyYAML; actionlint в cloud отсутствует, не запускался |
| `git diff --check`, проверка состава файлов | Успешно; приложение/миграции/Pages workflow неизменны, реальные отчёты VPS и секреты не включены |

Команда воспроизведения проверки скрипта не требует npm install или доступа к VPS. Новый workflow автоматически проверяет её и JSON только на CI runner. Полный существующий Backend CI продолжает работать отдельно; ссылка на результат указывается в PR/итоговом сообщении после реального прогона.

## Что осталось

1. Владелец получает обычные/загруженные снимки **обоих** VPS по [инструкции](../../vps-audit-runbook.md) и передаёт их приватно после проверки обезличивания.
2. Уточняет VPN peaks/443/TLS/нестандартные службы/внешний firewall, существующий backup-носитель и канал alerts.
3. На фактах заполняется сравнение, измеряется профиль готового SERVER-артефакта и принимается решение Швеция/Финляндия с бюджетом/stop thresholds. Пока нет измерений приложения, MemoryMax/точные MB не придуманы.
4. Отдельное согласование сервера, сети и будущих изменений. Нет публичного SERVER URL; HTTPS на Mac/телефоне ещё не организован. SSH loopback-туннель — предусмотренная альтернатива защищённого теста, не объявленная публичным HTTPS.
5. Отдельный этап сборки готового артефакта, разрешённой установки и 12 приёмочных сценариев, включая разрешённый reboot и offsite restore rehearsal. Эти проверки **не выполнены** на VPS.

Никаких действий на VPS, изменений VPN, публикации сайта или merge не выполнялось. Реальные персональные данные/секреты/отчёты серверов не добавлены. Backend/admin/уведомления и другие этапы не начаты.
