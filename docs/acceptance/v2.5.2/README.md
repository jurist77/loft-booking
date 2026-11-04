# Приёмка 2.5.2 — установщик, резервирование и восстановление

Дата: 04.11.2026. Основа `main`: `c7a8a453c3aab3914eee8296e4cdd46ff2a81e33` (PR №11). Ветка: `feat/universal-github-installer-v2.5.2`. [PR №12](https://github.com/jurist77/loft-booking/pull/12). **Merge, реальные SSH-подключения, VPS и рабочий backup repo не использовались.**

Последнее ТЗ разрешает временный публичный HTTP с вымышленными контактами и добавляет encrypted Releases/restore. Оно заменяет первоначальное loopback-only ограничение 2.5.2. HTTPS и сеть VPS не настраиваются. Старые успешные CI предыдущей редакции не считаются проверкой новой функциональности.

## Матрица требований

| Требование | Реализация / проверка | Граница подтверждения |
| --- | --- | --- |
| Только IP при Install | workflow_dispatch/server_ip, IPv4/IPv6; root:22/password Secret; gate exact main SHA | Contract tests; реальные SSH запрещены |
| Universal native package | Ubuntu 24.04 x64/ARM64, Node 24.12.0/ABI137, manifest/SHA/ldd/native sandbox | Две реальные архитектуры предусмотрены CI; текущий новый run ещё не подтверждён |
| Нет сборки на VPS | Allowlisted self-contained rootfs; Node/shared libs включены; runtime host не заменяется | Package parser/audit unit; полная native сборка требует Ubuntu CI |
| Не переносить секреты/данные | Source ignore + аудит финального rootfs: обязательные файлы, отсутствие .env/key/SQLite по имени и magic; builder не получает Secrets | Synthetic fixtures; смысловое распознавание всех возможных секретов не обещается |
| Первая установка / no-op / update | Managed user/пути, atomic state, systemd, отсутствие перезапуска исправного same SHA; update через offsite barrier | Unit + код настоящего systemd harness для CI |
| SQLite/photos/settings постоянные | DATA вне кода; новые релизы не заменяют файлы; photos initial seed, settings storage foundation | Real filesystem/SQLite unit; full systemd update/restore harness |
| Public HTTP, порт сохраняется | Свободный 3000 или 3100–3199, wildcard listener; exact IP Origin, явный тестовый флаг | Порт/Origin unit; CI local HTTP; реальный внешний маршрут не проверялся |
| Внутренний / внешний статус отдельно | Health/API/acceptance обязательны, отдельный external probe reachable/unreachable | Mock HTTP boundary + реальные локальные HTTP app tests |
| Encrypted offsite backup | Реальный SQLite Backup API, tar/checksums, GPG AES256, private Releases + download/readback | Реальные SQLite/GPG; GitHub операции **только FakeStore** |
| Daily / failure / retention | 03:15 Москва, максимум 2 попытки, FAILED + GitHub notifications; 7 успешных Moscow days / 3 completed preupdate / pending pin | Rotation/failure tests, включая переезд между instance и release+tag API contract |
| Update без backup запрещён | Nonce/schema/bundle-SHA receipt barrier, pre-migration hold; failure abort только при прежней схеме | Unit: install не вызван при backup failure; local state/service tests |
| Restore только по подтверждению | list → tag → typed confirmation, trusted SSH; decrypt/hash/точная migration map/schema check | Real archive/FS/SQLite tests; внешние операции mock |
| Preserve current / rollback | Original whole DATA/WAL/photos/settings сохраняется рядом; rollback code только совместим со схемой | Restore swap/undo unit + systemd harness success/failure; native CI pending |
| Изолированная техприёмка | Separate temp SQLite и Next child: health, availability, booking201/conflict409, restart→busy preserved | Настоящие local HTTP/SQLite; production клиентские записи не меняются |
| VPN/сеть не затронуты | RootDirectory/minimal permissions; только свой unit/user/files; никаких firewall/proxy/DNS/VPN commands | Unit + CI canary/fingerprints; реальные VPN не запускались |
| Нет реального deploy в PR | Install/backup/restore только main/manual или main schedule после merge; no push deploy | Статическая проверка workflows; старый real_ssh.py сохранён, но больше не вызывается CI |
| DEMO/SERVER сохранены | Не менялись UI/изображения/SQL/Pages/Backend CI; единственное API-изменение — opt-in HTTP literal IP | Existing unit/integration/HTTP/E2E/builds |

## Файлы

- `.github/workflows/install-studio.yml`: manual install + backup configuration gate + отчёт/cleanup.
- `.github/workflows/installer-package.yml`, `installer-checks.yml`: native package, unit/security, real systemd harness на disposable CI; без реальных SSH и backup repo.
- `.github/workflows/backup-studio.yml`: daily/manual encrypted backup; `.github/workflows/restore-studio.yml`: list/confirmed restore.
- `scripts/installer/package.py`: allowlist, native runtime/libs, final package audit и manifest; `deploy.py`: SSH/framing и безопасная передача snapshot/receipt.
- `scripts/installer/remote.py`, `maintenance.py`: host compatibility, managed filesystem/systemd, consistency barriers, photos/settings, whole-directory restore/rollback.
- `scripts/installer/backup.py`, `manage.py`: GPG, dedicated-token Releases, bounded retries/rotation, runner coordination.
- `scripts/installer/schema.mjs`, `acceptance.mjs`, `verify-main.py`, `verify-version.py`: fingerprint, isolated technical acceptance, exact-SHA CI gates.
- `tests/installer/`: unit/mock external tests и настоящий CI-only systemd harness. Исторический real_ssh.py сохранён, не вызывается.
- `src/server/api-security.ts`, `api.test.ts`: opt-in non-loopback HTTP только server + literal IP. HTTPS default/CORS/rate limits/booking rules сохранены.
- `README.md`, [полная инструкция](../../universal-installer.md), этот отчёт.

## Выполненные локальные проверки

Cloud: Node 24.19.0, SQLite 3.53.4, Python 3.12.14, GPG, Chromium; среда не Ubuntu 24.04 с полноценным root/systemd. Нельзя подменять эту среду настоящим VPS.

| Проверка | Результат |
| --- | --- |
| Installer unit/security/backup/restore | 40 passed; реальная криптография и SQLite, внешние действия mock |
| `npm test` | 152 passed |
| `npm run test:integration` | 57 passed, настоящая SQLite |
| `npm run typecheck`, `npm run lint` | Passed |
| `npm run build:server` | Passed |
| `npm run test:server:http` | 3 цикла 200→503→200, тот же Next process; readonly503→recovery200 |
| `npm run test:api:http` | 18 групп passed, real HTTP/SQLite |
| `npm run test:server:http:failure` | Passed: постоянный503 завершил настоящий CLI кодом1, cleanup восстановил тестовую DB |
| Node DEMO / static DEMO / audit | Passed при повторном полном `test:demo:isolation`: серверные API404, invalid SQLite config ignored, 29 файлов, canary/credentials отсутствуют |
| SERVER/DEMO E2E (`npm run test:server:ui`) | 20 SERVER + 26 DEMO passed, mobile/desktop, настоящая SQLite и static DEMO |
| Isolated installer acceptance CLI | Passed: real SQLite/HTTP, booking201/conflict409/restart→persistence; временная БД очищена |
| YAML / needs / Python syntax / diff | 8 workflows распарсены PyYAML; зависимости jobs валидны, Python compile, diff --check passed. Actionlint отсутствует |
| Новый GitHub CI | Запуски видны на публичной Checks-странице PR; окончательные native результаты текущей редакции ещё не подтверждены при фиксации отчёта. api.github.com возвращает Forbidden, draft domain ещё не опубликован |
| Реальные SSH/VPS/backup Releases | **Не выполнялись**, запрещены ТЗ |

Один первый локальный `test:demo:isolation` завершился `INVALID_NODE_DEMO` при startup probe; повторный полный запуск прошёл без изменения или ослабления теста. Точная причина первого transient response не установлена, поэтому это не скрывается за заявлением «всё стабильно». Требуется новый CI и последующая отдельная эксплуатационная приёмка.

Native CI run `41905497186` выявил `TypeError` в новом тестовом receiver adapter: keyword `bundle` вместо `restore_bundle` при framing. Исправлено; локальный regression вызывает тот же adapter с настоящим framed stream и mock внешнего запуска, проверяет архив/code/snapshot/hash/confirmation. Это ошибка тестового вызова, не основание отключать реальные systemd сценарии. Добавлена безопасная location-диагностика исключений CI; требуется успешный повтор текущего SHA.

При подготовке исправлены: chronological rotation после смены instance; cleanup собственного неподтверждённого draft; nonce/schema-safe release snapshot hold при transfer failure; завершение ephemeral GPG agent без наследования Secrets; проверка полноты и SQLite magic в пакете; fsync staged restore до rename; IPv4-only kernel; проверка ключа до SSH. Старый deploy CLI переведён на общий backup barrier/валидатор результата, чтобы не оставлять обход обязательной копии или устаревший loopback-контракт. Все исходные прикладные тесты сохранены.

## Что остаётся проверить

1. Новый полный native CI x64/ARM64 с **текущим SHA**: package/RootDirectory/systemd/restore/faults. Старые зелёные runs другой редакции не заменяют это подтверждение.
2. Только после отдельного разрешения: audit фактического VPS, реальные root:22 и known_hosts, память/диск/namespace, public route/IPv6, boot/reboot, VPN peaks и отсутствие влияния на VPN.
3. Только после отдельного разрешения: реально private repo/token с ContentsRW, upload/download/delete Releases+tags, quota/error handling и end-to-end restore на другой VPS. Токен/парольная фраза не запрашиваются в чате.
4. Для реальных контактов нужны HTTPS и согласованное правовое основание. До этого исключительно вымышленные данные.
5. Schedule GitHub может задерживаться/отключаться, email зависит от настроек владельца. Локальные releases/recovery/checkpoints требуют будущей политики очистки; они не удаляются автоматически ради места. Rollback после несовместимой committed migration не обещается.

## Действия владельца и root-операции

[Runbook](../../universal-installer.md) содержит точные шаги private repo, Secrets, Variables, Run workflow, restore и коды отказов. Необходимы Secrets `STUDIO_SSH_PASSWORD`, `STUDIO_BACKUP_TOKEN`, `STUDIO_BACKUP_PASSPHRASE`, `STUDIO_SSH_KNOWN_HOSTS`; Variables `STUDIO_BACKUP_REPOSITORY`, `STUDIO_BACKUP_SERVER_IP`. Install ввод — только IP; restore требует tag/confirmation.

Root создаёт только managed user/dirs/unit, извлекает проверенный код, запускает собственные sandbox DB/acceptance CLI, останавливает/запускает только Studio и переключает её DATA при подтверждённом restore. Он не редактирует VPN/sshd/firewall/proxy/DNS, не ставит пакеты на VPS. Next работает непривилегированно. Host-key exception Install несёт MITM/root-password риск; backup/restore — strict pinning.

Остановиться для приёмки PR; merge и запуск реальных workflows не выполнять автоматически.
