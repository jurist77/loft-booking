# Приёмка 2.5.2 — установщик, резервирование и восстановление

Дата: 04.11.2026. Основа `main`: `c7a8a453c3aab3914eee8296e4cdd46ff2a81e33` (PR №11). Ветка: `feat/universal-github-installer-v2.5.2`. [PR №12](https://github.com/jurist77/loft-booking/pull/12). **Merge, реальные SSH-подключения, VPS и рабочий backup repo не использовались.**

Последнее ТЗ разрешает временный публичный HTTP с вымышленными контактами и добавляет encrypted Releases/restore. Оно заменяет первоначальное loopback-only ограничение 2.5.2. HTTPS и сеть VPS не настраиваются. Старые успешные CI предыдущей редакции не считаются проверкой новой функциональности.

## Итог CI

Проверен код `5a214cbcf73cd6de74119763da69a7053e7a39e5`:

- [Installer CI — SUCCESS, x64 и ARM64](https://github.com/jurist77/loft-booking/actions/runs/41908397863): настоящие RootDirectory/systemd/HTTP/SQLite, install/no-op/update/restore/failures/rollback, внешнее backup storage mock. Jobs: x64 9m29s, ARM64 9m24s.
- [Backend CI — SUCCESS](https://github.com/jurist77/loft-booking/actions/runs/41908397881): существующие тесты, SERVER/DEMO, 20 SERVER + 26 DEMO E2E с штатным Chromium Playwright.
- [Read-only VPS audit CI — SUCCESS](https://github.com/jurist77/loft-booking/actions/runs/41908397935).

Последующий итоговый коммит меняет **только документацию**, код и тесты совпадают с проверенным SHA выше. Автоматические повторные checks этого документационного коммита могут ещё выполняться; ссылки выше относятся именно к проверенному коду. Ветка отправлена, main остаётся `c7a8a453c3aab3914eee8296e4cdd46ff2a81e33`, merge не выполнялся.

## Матрица требований

| Требование | Реализация / проверка | Граница подтверждения |
| --- | --- | --- |
| Только IP при Install | workflow_dispatch/server_ip, IPv4/IPv6; root:22/password Secret; gate exact main SHA | Contract tests; реальные SSH запрещены |
| Universal native package | Ubuntu 24.04 x64/ARM64, Node 24.12.0/ABI137, manifest/SHA/ldd/native sandbox | Обе архитектуры прошли финальный CI проверенного кода |
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
| Preserve current / rollback | Original whole DATA/WAL/photos/settings сохраняется рядом; rollback code только совместим со схемой | Restore swap/undo unit + настоящий systemd success/failure на двух архитектурах CI |
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
- `src/server/backup.ts`, `tests/integration/sqlite.test.ts`: проверка собственного временного SQLite output закрывается без orphan WAL/SHM; интеграционный regression сохраняет WAL/FULL исходной DB.
- `README.md`, [полная инструкция](../../universal-installer.md), этот отчёт.

## Выполненные локальные проверки

Cloud: Node 24.19.0, SQLite 3.53.4, Python 3.12.14, GPG, Chromium; среда не Ubuntu 24.04 с полноценным root/systemd. Нельзя подменять эту среду настоящим VPS.

| Проверка | Результат |
| --- | --- |
| Installer unit/security/backup/restore | 41 passed; реальная криптография и SQLite, внешние действия mock |
| `npm test` | 152 passed |
| `npm run test:integration` | 57 passed, настоящая SQLite |
| `npm run typecheck`, `npm run lint` | Passed |
| `npm run build:server` | Passed |
| `npm run test:server:http` | 3 цикла 200→503→200, тот же Next process; readonly503→recovery200 |
| `npm run test:api:http` | 18 групп passed, real HTTP/SQLite |
| `npm run test:server:http:failure` | Passed: постоянный503 завершил настоящий CLI кодом1, cleanup восстановил тестовую DB |
| Node DEMO / static DEMO / audit | Passed при повторном полном `test:demo:isolation`: серверные API404, invalid SQLite config ignored, 29 файлов, canary/credentials отсутствуют |
| SERVER/DEMO E2E (`npm run test:server:ui`) | 20 SERVER + 26 DEMO passed в раннем локальном прогоне и финальном Backend CI; повторные локальные ограничения описаны ниже |
| Isolated installer acceptance CLI | Passed: real SQLite/HTTP, booking201/conflict409/restart→persistence; временная БД очищена |
| YAML / needs / Python syntax / diff | 8 workflows распарсены PyYAML; зависимости jobs валидны, Python compile, diff --check passed. Actionlint отсутствует |
| Новый GitHub CI | SUCCESS для проверенного кода: Installer x64/ARM64, Backend, VPS audit; ссылки выше. Результаты прочитаны на публичных страницах; api.github.com остаётся Forbidden |
| Реальные SSH/VPS/backup Releases | **Не выполнялись**, запрещены ТЗ |

Один первый локальный `test:demo:isolation` завершился `INVALID_NODE_DEMO` при startup probe; повторный полный запуск прошёл без изменения или ослабления теста. Точная причина первого transient response не установлена. Два поздних локальных SERVER E2E-прогона дали по одному мобильному сбою: timeout 40s в `Intl.DateTimeFormat` и ожидание возврата кнопки после 429. Пройдено 19/20 в каждом, проблемные сценарии прошли в другом прогоне. Тесты/таймауты не ослаблялись. Здесь системный Chromium 154; штатный для установленного Playwright — 156. Загрузка 156 из cdn.playwright.dev заблокирована `403 Domain forbidden`. Версию браузера нельзя считать доказанной причиной сбоев без сравнения; в финальном Backend CI с штатным браузером прошли все 20+26. Для воспроизводимого локального повторения нужен Publish подготовленных настроек сети, затем установка штатного браузера.

Native CI run `41905497186` выявил `TypeError` в новом тестовом receiver adapter: keyword `bundle` вместо `restore_bundle` при framing. Исправлено; локальный regression вызывает тот же adapter с настоящим framed stream и mock внешнего запуска, проверяет архив/code/snapshot/hash/confirmation. Это ошибка тестового вызова, не основание отключать реальные systemd сценарии. Добавлена безопасная location-диагностика исключений CI; итоговый повтор успешен.

Следующий run `41906850646` успешно выполнил первую установку/no-op и отклонил consistent snapshot перед update. Причина воспроизведена локально на настоящем better-sqlite3: readonly verifier собственного временного backup output оставлял `.partial.sqlite-wal/-shm`, попадавшие в manifest и нарушавшие точный file set архива. Verifier теперь открывает только свой private temporary output read/write, чтобы SQLite сама убирала свои journals при закрытии. Живая база не копируется вручную, WAL/FULL источника не меняются. Усилен существующий integration test на отсутствие orphan partial files и сохранение PRAGMA WAL/FULL; все 57 проходят. Прежние зелёные CI не считаются доказательством этой последней правки.

Для обновления с прежнего CLI manifest строится ровно по содержимому архива: завершённый Backup-API output + photos/settings. Оставленные старым verifier временные файлы не становятся частью снимка и удаляются вместе с его private temp directory; source DB/WAL не затрагиваются. Отдельный regression проверяет эту совместимость.

При подготовке исправлены: chronological rotation после смены instance; cleanup собственного неподтверждённого draft; nonce/schema-safe release snapshot hold при transfer failure; завершение ephemeral GPG agent без наследования Secrets; проверка полноты и SQLite magic в пакете; fsync staged restore до rename; IPv4-only kernel; проверка ключа до SSH. Старый deploy CLI переведён на общий backup barrier/валидатор результата, чтобы не оставлять обход обязательной копии или устаревший loopback-контракт. Все исходные прикладные тесты сохранены.

## Что остаётся проверить

1. Native CI x64/ARM64 проверенного кода завершён успешно; последующее изменение отчёта не меняет код. Перед будущим Run Install всё равно требуется успешный exact-SHA push CI main после согласованного merge.
2. Только после отдельного разрешения: audit фактического VPS, реальные root:22 и known_hosts, память/диск/namespace, public route/IPv6, boot/reboot, VPN peaks и отсутствие влияния на VPN.
3. Только после отдельного разрешения: реально private repo/token с ContentsRW, upload/download/delete Releases+tags, quota/error handling и end-to-end restore на другой VPS. Токен/парольная фраза не запрашиваются в чате.
4. Для реальных контактов нужны HTTPS и согласованное правовое основание. До этого исключительно вымышленные данные.
5. Schedule GitHub может задерживаться/отключаться, email зависит от настроек владельца. Локальные releases/recovery/checkpoints требуют будущей политики очистки; они не удаляются автоматически ради места. Rollback после несовместимой committed migration не обещается.

## Действия владельца и root-операции

[Runbook](../../universal-installer.md) содержит точные шаги private repo, Secrets, Variables, Run workflow, restore и коды отказов. Необходимы Secrets `STUDIO_SSH_PASSWORD`, `STUDIO_BACKUP_TOKEN`, `STUDIO_BACKUP_PASSPHRASE`, `STUDIO_SSH_KNOWN_HOSTS`; Variables `STUDIO_BACKUP_REPOSITORY`, `STUDIO_BACKUP_SERVER_IP`. Install ввод — только IP; restore требует tag/confirmation.

Root создаёт только managed user/dirs/unit, извлекает проверенный код, запускает собственные sandbox DB/acceptance CLI, останавливает/запускает только Studio и переключает её DATA при подтверждённом restore. Он не редактирует VPN/sshd/firewall/proxy/DNS, не ставит пакеты на VPS. Next работает непривилегированно. Host-key exception Install несёт MITM/root-password риск; backup/restore — strict pinning.

Остановиться для приёмки PR; merge и запуск реальных workflows не выполнять автоматически.
