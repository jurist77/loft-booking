# Приёмка 2.5.2 — аудит установщика и единая SSH-политика

Дата: 05.11.2026. Ветка `feat/universal-github-installer-v2.5.2`, существующий [draft PR №12](https://github.com/jurist77/loft-booking/pull/12). Основа main неизменна: `c7a8a453c3aab3914eee8296e4cdd46ff2a81e33`. Новый PR, merge, реальные SSH/VPS и рабочий backup-репозиторий не используются.

## Изменения этого аудита

1. Все операции Studio используют общий SSH helper с `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, `GlobalKnownHostsFile=/dev/null`, `UpdateHostKeys=no`, `-F /dev/null`. Удалены требование Secret ключей хоста, временный known_hosts и инструкции его настройки. Root-пароль остаётся только в Actions Secret, передаётся sshpass через отдельное окружение, не argv/файлы/артефакты/логи. Глобальный SSH runner/VPS не меняется.
2. Подтверждён и исправлен дефект cleanup: при прежнем порядке Release→tag отказ удаления тега оставлял невидимый для следующей ротации orphan tag. Новый порядок tag→Release сохраняет архив доступным до завершения удаления тега; повтор безопасно завершает частичное удаление. Только настоящий HTTP 404 допускается как «уже отсутствует»; 403/500/transport errors завершают операцию с ошибкой.
3. Расширены fault tests: разрыв до/во время/после снимка, разрыв передачи пакета после verified backup, потеря ответа после COMMIT, изменение схемы перед потерей связи и недоступность abort. Добавлены API upload/readback/checksum/delete faults, повтор частичной очистки и независимый host restore.
4. Native harness дополнительно проверяет неизменность PID/релиза при no-op и восстановление в чистую установку с новым instance и TEST-NET Origin. Это модель другого совместимого VPS на disposable CI; TEST-NET адрес не используется для сетевого подключения.

**Риск согласованной SSH-политики:** MITM/ошибочный IP могут перехватить root-пароль, подменить сервер и данные до шифрования. SHA256 и зашифрованные Releases этого риска не устраняют. Политика действует для install, daily, pre-update и restore; обычный SSH владельца не меняется.

## Матрица сценариев

| Сценарий | Проверка и ожидаемый результат |
| --- | --- |
| Первая установка | Native x64/ARM64: реальный systemd RootDirectory, SQLite init/migrate/check, API/health, изолированный booking/conflict/restart acceptance |
| Тот же исправный SHA | Native: already-current, неизменные release и MainPID; существующая бронь сохраняется |
| Update с подтверждённой копией | Real SQLite snapshot + GPG + mocked Releases upload/download SHA; nonce/bundle/schema receipt до миграций; порт/данные сохраняются |
| Потеря связи до/во время снимка | Update не вызывается; при доступном управлении исходный сайт возобновлён, state ready |
| Потеря ответа после снимка | Coordinator узнаёт nonce через info и пытается безопасный abort; без связи остаётся неизвестный итог, без ложного SUCCESS |
| Потеря связи при передаче пакета | Старый сайт возобновляется только при прежней схеме; verified pre-update copy остаётся закреплённой |
| Потеря ответа после сохранения | Сохранённая ready-версия не откатывается; следующий запуск подтверждает health, снимает pin и выполняет no-op |
| Несовместимая миграция / потеря связи | Старый код не запускается автоматически; DB и защищённая копия сохраняются, manual-required/hold |
| Отказ upload/readback/checksum/cleanup до update | Нет разрешающего receipt: update не начинается, старый сайт возобновляется при безопасной схеме |
| Ошибка retention после COMMIT | FAILED без ложного отката: новая ready-версия/DB сохраняются, очистка повторяется позднее; временно возможно превышение лимита копий |
| Отказ удаления tag/Release, потеря ответа DELETE | Release остаётся доступным до завершения удаления тега; повтор завершает cleanup, чужой namespace не затрагивается |
| Retention | 7 успешных Moscow daily days, 3 completed pre-update + protected pending; failure не удаляет последнюю успешную копию |
| Restore на том же host | Настоящие SQLite/GPG/filesystem и native systemd: фото/settings/брони восстановлены; исходный DATA/WAL сохранён рядом |
| Restore на другом host | Independent local filesystem fixture + чистая native CI установка: новый instance/Origin, сохранённые records/photos/settings, исходные данные не меняются |
| Ошибка restore/start | Возвращается исходный DATA и совместимый старый код; при несовместимости остановка, без удаления записей |
| Сторонние службы/VPN/сеть | Native canary PID/config, fingerprints других unit/firewall/routes/DNS неизменны; jail не читает host canary/shadow |
| Секреты / SSH | Один helper для всех операций; password не argv/payload/output; нет глобального SSH config, env dumps и рабочего backup repo |
| DEMO/SERVER | Клиентский код, UI, SQL, Pages и Backend workflow в этом аудите не меняются; существующие проверки сохраняются |

Тесты потери связи **моделируют транспортные разрывы**, не подключаются по SSH. Native harness реально запускает systemd/Next/SQLite только на одноразовых Ubuntu runners. Fake VPN canary не доказывает поведение настоящего VPN при нагрузке.

## Проверки

- Installer/security/recovery: **51 tests**, реальные локальные SQLite/GPG/файлы; внешние GitHub/SSH операции mocked.
- Существующие прикладные suites: 152 unit, 57 real SQLite integration, 18 групп API HTTP, health recovery и negative control, 20 SERVER + 26 DEMO E2E, typecheck/lint, SERVER/Node DEMO/static DEMO/audit — входят в обязательный повтор Backend CI.
- Installer CI заново собирает пакеты Node 24.12.0/ABI137 + native better-sqlite3 на **Ubuntu 24.04 x64 и ARM64** и выполняет весь реальный systemd harness. Старые успешные runs не заменяют проверку итогового SHA.
- [Текущие Checks PR №12](https://github.com/jurist77/loft-booking/pull/12/checks) содержат окончательные результаты и ссылки для SHA последнего коммита. Точный SHA и подтверждённые ссылки приводятся в итоговом сообщении; никаких дополнительных документирующих коммитов после финального CI не требуется.
- Проверяются YAML/acyclic needs, Python syntax, diff, отсутствие credential patterns/DB/build outputs в коммите и неизменность main.

Предыдущая редакция кода `5a214cb` прошла [Installer](https://github.com/jurist77/loft-booking/actions/runs/41908397863), [Backend](https://github.com/jurist77/loft-booking/actions/runs/41908397881) и [audit](https://github.com/jurist77/loft-booking/actions/runs/41908397935); эти ссылки — история, не результат нового аудита.

## Изменённые файлы этого аудита

- `scripts/installer/deploy.py`, `manage.py`: общая command-scoped SSH-политика без host-key Secret.
- `scripts/installer/backup.py`: retry-safe cleanup tag/Release и ограниченное распознавание 404.
- `.github/workflows/backup-studio.yml`, `restore-studio.yml`: удалена передача ключей хоста; общий helper уже используется также install/pre-update.
- `tests/installer/test_backups.py`, `test_recovery_audit.py`, `real_systemd.py`: policy, API/fault/recovery/cross-host/no-op tests.
- `README.md`, `docs/universal-installer.md`, этот отчёт и `PR.md`: актуальные правила/инструкции.

## Ограничения и действия владельца

- Реальные VPS, VPN, SSH, reboot, публичный маршрут, фактические backup repo/token/quota и удалённое восстановление не проверялись и не запускались.
- Непрерывная потеря связи или SIGKILL/отключение питания могут оставить hold/manual-required. Не обещается автоматический rollback при несовместимой схеме или неизвестном результате; не удалять state, WAL и защищённую копию для обхода защиты.
- HTTPS отсутствует: временный HTTP только для вымышленных контактов. Нельзя вводить реальные клиентские телефоны.
- Daily schedule/email GitHub не дают SLA; key loss означает потерю возможности расшифровки. Локальные release/recovery/checkpoint каталоги требуют отдельной политики очистки.
- В cloud остаётся заблокирован api.github.com: Git fetch/push работают, результаты CI доступны на публичных страницах, но title/body PR нельзя изменить через API. Актуальное описание сохранено в [PR.md](PR.md). Подготовленный network draft нужно Review/Save→Publish для API и штатного browser download. Локальный Chromium154 отличается от штатного Playwright156; прошлые локальные E2E были нестабильны, таймауты не ослабляются; финальный Backend CI использует штатный браузер.

Secrets: `STUDIO_SSH_PASSWORD`, `STUDIO_BACKUP_TOKEN`, `STUDIO_BACKUP_PASSPHRASE`; Variables: `STUDIO_BACKUP_REPOSITORY`, `STUDIO_BACKUP_SERVER_IP`. Дополнительный Secret ключей хоста не нужен. Подробные шаги — [runbook](../../universal-installer.md). Остановиться для приёмки, без merge/deploy.
