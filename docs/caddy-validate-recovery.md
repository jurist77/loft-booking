# Caddy validate после VERIFIED_PORTS_PROBE

## Воспроизведение и причина

Run [42645562662](https://github.com/jurist77/loft-booking/actions/runs/42645562662) вернул `CADDY_CONFIG_INVALID` после успешного port proof. Неизменённый JSON из `configuration.caddy_config()` проходит стандартный `caddy validate --config ...` официального закреплённого Caddy **2.11.9**. Проверка выполнена локально и отдельно от TLS UID в CI; issuer Let's Encrypt, challenges, storage, admin socket, listeners и headers не подменялись.

Причина воспроизведена на **обеих архитектурах** в [run 42647756122](https://github.com/jurist77/loft-booking/actions/runs/42647756122):

- `PRODUCTION_JSON_VALIDATE_OK`: тот же production JSON корректен.
- Реальный `Operations.prepare()` под `umask 077` создаёт BASE, ETC и releases с `0700`, несмотря на аргументы mkdir 0755/0750.
- Реальный `runuser ... caddy validate ...` получает `Permission denied`: отдельный TLS-пользователь не может пройти к бинарнику. Caddy не начинает разбор JSON в этом вызове. Обёртка ошибочно называет любое ненулевое завершение runuser `CADDY_CONFIG_INVALID`.
- Воспроизводитель выводит только фиксированные маркеры/биты прав, без raw stderr, конфигурации, адресов и секретов. Это воспроизведение условий установщика на CI, не фактическая инспекция файлов VPS.

Ошибка файловой конфигурации исправлена точечно: **только после создания новых каталогов** явно выставляются BASE/releases/release-dir 0755 и ETC 0750 (root:TLS group). DATA остаётся 0700 TLS UID, JSON — 0640, owner/checkpoint — 0600 root. Уменьшать общий umask, делать chmod -R, менять существующие неизвестные каталоги, Caddy JSON, TLS/Origin, SQLite или чужие службы не требуется. Существующие неизвестные остатки не усыновляются.

## Обязательный CI

На x64/ARM64 используются официальный архив/закреплённый SHA-256 и настоящий бинарник Caddy:

1. Стандартный validate неизменённого production JSON отдельным непривилегированным UID.
2. Настоящий prepare под 077: реальная файловая система/mkdir/chown/chmod/runuser/validate; только пути в /tmp, создание аккаунта и вызовы systemd изолированы. Никакой сервис не запускается, никакой ACME-заказ не создаётся.
3. Заведомо неверная JSON-фикстура обязана отклоняться; фиксируется точный след неудачной подготовки: staged files есть, но owner/checkpoint/units и systemd-вызовов нет.
4. Проверяются режимы каталогов и файлов. Итоговый JSON совпадает с renderer.
5. Gate обязателен после checkout текущих reviewed controls, до TLS acceptance и публикации пакета; не скрывается internal-CA override. Дополнительно первый реальный TLS apply на disposable runner теперь идёт с umask 077.

Все прежние unit/integration, browser, SERVER/DEMO, TLS/recovery/update/restore и безопасный откат остаются обязательными. Результаты итогового SHA — в PR checks.

## Что мог оставить неуспешный apply

`prepare()` вызывается **до** записи transaction checkpoint и до try/rollback последующих стадий. До validate он уже создаёт TLS account/group и собственные каталоги; записывает Caddy binary/LICENSE, control.py и caddy.json. Поэтому они могут остаться, а повторный apply справедливо блокируется как неизвестное/незавершённое состояние.

При именно этом месте отказа **данный запуск ещё не** записывал managed.json, transaction.json или unit files, не делал daemon-reload/enable/start TLS/recovery, не менял Studio env/unit и не перезапускал Studio. `checkpoint()` до prepare — объект в памяти, не durable файл. Port-probe listeners закрываются до prepare. SQLite этим контроллером не копируется/не открывается/не откатывается. Фикстура реального prepare подтверждает этот порядок; фактическое состояние VPS после других/параллельных действий неизвестно.

Нельзя из этих выводов обещать, что VPS сейчас чист: могли быть другие попытки/ручные действия. Автоматического удаления/adoption или слепого rollback нет.

## Безопасная read-only проверка перед повтором

После приёмки/merge и зелёного main:

1. **Diagnose Studio HTTPS readiness → main → прежний server_ip.** Существующий read-only workflow дополнен метаданными собственных TLS-каталогов, owner/checkpoint и unit files, состояниями пяти Studio TLS/recovery/monitor units. Это только lstat и существующий пассивный список systemd, без чтения конфигураций/ключей/БД и без перезапусков. Секрет прежний, новых inputs/Secrets нет.
2. Проверить, что Studio активна, health исправен; оценить TLS units и TLS metadata. Для ожидаемого следа этого отказа возможны private BASE/releases/ETC/DATA, отсутствующие owner/checkpoint/unit files и not_observed TLS units. `not_observed` само по себе не доказывает отсутствие файлов; обе части отчёта нужны. `private` — классификация режима, а не доказательство владельца/принадлежности. Active/failed/unknown units, symlinks, owner/checkpoint или любое расхождение требуют отдельной проверки.
3. **Manage Studio HTTPS → main → прежние server_ip/hostname → mode=check, confirmation пустой.** Это только чтение. Check может остановиться:

| Код | Действие |
|---|---|
| UNMANAGED_TLS_PATH_COLLISION | Есть staged/неизвестные TLS paths без owner metadata. Не повторять apply и не удалять их вслепую |
| UNMANAGED_TLS_USER_COLLISION / UNMANAGED_TLS_UNIT_COLLISION | Неизвестная identity/unit; не менять её автоматически |
| PENDING_TLS_RECOVERY_REQUIRED | Есть checkpoint; не запускать новый apply и не откатывать SQLite |
| CHECK_EXISTING_HTTPS | TLS уже принят; не выполнять повторную первоначальную установку |
| CHECK_CANDIDATE_ACTIVE_PROOF_REQUIRED | Чистый кандидат после preflight; ещё не разрешение и не гарантия выдачи сертификата |

Если остались staging paths/account, **это исправление намеренно не обходит защиту**. Перед повтором нужна отдельно согласованная, проверенная очистка только подтверждённых собственных TLS-остатков, без затрагивания `/opt/studio1925`, `/etc/studio1925`, `/var/lib/studio1925`, SQLite, VPN и других приложений. Не выполнять chmod -R/rm -rf/userdel по одной догадке. Данный PR не содержит и не запускает очистку.

Только после подтверждения безопасного состояния и нового отдельного разрешения владельца возможен будущий apply с прежним точным подтверждением. В этом PR apply, merge, deploy, SSH-подключение к VPS, изменение DNS/firewall/служб/SQLite не выполнялись. Передайте для следующего анализа ссылку на read-only run и безопасные классификации, не raw stderr/config/ключи.
