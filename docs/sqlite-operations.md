# Простая эксплуатация на Ubuntu 24.04 — проект, не развёртывание

Постоянно работают Next.js и HTTPS reverse proxy. Отдельного процесса БД нет. systemd управляет приложением и периодическими oneshot-задачами. Предлагаются бесплатные Nginx + Certbot и restic; Docker, внешняя БД, ORM, очереди и платные SaaS не требуются. Ни один пример ниже не устанавливался на VPS в этом этапе.

## Каталоги и запуск

- `/opt/studio1925/releases/<commit>/` — неизменяемые релизы и native node_modules под Ubuntu/Node 24, владелец deploy/root.
- `/opt/studio1925/current` — ссылка на выбранный релиз; это ссылка кода, **не ссылка файла SQLite**.
- `/var/lib/studio1925/` — единственный постоянный каталог SQLite (0700, владелец studio1925); его не включать в релиз/очистку build.
- `/etc/studio1925/server.env` — APP_MODE=server, SQLITE_PATH=/var/lib/studio1925/studio.sqlite, SQLITE_BUSY_TIMEOUT_MS=1000. Права 0600; секретов БД нет.
- `/var/backups/studio1925/` — private staging snapshots, не конечное backup-хранилище.

Пример systemd unit для будущей проверки на целевом VPS:

```ini
[Unit]
Description=studio 19.25 Next.js
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=studio1925
Group=studio1925
WorkingDirectory=/opt/studio1925/current
EnvironmentFile=/etc/studio1925/server.env
Environment=NODE_ENV=production
ExecStart=/usr/bin/node node_modules/next/dist/bin/next start --hostname 127.0.0.1 --port 3000
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
StateDirectory=studio1925
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/studio1925 /opt/studio1925/current/.next-server/cache

[Install]
WantedBy=multi-user.target
```

Каталог cache заранее создаётся и доступен пользователю приложения; код релиза остаётся недоступным для записи. Фактический путь Node и sandbox-настройки нужно проверить при будущем развёртывании. Приложение не запускается от root. systemd Restart восстанавливает процесс, но не исправляет повреждённый диск/БД.

## HTTPS

Nginx проксирует на 127.0.0.1:3000, Certbot получает/обновляет бесплатный сертификат Let's Encrypt через systemd timer. Понадобятся согласованный домен и DNS на VPS; они ещё не предоставлены/не настраивались. PostgreSQL-портов нет. SSH ограничивается штатными средствами владельца, существующий VPN не меняется.

Health раскрывает только ok/unavailable и статус HTTP. Для внешнего мониторинга допустим этот минимальный endpoint за HTTPS с ограничением частоты на reverse proxy; например stock Nginx `limit_req_zone ... rate=1r/s` и `limit_req ... burst=3 nodelay` на `/api/health`. Нельзя добавлять туда пути, версию, SQL, контакты и диагностическую панель. Обычный API трафик в будущем потребует отдельно согласованной защиты.

## Зашифрованная копия вне VPS

1. Владельцу нужен **независимый доступный носитель**: собственный NAS/компьютер с SSH/SFTP или другое уже доступное хранилище. Платный второй VPS не обязателен. Если внешнего носителя нет, критерий offsite-backup не выполнен; копия на том же VPS этого не заменяет.
2. Использовать restic: бесплатная встроенная аутентифицированная шифрация, дедупликация и проверка репозитория. SSH host key проверяется; не использовать StrictHostKeyChecking=no. Отдельный ограниченный backup-доступ, не административная учётная запись сайта.
3. RESTIC_REPOSITORY и пароль/SSH-ключ хранятся в private настройках, не в Git/CI/чатах. Пароль restic обязательно сохранить **отдельно от VPS** в доступном владельцу защищённом месте. Потеря ключа означает потерю возможности восстановления.
4. systemd oneshot сначала вызывает `db:backup` в уникальный staging-каталог, затем `restic backup` готового snapshot. Только успешный exit означает успешную задачу. При ошибке upload staging сохраняется для повторной отправки и выдаётся уведомление.

Пример содержания будущего backup-скрипта (пути и restic environment настраивает владелец):

```bash
#!/bin/sh
set -eu
umask 077
cd /opt/studio1925/current
jobdir=$(mktemp -d /var/backups/studio1925/snapshot.XXXXXX)
node --env-file=/etc/studio1925/server.env --conditions=react-server scripts/database.mjs backup --to "$jobdir/studio.sqlite"
restic backup --tag studio1925 "$jobdir"
rm -r -- "$jobdir"
```

Это **документационный шаблон**, не запущенный сервис. Staging родитель создаётся 0700; скрипт работает пользователем-владельцем SQLite. Restic получает credentials безопасно через systemd EnvironmentFile/LoadCredential, не аргументами пароля. `restic init` выполняется владельцем один раз, не при каждом backup.

Будущий timer: `OnCalendar=*-*-* 03:15:00`, `Persistent=true`, `RandomizedDelaySec=10m`; service `Type=oneshot`, `User=studio1925`, `UMask=0077`, разумный TimeoutStartSec (например 10 минут) и ошибка/уведомление при превышении. Это периодическая задача, не постоянно работающий backup-daemon.

Начальная политика хранения: 7 дневных, 5 недельных, 6 месячных копий; уточнить по объёму/доступному диску. Prune/forget выполняется отдельно с контролем владельца; доступ с VPS к хранилищу способен удалить доступные ему копии, поэтому на NAS/носителе нужны независимые snapshots/периодическая offline-копия или отдельные права удержания. Это ограничение нельзя решить одной шифрацией.

`restic check` — еженедельно, проверка данных `--read-data` и учебное восстановление — ежемесячно. Следить за возрастом последнего успешного snapshot, свободным местом staging/БД, inode и ошибками fsync. WAL требует свободного диска; не удалять `-wal` вручную.

## Восстановление и проверка

Плановый offline-runbook, после согласования владельцем:

1. Остановить `studio1925.service`. Убедиться, что процесс завершён и нет других CLI/писателей. Не восстанавливать поверх открытой SQLite. Не удалять исходные данные.
2. Сохранить **весь** `/var/lib/studio1925` под новым именем, вместе с `studio.sqlite`, `-wal`, `-shm`. Это материал для диагностики и возможность вернуться назад. Создать новый пустой `/var/lib/studio1925` с владельцем studio1925 и правами 0700.
3. На чистом/исправном диске `restic check`, затем `restic restore <snapshot-id> --target <private-restore-dir>`. Нужны доступ к offsite и сохранённый отдельно пароль. Убедиться, что выбран snapshot нужной даты и именно нужной студии. Decrypted snapshot — приватные данные: владелец studio1925, права 0600, родитель 0700.
4. Под пользователем studio1925 из **совместимого релиза**:

```bash
node --env-file=/etc/studio1925/server.env --conditions=react-server scripts/database.mjs restore --from /absolute/private-restore-dir/path/studio.sqlite
node --env-file=/etc/studio1925/server.env --conditions=react-server scripts/database.mjs check
node --env-file=/etc/studio1925/server.env --conditions=react-server scripts/database.mjs migrate
```

5. При integrity/history mismatch остановиться; не менять журнал вручную. Установить совместимую версию кода либо выбрать подходящую копию. Скрипт никогда не заменяет существующий destination, поэтому ошибочный путь не уничтожит рабочую базу.
6. Запустить systemd service, проверить локальный и внешний HTTPS `/api/health` (именно 200), отсутствие ошибок записи, несколько последующих запросов, правильную версию релиза. Для будущей реальной записи проверить согласованные количества/интервалы без публикации контактов. В этом этапе реальных записей нет.
7. Зафиксировать snapshot-id, версию приложения, время восстановления и результат; прежний каталог не удалять до приёмки. Для учебной проверки использовать другой private путь и отдельный порт, не трогать рабочий service.

Целевые RPO при ежедневной копии — до суток, RTO зависит от объёма и доступности носителя/владельца. Это **план**, не измеренная гарантия. Перед настоящим запуском сделать полный rehearsal с offsite-копией и записать фактическое время.

## Доступность и уведомления

- systemd автоматически перезапускает процесс, journal сохраняет технические ошибки без контактов/SQL/секретов.
- В будущем отдельный oneshot health timer раз в минуту проверяет локальный `/api/health` с timeout; ошибка процесса/БД/возраст backup должны давать сигнал владельцу, а не только запись в log.
- Для внешнего сигнала без платного сервиса можно использовать отдельный scheduled GitHub Actions в текущем public-репозитории: HTTPS health будущего VPS каждые 5 минут и проверка возраста offsite backup по согласованному механизму. Ошибка job → GitHub email notifications владельцу (включить и проверить тестовым отказом). Для локальных systemd/backup ошибок — существующий бесплатный почтовый канал владельца/oneshot SMTP-клиент после согласования; Telegram не подключается.
- GitHub schedule не имеет строгой гарантии времени, может задерживаться и отключаться при неактивности репозитория. Альтернатива — периодическая проверка с собственного offsite-компьютера. Наблюдатель должен находиться вне VPS, чтобы заметить полный отказ VPS.
- Production URL, адрес получателя, внешний носитель и канал локальных alert пока не заданы. Никакие мониторинговые workflows, SMTP-ключи или сообщения сейчас не создаются. Нельзя считать эксплуатационный мониторинг внедрённым до тестового получения уведомления.

## Обновление и откат

1. Отдельная ветка → тесты → PR → ручное согласование merge. На текущем этапе merge/deploy не выполняются.
2. Будущий GitHub deployment собирает SERVER для Ubuntu/Node 24, не DEMO. Перед миграцией — verified offsite snapshot; старый релиз сохраняется. Нельзя выкладывать файл SQLite или env в артефакт/Pages.
3. Для простоты короткая maintenance-пауза: остановить приложение, применить миграции из нового релиза, переключить current, запустить, проверить health/запись. Миграционный runner не применяет одновременно два пакета.
4. Если ошибка только в коде и схема совместима — вернуть current на прежний релиз и перезапустить. Несовместимая миграция требует offline restore подходящего snapshot + соответствующего кода; автоматического удаления колонок/down-migration нет. Restore старого snapshot может потерять более поздние изменения, поэтому сохранять неисправную БД и согласовать восстановление.
5. Данные находятся вне release, поэтому очистка старых релизов их не затрагивает. CI/CD, SSH-доступ и systemd/Nginx templates проверяются отдельно на целевой машине до реального запуска.
