# Studio 19.25 — установка и обновление через GitHub Actions (2.5.2)

**Разработано для приёмки. На реальном VPS не запускалось.** Адресов серверов в коде нет; страна, провайдер и имя сервера не используются. Клиентские экраны, API, бизнес-правила, DEMO/Pages, Backend CI и read-only VPN-аудит не меняются. Публичный HTTPS этим workflow **не создаётся**.

## Что делает владелец

После приёмки и **самостоятельного merge PR** новый workflow появится в `main`. До merge отсутствие кнопки Run workflow ожидаемо; установку из feature-ветки проверка запрещает. На этом этапе Codex не выполняет ни merge, ни установку на VPS.

1. Сначала оцените VPS по [инструкции аудита](vps-audit-runbook.md). Убедитесь, что выбранный сервер принадлежит вам, есть запас ресурсов и известен обычный режим работы VPN. Кратковременный MemAvailable не доказывает запас под пиковый VPN.
2. Откройте GitHub → `jurist77/loft-booking` → **Settings → Secrets and variables → Actions → New repository secret**.
3. Name: **`STUDIO_SSH_PASSWORD`**. Secret: существующий SSH-пароль root выбранного VPS. Нажмите **Add secret**. Не вставляйте пароль в issue/PR/чат, workflow inputs, Variables, команды или исходный код. Для другого сервера с другим паролем обновите этот Secret **до** запуска; один Secret не хранит таблицу серверов. Не меняйте его во время установок.
4. Убедитесь, что последние проверки `main` успешны: `Check backend foundation`, `Check read-only VPS audit tool`, `Check universal installer`. Если main только что обновлён, дождитесь проверок.
5. **Actions → Install Studio 19.25 → Run workflow**. Branch: **main**. Заполните единственное поле **`server_ip`** голым IPv4 или IPv6, без `http://`, порта, квадратных скобок, имени сервера или shell-команд. Нажмите **Run workflow**. Адрес вводится каждый раз; исходный код его не содержит. Input не является Secret: не рассчитывайте на конфиденциальность IP в метаданных GitHub Actions.
6. Дождитесь всех jobs. Сборка и отказные тесты x64/ARM64 выполняются на бесплатных стандартных GitHub runners; это может занять несколько минут. Пакет не попадает на VPS до успешных проверок. Откройте Summary job установки: там версия (полный SHA), операция, миграции, service, HTTP health, loopback listener и **SUCCESS/FAILED**. Зелёная сборка без успешного install job не означает установку.

Другие поля, ключи или токены в Run workflow не нужны. SSH использует **root, порт 22**. Установщик не включает парольный/root SSH, не меняет sshd и не создаёт обходные способы входа. Если такая авторизация уже запрещена, запуск завершится ошибкой; изменение политики доступа требует отдельного решения владельца.

Workflow запускается **только вручную**. Push/merge main сам по себе не запускает **SERVER-deploy**; автоматическая публикация DEMO Pages остаётся прежней. Проверочные workflows на push/PR работают только на одноразовых CI runners и не получают SSH Secret. Повторный запуск установки выбирает принятый SHA main **на момент запуска**, не произвольную ветку/тег. Даже если main изменится во время сборки, ставится зафиксированный проверяемый SHA этого run.

## Важное исключение: SSH host key не проверяется

**По указанию владельца только этот установочный workflow отключает проверку идентичности SSH-сервера.** Используются локальные для команды параметры `-F /dev/null`, `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, `GlobalKnownHostsFile=/dev/null`, `UpdateHostKeys=no`. Никакие пользовательские/глобальные SSH-конфигурации не переписываются; read-only аудит и обычный SSH на Mac сохраняют свои правила проверки ключей.

**Риск:** ошибочный IP, перехват маршрута или MITM могут подставить другой SSH-сервер. Workflow передаст ему root-пароль и установочный пакет. Шифрование SSH защищает канал до выбранного peer, но без проверки host key не доказывает, что peer — ваш VPS. SHA256 пакета **не устраняет** этот риск. Проверяйте адрес в доверенной панели провайдера; не запускайте на чужом/непроверенном адресе. Наиболее безопасное будущее улучшение — вернуть pinning host key, но в этом этапе оно не включено вопреки явному решению владельца.

Пароль берётся из Secret только в install job. `sshpass -e` получает его через отдельное окружение `SSHPASS`; пароль не находится в argv, stdin пакета, постоянных/временных файлах, архиве, summary или artifacts. Не применяется shell tracing, env dump, печать SSH config/stderr. Дочерний SSH не наследует GitHub token и прочее окружение runner. В remote env пароль не отправляется. Сырые сообщения SSH/сервера не печатаются; допускаются только фиксированные коды ошибок и проверенные поля результата.

## Совместимость и ограничения приёма

- Ubuntu **24.04**, полноценный systemd с работающим mount namespace / RootDirectory; root SSH:22 и уже установленный Python **3.12+**. При отсутствии базового инструмента установка останавливается, пакеты на VPS автоматически не устанавливаются. Нужны штатные `systemctl`, `systemd-run`, `useradd` и kernel capabilities обычного VPS. Ограниченный LXC/OpenVZ может быть несовместим с sandbox; он не отключается ради установки.
- Архитектуры **x86_64 и aarch64**, отдельные пакеты на `ubuntu-24.04` и `ubuntu-24.04-arm`. ARM-пакет проверяется на настоящем ARM64 runner, не под эмуляцией. Другие OS/архитектуры отклоняются до создания приложения.
- IPv4/IPv6 адреса проверяются как literal и передаются OpenSSH без shell-интерполяции. Сервер должен быть маршрутизируем из GitHub runner: наличие IPv6 loopback в CI не доказывает публичный IPv6 egress конкретного runner. При отсутствии маршрута — отказ подключения, без скрытого NAT64/VPN/стороннего туннеля.
- Node **24.12.0**, ABI **137**, `better-sqlite3` из существующего lockfile. Проверяются OS/arch manifest, версия Node и реальная загрузка native SQLite **в sandbox**. Runtime и нужные shared libraries включены в пакет; существующий Node на VPS не заменяется. Не используется бинарный пакет Ubuntu-latest/26 для Ubuntu 24.04.
- Перед изменениями приложения требуется минимум **512 MiB MemAvailable** и свободное место на фактических разделах для двух размеров распакованного пакета, входящего архива, трёх размеров текущих DB-файлов и 512 MiB резерва. Отдельный upload staging проверяет свободное место. Это консервативные **нижние admission thresholds**, не замер пика Next/VPN, не гарантии и не жёсткий memory limit. Если VPS тесен, устанавливать нельзя.
- Все целевые каталоги/пользователь/unit должны быть свободны либо иметь созданный этим установщиком root-only state. Чужие существующие файлы, symlink-каталоги, пользователь `studio1925` без marker, изменённый unit/identity/group или конфиг приводят к отказу. Автоматического «усыновления» чужой установки нет.
- Для code/data/cache/backups требуется локальная persistent FS: ext4/xfs/btrfs/zfs, определяемая штатным `findmnt` без вывода mount options. NFS/CIFS/FUSE, tmpfs и overlay отклоняются: нельзя обещать надёжный WAL и сохранность после reboot на неизвестном сетевом/временном слое. Фактическая долговечность диска/mount при reboot всё равно требует будущей приёмки; ОС не перенастраивается.
- Сборка идёт off-VPS. VPS не выполняет npm install, npm build, apt upgrade/install, установку Docker/БД/Redis, обновление proxy или Node хоста. Единственный постоянно работающий новый процесс — Next.js под systemd; SQLite встроена.

При малом запасе, неизвестных VPN-пиках или отсутствии offsite backup успешный тест не означает готовность к реальным клиентам. Установка потребляет CPU/диск/сеть; абсолютное отсутствие влияния на VPN без фактических измерений не заявляется. У самого installer понижен nice, у сайта/CLI ниже CPU/IO weight и положительный OOMScoreAdjust, чтобы при давлении ОС предпочитала завершать сайт. Жёсткий MemoryMax без измерений не придуман, WAL/FULL/busy_timeout не ослабляются. Если нормальный профиль приложения не помещается, выбирается другой имеющийся сервер.

## Что находится на VPS после успешной установки

| Объект | Назначение |
| --- | --- |
| `studio1925` | System user/group, nologin, без sudo и дополнительных групп |
| `/opt/studio1925/releases/<sha>-<archive-hash>-<attempt>/` | Root-owned неизменяемый релиз: `manifest.json`, `root/` с кодом, Node и shared libraries |
| `/var/lib/studio1925/` | Постоянная SQLite, владелец studio1925, каталог 0700, файл 0600, не удаляется/не заменяется при обновлении |
| `/var/cache/studio1925/` | Только writable cache приложения |
| `/var/backups/studio1925/` | Приватные online/pre-migration snapshots, не offsite |
| `/etc/studio1925/server.env` | Root:root 0600, только настройки SERVER, без SSH-пароля |
| `/etc/studio1925/state.json` | Root:root 0600, marker, UID/GID, phase, текущий/предыдущий релиз, порт и hash unit |
| `/etc/systemd/system/studio1925.service` | Только служба сайта; `Restart=on-failure`, ограниченный restart budget, автозапуск после успешного health |
| `/run/lock/studio1925-install.lock` | Неудаляемый inode блокировки; предотвращает параллельные транзакции установки независимо от IP/IPv6 aliases |

Приложение работает в `RootDirectory=<релиз>/root`, `WorkingDirectory=/app`. Видит только собранный runtime/код и bind-mount `/data` (его SQLite), `/app/.next-server/cache`. Хостовые `/etc`, `/root`, `/home`, `/opt`, VPN-конфиги не монтируются. Даже world-readable VPN-файл хоста недоступен по обычному пути внутри rootfs. `ProtectProc=invisible`, отсутствие capabilities, `NoNewPrivileges`, `ProtectSystem=strict`, PrivateDevices и отдельный uid дополняют изоляцию. Это Linux process sandbox, не защита от уязвимости ядра/root-компрометации.

CLI миграций/backup запускается короткими systemd transient units `studio1925-task-*` от того же пользователя в том же rootfs; только им дополнительно доступен `/backups`. RuntimeMaxSec и внешние timeout ограничивают зависания; helpers завершаются/собираются. Постоянного backup/monitoring daemon установщик не создаёт. Значения DB-пути внутри jail `/data/studio.sqlite` и host `/var/lib/studio1925/studio.sqlite` обозначают **один файл**.

Ни `firewall`, ни NAT/routes/DNS, ни конфиги/службы 3X-UI/Xray/VPN Manager/reverse proxy не меняются. `systemctl daemon-reload` перечитывает manager config после создания **unit сайта**, не перезапускает другие службы. `systemctl stop/start/disable/enable/reset-failed` вызывается только для studio1925 и её transient helpers. Чужие данные не удаляются.

## Пакет и проверенная версия

`installer-package.yml` — reusable workflow без SSH Secrets. Он собирает оба native-пакета из exact source SHA, выполняет unit/type/lint/integration/HTTP, затем реальные install/update/failure tests в CI. Производственный архив и SHA256 загружаются как artifact **только после** успешных испытаний; сами fault-variant archives, базы, ключи тестового SSH, env и private CI state не публикуются.

`package.py` использует allowlist: `.next-server`, node_modules, runtime TS/config, public, migrations 0001/0002 и CLI. Не меняет next.config и не требует непроверенного standalone tracing. Генерируемые Turbopack ссылки только в чистые npm-ci node_modules материализуются; прочие escapes запрещены. Удаляются foreign/musl native variants, исходные тесты, cache и приватные файлы. Нужные glibc/shared libraries копируются с matching Ubuntu runner. Node/OS licenses сохраняются. На VPS нет symlink/hardlink/device members архива, `..`/absolute paths или setuid files.

Manifest фиксирует source SHA, OS/arch, Node/ABI, SERVER-mode, хэши SQL и распакованный размер. SHA256 всего архива проверяется до отправки и перед распаковкой; миграции дополнительно сверяются с manifest. SHA/digest GitHub Artifact вместе с принятым исходным run задают происхождение; пара archive/checksum сама по себе не является подписью. Независимые Next builds могут иметь разные BUILD_ID — побайтовая воспроизводимость разных сборок не заявляется. Повторная доставка **того же принятого архива** воспроизводит пакет.

Клиент получает обе сборки из собственного успешного workflow run и выбирает пакет по SSH preflight arch. Проверка main запрещает деплой до success последних push-checks Backend/Audit/Installer для exact SHA. При истечении retention прошлых artifacts новый Run workflow пересоберёт и заново проверит пакет, не полагаясь на старую ссылку.

## Установка, повтор и откат

1. Проверка main/IP/наличия Secret, CI пакеты, SSH preflight root/Ubuntu/systemd/архитектура. Данные до этого не меняются. Адрес должен быть literal; scoped/link-local/loopback/multicast/unspecified IP отклоняется.
2. SSH передаёт только код установщика и архив в private temporary upload (0700/0600); размер/время ограничены, каталог очищается после завершения. Затем host lock исключает параллельные изменения приложения. GitHub concurrency дополнительно сериализует одинаковый input; другая форма IP не обходит host lock.
3. Проверка SHA/manifest/путей/места/памяти, managed marker. Создание только собственных каталогов и пользователя. Пакет сначала проверяется на реальную совместимость runtime/SQLite в sandbox.
4. Первая установка: `init` (не перезаписывает существующий DB-файл), `migrate`, `check`. Запуск готового сайта только после этих операций. Автозапуск включается после трёх последовательных HTTP 200 и active service.
5. Если уже установлен тот же source SHA, проверяются managed identity/config и health, восстанавливается enable автозапуска; при исправной службе результат `already-current`, новая БД или дубль не создаются. Остановленная/нездоровая служба проходит контролируемую переустановку того же кода через backup/update path, а не получает ложный SUCCESS.
6. Обновление: online backup API до остановки; disable/stop **только сайта**, второй точный checkpoint после остановки. Изменения SQLite применяются существующим transactional runner без редактирования 0001/0002. Переключается unit на новый rootfs, запускается сайт, проверяются health/service, затем enable и атомарная фиксация state. Предыдущий релиз сохраняется. Данные остаются вне релизов.
7. Ошибка: новый service останавливается/отключается. Если schema+history fingerprint совпадает с pre-update и старый migration runner/check проходит, возвращаются прежние unit/env/code, затем health проверяется заново. Только тогда выводится `rollback=restored-and-health-verified`. Если новая миграция уже committed или старый код/БД не проходят проверку — `rollback=manual-required`, сайт остаётся остановленным. База/брони не удаляются, backup автоматически поверх live DB не восстанавливается.

State записывается атомарно с fsync. `phase=updating` после жёсткого обрыва/отключения питания блокирует дальнейшую автоматическую установку: сначала разбор состояния/совместимости. SIGTERM/HUP/обычные ошибки обрабатываются с cleanup и безопасным rollback; SIGKILL/потеря питания не позволяют обещать выполнение cleanup. Потеря SSH-ответа также означает **неизвестный итог**, а не доказанный отказ сервера. Не запускать много параллельных повторов; дождаться окончания/освобождения lock. Установщик не выполняет автоматический reboot.

Повтор после обычного безопасно завершённого сбоя не удаляет DB; очередной Run создаёт отдельный release attempt. Если state/права/схема требуют разбора, он остановится. Это сознательное ограничение вместо опасного «починить любой ценой». Реальные rollback/recovery операции при manual-required требуют отдельно проверенного решения, а не удаления state или правки журнала миграций вручную.

## Как открыть сайт безопасно

SUCCESS означает локально исправный SERVER, **не публичный сайт**. Адрес в Summary всегда `127.0.0.1:<порт>`. Установщик сначала проверяет 3000; если занят, ищет 3100–3199. Чужой listener не останавливается и не захватывается. Есть неизбежное короткое окно между проверкой и bind; если другой процесс займёт порт, запуск завершится ошибкой и сработает безопасный rollback, а не kill чужого процесса.

На Mac можно открыть отдельный существующий SSH-туннель (не меняет службы VPS):

```bash
ssh -N -T -L 127.0.0.1:ПОРТ_ИЗ_SUMMARY:127.0.0.1:ПОРТ_ИЗ_SUMMARY root@АДРЕС_ИЗ_SERVER_IP
```

Замените оба порта и адрес значениями вашего запуска. В другом окне браузера Mac: `http://127.0.0.1:ПОРТ_ИЗ_SUMMARY`. Локальный HTTP идёт только по loopback, удалённый транспорт шифруется SSH; не добавлять `-g` и не привязывать туннель к LAN/0.0.0.0. Оставьте стандартную проверку host key на Mac включённой и сверяйте fingerprint доверенным способом. Workflow не меняет эти настройки.

На телефоне нужен собственный доверенный SSH-клиент с local forwarding либо будущий согласованный HTTPS. Mac localhost не доступен телефону автоматически. Публичный HTTPS/домен/сертификат/proxy/80/443 — отдельный этап после анализа занятого VPN 443. Установщик не подключает публичные туннельные SaaS и не передаёт контакты по открытому интернету.

Используйте именно `127.0.0.1` и тот же порт локально: это значение `API_PUBLIC_ORIGIN`. Подмена на `localhost` или другой локальный порт приведёт к отказу POST по Origin. Если порт занят на Mac, сначала освободите его; не публикуйте незашифрованный LAN listener ради обхода.

## Ошибки и ограничения эксплуатации

| Код | Действие / смысл |
| --- | --- |
| `MAIN_REQUIRED` / `MAIN_CHECKS_NOT_SUCCESSFUL` | Только main, дождаться success exact SHA. Не ослаблять gate |
| `INVALID_SERVER_IP` | Исправить literal IPv4/IPv6 input, без схемы/порта/zone |
| `STUDIO_SSH_PASSWORD_MISSING` | Добавить repository Secret с точным именем |
| `SSH_AUTH_FAILED` | Пароль/доступ root не принят. Проверить существующую политику; workflow её не меняет |
| `SSH_CONNECTION_FAILED` / `SSH_TIMEOUT_OR_TRANSPORT_FAILED` | SSH:22 недоступен/оборван; raw stderr скрыт. После обрыва нельзя считать результат однозначным |
| `UBUNTU_24_04_REQUIRED` / `ARCH_UNSUPPORTED` / `SYSTEMD_REQUIRED` | Сервер не соответствует поддерживаемой платформе |
| `ARTIFACT_*_MISMATCH` | Неверный/повреждённый пакет. Не отключать проверку |
| `SANDBOX_RUNTIME_UNAVAILABLE` / `NATIVE_SQLITE_UNAVAILABLE` | Не прошёл runtime/sandbox/native smoke; не отключать sandbox и не ставить чужую архитектуру |
| `MEMORY_HEADROOM_BELOW_512_MIB` / `DISK_HEADROOM_INSUFFICIENT` | Недостаточен минимальный запас; не освобождать место удалением VPN/DB и не снижать надёжность |
| `LOCAL_PERSISTENT_STORAGE_REQUIRED` / `STORAGE_TYPE_UNAVAILABLE` | Не подтверждено локальное постоянное хранилище; не переносить SQLite на NFS/tmpfs ради обхода |
| `UNMANAGED_*` / `UNSAFE_*` / `*_CHANGED_*` | Чужие пути/права/конфигурация или незавершённый state; требуется разбор, не принудительное перезаписывание |
| `INSTALL_ALREADY_RUNNING` | Другой installer держит lock. Дождаться завершения, не удалять lock inode |
| `BACKUP_FAILED` / `MIGRATION_FAILED` | Данные не удаляются. Проверить suffix rollback, не делать destructive down-migration |
| `APP_START_FAILED` / `APP_HEALTH_FAILED` | Не удалось подтвердить работающий сайт; SUCCESS не выдаётся, применяется только безопасный rollback |
| `REMOTE_PROTOCOL_FAILED` / `REMOTE_INSTALL_FAILED` | Некорректный/неизвестный ответ, сырые строки не раскрываются |

Автоматические snapshots перед update локальные. **Offsite encryption, retention, health alerts, полная ротация логов и recovery/reboot rehearsal не внедрены этим установщиком.** Их проект — [план VPS](vps-deployment-plan.md) и [SQLite operations](sqlite-operations.md). Systemd restart не лечит corruption/full disk; не удалять WAL/DB. Неиспользованные/неудачные releases и backups автоматически не удаляются, поэтому свободный диск проверяется каждый раз. Нужен отдельный согласованный maintenance-план; бесконечное хранение не гарантируется.

Приложение не пишет контакты/пароли в технические логи; raw SSH/SQL/stack на стороне workflow не публикуются. Runtime stdout/stderr попадает в штатный защищённый journal; глобальные journald/логи VPN не перенастраиваются. До публичной эксплуатации нужны site-specific disk/log policy, offsite restore и проверенный канал уведомлений. Это **тестовое** размещение, не заявление production readiness. Тестировать только вымышленные контакты; правовые условия обработки реальных данных остаются отдельным вопросом.

[Отчёт испытаний и границы проверок](acceptance/v2.5.2/README.md). Ни CI, ни mock-тесты не считаются успешным тестом на реальном VPS/VPN.
