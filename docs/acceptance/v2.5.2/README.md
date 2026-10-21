# Приёмка 2.5.2 — универсальный GitHub installer

Дата: 21.10.2026. Основа: `main` после PR №11, `c7a8a453c3aab3914eee8296e4cdd46ff2a81e33`. Рабочая ветка: `feat/universal-github-installer-v2.5.2`. PR готовится отдельно, merge и реальное VPS-развёртывание не выполняются.

**Серверы владельца не использовались.** Реальные systemd/SSH/SQLite проверки выполняются исключительно в одноразовых GitHub Ubuntu 24.04 runners x64 и ARM64. Это не доказательство достаточных ресурсов, доступности SSH, отсутствия влияния на реальный VPN или готовности HTTPS на будущем VPS.

## Состав

| Файл | Назначение |
| --- | --- |
| `.github/workflows/install-studio.yml` | `Install Studio 19.25`, только workflow_dispatch, единственный input server_ip, парольный Secret только install job, root:22, итог Summary |
| `.github/workflows/installer-package.yml` | Переиспользуемая native-сборка и испытания на двух Ubuntu 24.04 архитектурах; публикация только проверенных artifacts |
| `.github/workflows/installer-checks.yml` | Автоматические проверки установщика на PR/main, без SSH к VPS и без SSH Secrets |
| `scripts/installer/package.py` | Allowlisted self-contained rootfs: Node, shared libraries, Next SERVER, SQL/CLI, manifest и SHA256 |
| `scripts/installer/remote.py` | Совместимость, lock, managed identity/права, первая установка/update/backup/migrate/systemd/health и безопасный rollback |
| `scripts/installer/deploy.py` | Password SSH через env, IPv4/IPv6, ограниченное исключение host-key check, private upload framing, безопасные коды/summary |
| `scripts/installer/verify-main.py` | Точный main SHA и последние успешные Backend/Audit/Installer push-checks, проверка input/наличия Secret до SSH |
| `scripts/installer/schema.mjs` | Только fingerprint схемы и журнала миграций; не клиентских строк |
| `tests/installer/test_installer.py` | Security/contract unit tests: input, gate, ошибки SSH, secret-free output, tar/links/ABI, ports, lock, private unit |
| `tests/installer/real_systemd.py` | Настоящий production receiver/installer, systemd rootfs, HTTP/SQLite, repeat/update/failures/rollback/data и инварианты CI host |
| `tests/installer/real_ssh.py` | Настоящий SSH на loopback с синтетическим test account/password: success/auth failure/connection failure/безопасный вывод |
| `docs/universal-installer.md` | Настройка Secret, Run workflow, архитектура/права, доступ через SSH, ограничения, риск MITM и recovery |
| `README.md`, этот отчёт | Навигация и результаты |

Исходный `src`, Next config, package/lock, миграции 0001/0002, логотип/изображения, прежние unit/integration/E2E, Pages workflow, Backend CI и VPN-аудит не менялись. Новый SERVER deployment не запускается по push. Установщик не добавляет API, бизнес-операции, административную панель или уведомления.

## Автоматические сценарии

| Требование | Проверка |
| --- | --- |
| Первая установка | Реальный root installer на Ubuntu 24.04 CI без предшествующей Studio; init/migrate/check, service active/enabled, health 200 |
| Повтор | Тот же source SHA → already-current; ранее созданная вымышленная бронь остаётся в SQLite/GET |
| Обновление | Новый test release, тот же DB, сохранён previous release, online и pre-migration snapshots |
| Ошибка SSH | Настоящий локальный sshd остановлен → SSH_CONNECTION_FAILED, без raw stderr |
| Неверный пароль | Настоящий sshd + synthetic password → SSH_AUTH_FAILED; Secret владельца не нужен и не используется |
| Занятый порт | На 3000 удерживается отдельный CI listener; приложение получает свободный loopback-порт, прежний socket остаётся |
| Неверная архитектура | Настоящий tar/manifest parser отклоняет wrong-arch до распаковки; correct native пакеты отдельно испытываются на x64 и ARM64 |
| Ошибка миграции | В отдельном тестовом архиве SQL 0003 с синтаксической ошибкой; транзакция откатывается, прежний service/бронь проверяются |
| Ошибка старта | В fault archive отсутствует BUILD_ID; SUCCESS запрещён, первая неудачная установка не оставляет работающий service |
| Откат | Неизменная schema/history → старый migration check и health; после committed тестовой миграции rollback блокируется, DB сохраняется и сайт остановлен |
| Секреты | Пароль не в argv/files/upload/artifact; unit adversarial stdout/error и настоящий SSH malformed stdout не публикуют raw значения |
| Другие службы/VPN | Инертная CI service-canary: PID и файл неизменны; fingerprints прочих unit/config, DNS, routing и firewall проверяются; host canary 0644 недоступен внутри jail |

В сравнении `iptables-save` исключаются только заголовки времени и числовые packet/byte counters цепочек, у route — уменьшающийся lifetime. **Сами правила, default policies, пути/адреса маршрутов и конфиги не исключаются.** Реальная 3X-UI/Xray/VPN Manager и реальный VPN-трафик не запускались; canary не является VPN-сервисом.

Production receiver тестируется с тем же framed code/archive stream, что применяется после SSH; реальный SSH канал проверяется отдельно на CI loopback. Полного вызова `Install Studio 19.25` с root-паролем настоящего VPS не было. Фальшивые fault archives и БД не публикуются; SHA исходного production package после тестов проверяется на неизменность.

## Результаты

Локальная cloud-среда — Debian 13 без работающего systemd PID1 и без root. Поэтому здесь не имитируется Ubuntu/VPS установка: только Python security unit tests, YAML/синтаксис и доступные existing checks. Root/systemd/архитектурные результаты берутся из GitHub CI, не из моков.

- Unit установщика: **16 passed** в cloud; дополнительно выполняются на обеих CI архитектурах.
- Настоящие install/update/failure/rollback на Ubuntu 24.04 **x64 и ARM64** прошли в CI, включая stopped first failure/retry, сохранность брони и правила безопасности. Проверки private HTTP assets включены в финальный прогон.
- Настоящий SSH CI: успешный вход, неверный пароль, недоступный listener и безопасные ошибки проверены на обеих архитектурах. IPv6 loopback проверяется при наличии kernel support и отдельно отмечается в CI notice; публичная IPv6-маршрутизация/реальный VPS не проверялись.
- В ходе испытаний исправлена классификация отказа авторизации: при NumberOfPasswordPrompts=1 OpenSSH может вернуть 255 вместо sshpass 5. Фиксированные C-locale маркеры stderr разбираются только в памяти, raw stderr не публикуется; число попыток не увеличено. Добавлен regression unit test.
- Старые проверки приложения: **151 unit, 57 SQLite integration, 18 групп API HTTP, health 3×200→503→200/readonly/negative control, 20 SERVER + 26 DEMO E2E**, TypeScript/lint, SERVER/Node DEMO/static DEMO builds и audit 29 экспортированных файлов успешны в Backend CI.
- YAML (inputs/triggers/needs/permissions), ссылки документации, diff и неизменность app/Pages/SQL проверены; секреты/реальные контакты/БД и отчёты VPS не включены. Actionlint локально отсутствует; синтаксис новых CI workflows дополнительно проверен самим GitHub при реальных запусках.

Ссылки на **финальные полные CI runs и точный SHA** приводятся в PR и итоговом сообщении после завершения. PR переводится из draft только после success всех jobs, включая обе архитектуры; успешные отдельные шаги не объявляются успешным deployment. На этом этапе workflow `Install Studio 19.25` на реальном VPS не запускался.

## Оставшиеся ограничения

- Реальный VPS не установлен/не протестирован; нагрузка VPN и минимальные ресурсы конкретной машины неизвестны. CI успех не заменяет [аудит VPS](../../vps-audit-runbook.md).
- Host key verification отключена только install workflow по решению владельца. MITM может получить root-пароль; checksums этого не устраняют. Обычные SSH/audit-настройки не изменены.
- Только Ubuntu 24.04/systemd/Python 3.12/root:22/x64 или arm64 с поддержкой namespace sandbox; пакеты ОС на VPS не устанавливаются. Ограниченные контейнерные VPS могут не подойти.
- Сайт только 127.0.0.1. Публичный HTTPS, телефонный доступ, домен и reverse proxy не настроены. Для Mac предусмотрен проверяемый SSH loopback tunnel, с точным Origin.
- Backups перед обновлением локальные, не offsite. Шифрованный внешний backup/retention/alerts, полный log/disk maintenance и reboot/recovery rehearsal остаются отдельной эксплуатационной работой. Старые/failed releases и snapshots не удаляются автоматически.
- При committed новой миграции или hard interruption не обещается автоматический старый код/restore: сохраняются данные, требуется проверка совместимости. Ничего не стирать для обхода blocked state.
- Реальные персональные данные не использовались; правовые основания публичного сбора контактов не решены этим этапом.

[Инструкция для владельца и технический runbook](../../universal-installer.md). Остановиться для приёмки PR, не запускать на VPS и не выполнять merge автоматически.
