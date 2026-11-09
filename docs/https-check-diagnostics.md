# Диагностика read-only HTTPS check

## Что известно об исходном сбое

Запуск [42604873308](https://github.com/jurist77/loft-booking/actions/runs/42604873308/job/129118157836), main после PR #21, завершился `HTTPS_OPERATION_FAILED`.

По коду и журналу достоверно установлено: DNS проверен, SSH-процесс получил пакет, bootstrap загрузил модули и передал управление `host.entry`. Общий код создаётся в обработчике этого entry. Если бы отказали SSH/framing/import, получился бы другой путь ошибки. Но entry уничтожил исходный тип/сообщение/traceback: **внутренняя фаза и точная первопричина исторического сбоя не установлены**. Их нельзя восстановить по одному общему коду. Повторный запуск старого main без новой телеметрии этого не исправляет.

В изолированных тестах несколько разных сбоев состояния, чтения команд и HTTP дают тот же общий код. Поэтому нельзя объявлять причиной DNS, firewall, нехватку памяти, SQLite, Origin или listener без новых доказательств.

## Подтверждённый дефект кода и исправление

`inventory.own_listeners` вызывал парсер `bindings.listener_records` / `listener_ownership`, но не преобразовывал `rules.Unsafe`. Некорректные/неполные метаданные сокета вызывали этот тип исключения, который entry скрывал под общим `HTTPS_OPERATION_FAILED`.

Теперь этот отказ возвращает `LISTENER_METADATA_UNCONFIRMED` с фазой `CHECK_LISTENER`. Парсер, проверка PID/fd/inode, IPv4/IPv6 и v6only, требования исключительного владения и последующие ограничения сохранены. Отказ остаётся отказом; неподтверждённый listener не допускается к apply. **Этот воспроизведённый дефект обработки ошибки не доказывает, что исторический VPS упал именно на нём.**

## Новая телеметрия

В SSH JSONL передаются только фиксированные события `phase`. Runner проверяет точный набор полей, enum, режим и предел 80 событий. Они не являются ACK и не могут заменить последовательность внешних доказательств apply.

GitHub Summary содержит таблицу начатых фаз и, при ошибке, ограниченные `code`, `phase`, `kind`:

| Группа | Примеры |
|---|---|
| Runner | RUNNER_INPUT / MAIN_CI / DNS / SSH_CHECK / ARTIFACT / SSH_APPLY / RESULT |
| Bootstrap | BOOTSTRAP_HEADER / PAYLOAD / EXEC, MODULE_* |
| Managed state | CHECK_ROOT / INPUT / PENDING / STATE / TLS_OWNER / TRANSPORT |
| Admission | CHECK_PLATFORM / IDENTITY / STORAGE / ENVIRONMENT, READ_* |
| Сеть и приложение | CHECK_FIREWALL / SERVICE / LISTENER / HEALTH / API / TLS_LISTENER / INTERFACES / MEMORY / ACME / STABILITY / LOCAL_TLS / COMPLETE |

`kind`: EXPECTED, JSON_INVALID, NAME_ERROR, ATTRIBUTE_ERROR, IMPORT_ERROR, TYPE_ERROR, LOOKUP_ERROR, ACCESS_DENIED, FILE_MISSING, OS_ERROR, TIMEOUT, VALUE_ERROR, RUNTIME_ERROR или OTHER. Выводится категория, а не динамическое имя класса/текст ошибки.

Нет IP, hostname, nonce, сертификатов/ключей, пароля, содержимого state/env/firewall, ФИО/телефонов, stderr, traceback или внутренних путей. Даже произвольный ALL_CAPS ValueError не становится публичным кодом. Коды ограничены проверенными константами и составными DNS-кодами фиксированного формата.

Начатая фаза не означает успешную проверку. При потере SSH последняя фаза — только последняя полученная точка исполнения; результат может быть неизвестен. Никакого автоматического повторного apply/ослабления защиты/HTTP downgrade нет. Recovery/monitor остаются без протокольных сообщений при локальном запуске сохранённого control.py.

## Доказательства тестами

- Настоящий production bootstrap запускается с `python3 -I -B -S`, реальным framing/PIPE, bundle imports, entry и **полным snapshot**. Подменены только внешние read primitives/факты и данные изолированной фикстуры, а не весь admission.
- Номинальный путь проходит все фазы; попытка записи состояния, lock, служебной команды или изменения файлов вызывает провал теста.
- Ошибки состояния, TLS owner, отдельных read-команд, health/API/ACME определяются по точной фазе и фиксированной категории. Synthetic secret canary не попадает в stdout/Summary.
- Некорректный listener отклоняется именованным кодом; дополнительные firewall rules по-прежнему запрещены.
- Реальный Session сохраняет phase/kind через PIPE и закрывает процесс/потоки. Неизвестные enum/лишние поля не принимаются; ACK/proof guards остаются.
- Native Installer CI x64/ARM64 дополнен полным read-only entry/snapshot с настоящими systemd, сокетами, локальными health/API и проверкой неизменности managed state/env/unit. Только адрес/firewall/outbound admission и метаданные трёх системных родителей GitHub runner — фикстура, без production SSH/DNS/ACME. Остальные TLS/browser/recovery/update/restore проверки сохранены.

Дополнительный native-тест выявил отдельное отличие GitHub runner: полный preflight вернул `CHECK_STORAGE / UNSAFE_DIRECTORY` ([run 42608813172](https://github.com/jurist77/loft-booking/actions/runs/42608813172)). Это именованный отказ проверки прав системного родителя, **не** исторический `HTTPS_OPERATION_FAILED`. Production-проверка не ослаблена: в CI только три чтения метаданных родителей перенесены на изолированные root-owned каталоги в /tmp. Настоящий валидатор сначала обязан отказать на mode 0777, затем пройти на 0755; настоящие /opt, /etc, /var/lib не изменяются. Остальные app/kernel/HTTP проверки остаются реальными.

Конкретные результаты итогового SHA — в PR checks. Успешный CI доказывает исправление диагностики и регрессий на фикстурах/runner, а не устранение ещё неизвестной причины на VPS.

## Следующий безопасный шаг

После приёмки и merge владельцем, затем успешного CI нового main, запустить существующий **Manage Studio HTTPS**, branch `main`, с прежними server_ip/hostname, пустым additional_ip при отсутствии IPv6, **mode=check**, пустым confirmation. Не запускать apply.

Для дальнейшего анализа достаточно ссылки на run и безопасных code/phase/kind из Summary. Не присылать пароль, state/env, raw stderr, firewall/VPN-конфигурации или базу. Если check успешен, старую причину всё равно нельзя считать доказанной: сбой мог быть временным. Если повторяется — новая фаза/категория позволит сузить причину и подготовить подтверждённое минимальное исправление.

В этом PR нет подключения к VPS, установки, перезапуска, миграций/записи SQLite, изменения DNS/firewall/HTTP-сайта, merge или apply. Main-only/проверка зелёного main, CAA/DNSSEC, точный Origin, firewall admission, владение портами и подтверждение apply не изменены.
