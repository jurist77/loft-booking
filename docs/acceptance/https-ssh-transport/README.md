# HTTPS SSH input: исправление duplex transport

## Доказательства и границы вывода

Исходный main: `8aae6a9efc2f66bbe8e76161c2176097266a9edc` (merge PR30). Через штатный GitHub API подтверждены failed apply [43086228271](https://github.com/jurist77/loft-booking/actions/runs/43086228271) и successful check [43087103707](https://github.com/jurist77/loft-booking/actions/runs/43087103707) на этом SHA. Apply-step длился 157 секунд; check-job — 63 секунды. Эти общие длительности не разделяют DNS, download и SSH upload. Полные журналы недоступны из среды разработки; фактическую скорость/очередь stdout того apply установить не удалось.

В старом `Session.write()` select следил только за writable stdin. Пока весь пакет не записан, stdout не читался. Если peer сначала заполняет stdout и перестаёт читать stdin, заполняется второй pipe: обе стороны ждут друг друга до `SSH_INPUT_TIMEOUT`. Регрессия воспроизводит это настоящими локальными Python-процессами с обоими pipes 4096 байт: 75 допустимых phase-событий перед чтением тела + большой payload. Старая реализация получает timeout, исправленная проходит тот же peer, сохраняя FIFO и все события.

**Это подтверждённый дефект транспорта, но не доказанная единственная причина конкретного запуска.** Штатный bootstrap до получения всего архива печатает только BOOTSTRAP_HEADER / BOOTSTRAP_PAYLOAD: 97 байт, обычно недостаточно для заполнения stdout. MODULE/host-события возникают после полного read архива. Не приписываем инцидент stdout-deadlock автоматически.

Зафиксированные официальные Caddy 2.11.9 архивы с правильными SHA-256: x64 **18 020 988 байт**, ARM64 **16 342 262 байта**. Bundled control исходного main — 199 261 байт плюс JSON header. Прежний client write deadline и remote bootstrap alarm — по 120 секунд. Для x64 требуется в среднем больше примерно 152 KB/s (~1,2 Mbit/s), без учёта запуска/SSH overhead. На более медленном/застопорившемся канале возможен настоящий deadline timeout даже без stdout flood. Без журнала/измерений не утверждаем, что это произошло. Тайм-ауты не увеличены и не превращены в безграничный inactivity retry.

## Минимальное исправление

- Один select одновременно обслуживает nonblocking stdin/stdout. Общий bounded receive сохраняет байты в прежнем FIFO buffer **до 8192 байт**; record() и существующая строгая проверка событий/80-phase limit продолжают применяться. Неизвестный/избыточный output не печатается и не разрешает apply.
- Частичные записи учитываются по фактически принятому числу байт. Deadline остаётся абсолютным: даже stdout-активность/малый прогресс его не продлевают. EOF/auth/connection failure не считаются успешным HTTPS, автоматического повтора apply нет.
- После EOF stdin при cleanup stdout дренируется фиксированными небольшими блоками без накопления/печати. Это устраняет второй круг ожидания: peer flush при выходе/rollback против parent wait. Сохранены 90 секунд grace, затем прежние TERM/10 секунд/KILL и reap.
- Для SSH_INPUT_TIMEOUT Summary показывает только local pipe accepted/total bytes, elapsed seconds и buffered stdout bytes. Это не подтверждение приёма сервером и не результат операции. Адреса, hostname, архив, пароль, raw stderr/ответы не выводятся.
- Bootstrap framing, размеры, alarm, TLS/Origin/DNS/firewall/ownership checks, nonce ACK/external proof, hash официального архива перед prepare и rollback/recovery не меняются. Нет потоков, сервисов, протокола v2, reinstall или изменений приложения.

## Тесты

`tests/https/test_session_transport.py`: воспроизведение старой взаимной блокировки, исправленный проход, большой payload, медленные чтения, частичные os.write, неизменный абсолютный deadline, раннее закрытие/auth/connection failure, потеря соединения между proof и result, oversized stdout/redaction, cleanup flush, безопасный Summary.

`tests/https/full_archive_transport.py`: обязательный native x64/ARM64 gate внутри существующего Installer CI после скачивания/валидации закреплённого Caddy и до публикации. Проверяет manifest SHA и передачу **полного** архива через настоящий bootstrap, загружая реальные bundled modules. Заменяется только mutating host entry на локальный контролируемый receiver с SHA-256 и тем же proof/ACK порядком. Нет SSH, реального host admission, запуска Caddy/Studio, DNS, firewall, БД или VPS apply. Локально через pipes прошли оба полных архива; перенос ARM64-байтов на x64 не выдаётся за native ARM64 execution. Native architectures дополнительно проверяются CI.

Существующие реальные Caddy/systemd/TLS/browser/isolated SQLite/install/update/restore/rollback проверки остаются обязательными. Локально: 88 HTTPS, 74 Installer и 16 quarantine tests passed; diff check passed. Полные статусы/ссылки CI итогового SHA — в PR.

## Повтор владельцем без терминала

1. После приёмки, merge владельцем и зелёных обязательных main push checks открыть Actions → **Manage Studio HTTPS → Run workflow → main**. Указать текущие server_ip/hostname, дополнительный IP только если он действительно используется; mode=**check**, confirmation пустой. Переподключать/переустанавливать Studio не нужно.
2. `CHECK_EXISTING_HTTPS` означает проверку уже действующего HTTPS — повторный apply не требуется. Для `CHECK_CANDIDATE_ACTIVE_PROOF_REQUIRED` проверить отсутствие остальных блокировок и firewall_plan (в исходном отчёте пустой). Этот check не выдаёт сертификат и не доказывает будущий active probe.
3. Только отдельным осознанным ручным запуском владельца выбрать **apply**, те же inputs и точное `ENABLE STUDIO HTTPS`. В рамках разработки apply/deploy не запускаются.
4. Успех определяется прежней полной цепочкой внешних DNS/80/443/TLS/health/API/backend-closure проверок и финальным SUCCESS, не приёмом архива в локальный pipe. Боевые POST бронирований не создаются.
5. При transport timeout/разрыве исход остаётся неизвестным. Дождаться существующего recovery и повторить только check; не выполнять автоматический apply/reinstall, слепую очистку, HTTP downgrade или правку checkpoint. Если timeout повторится — передать безопасный Summary с byte/time counters и фазой для точной диагностики скорости/остановки канала. Pending recovery/ownership/collision/другой blocker требует отдельного разбора.

VPS, SSH configuration, DNS, firewall, SQLite/контакты и работающая Studio не изменялись. Код транспортного исправления проверяется в PR, но реальный HTTPS на VPS им не объявляется включённым.
