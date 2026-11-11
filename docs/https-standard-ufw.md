# HTTPS со стандартным активным UFW

Причина отказа run 42983896992 — `inventory.empty_firewall()` требовал `UFW inactive` **до** анализа пути пакетов. Это сознательная граница первоначального HTTPS-выпуска, а не доказательство того, что TCP/80/443 закрыты. Между workflows оставался пробел: HTTP получил отдельный audited UFW engine для TCP/3000, а HTTPS не использовал его и тестировался с пустым firewall. Новая версия переиспользует этот engine с явным портом и добавляет обязательный тест полного стандартного Ubuntu UFW, а не только упрощённых цепочек.

## Что происходит

1. Как раньше: verified main CI, два DNS resolver/CAA, direct public IP, Studio identity/unit/listener/health/API, отсутствие чужих TCP/80/443 listeners, ACME и контроль состояния. Никакая проверка не удалена ради UFW.
2. Неактивный UFW: прежнее требование пустых согласованных rulesets остаётся.
3. Активный UFW: официальный lock, проверенная реализация Ubuntu `ufw 0.36.2-6`, root-owned/non-writable files, default deny incoming, allow outgoing, `IPV6=yes`, `MANAGE_BUILTINS=no`; проверяются nft и iptables **обоих семейств**, отдельный legacy backend, persisted/live consistency и сохранность before/after/default/sysctl configs. Смешанные backend, NAT, чужие chains/hooks/sets, scoped/conflicting/непонятные правила и нестандартные политики блокируются.
4. Путь SSH TCP/22 в семействе SSH-соединения должен быть доказан разрешённым. Механизм не создаёт и не исправляет SSH-правила. Поддерживается стандартный профиль OpenSSH; его tuple и правила сохраняются.
5. Если путь TCP/80 или TCP/443 уже разрешён, изменений для него нет. В `check` выводится только `firewall_plan: []`, `[80]`, `[443]` или `[80,443]`, без правил/адресов/комментариев. Это доказательство host firewall, **не** публичной достижимости до появления listener. На уже установленном HTTPS внешний health проверяется, если firewall не требует изменений. При недостающих правилах возвращается `CHECK_FIREWALL_PLAN_REQUIRED`.
6. Только `apply` с точным `ENABLE STUDIO HTTPS` может применить план. Подтверждение теперь явно включает только доказанные недостающие TCP/80/443. Под общим Studio install lock и официальным UFW lock повторно читается состояние, сверяется fingerprint, до первой записи выполняются dry-run планы обоих портов официальным parser/serializer UFW. Каждое реально добавляемое правило ограничено `allow in proto tcp from any to any port 80/443`, только для отсутствующих семейств. Дубликаты не добавляются.
7. Разрешены только append в существующие user-input chains и соответствующее штатное сохранение user rules. Запрещены capability-test chains, flush, insert, delete, policy changes, reload, restart UFW и прямое программирование nftables. Это не shell-вызов произвольного `ufw` без защиты: engine перехватывает subprocess boundary, проверяет допустимые команды и dry-render, блокирует reload fallback. Непроверенная новая версия UFW требует отдельного анализа, а не автоматического downgrade/обхода hash gate.
8. После **каждого порта** сверяется точный kernel/persistent delta: только ожидаемые append; все прежние правила, порядок, политики, SSH и protected configs неизменны. Затем повторяются полный preflight и proof. Только после этого запускается временный nonce-probe; runner должен доказать TCP/80 **и** TCP/443 на каждом опубликованном адресе. Затем — доверенный сертификат, внешний HTTPS health/API, точный Origin/proxy trust, loopback cutover и недоступность публичного backend. Доступность upstream firewall провайдера не угадывается.

### Совместимые `xt`-выражения nft

На реальном стандартном Ubuntu UFW `nft -j` показывает `xt` match/target, но не их полный payload. Прежняя упрощённая модель ожидала только полностью декодированные native expressions. Просто игнорировать `xt` запрещено. Для этого случая добавлен узкий stock-профиль: **вместе** сверяются SHA-256 канонической постоянной части обоих iptables-снимков, всей nft topology/порядка постоянных правил и оригинальных before/after-файлов. Эталон получен из закреплённого официального UFW в изолированном CI; независимые x64/ARM64 результаты совпали. Поддержаны штатные low/off logging profiles; алгоритм не переключает logging target.

Переменные user-input/output правила не исключаются из проверки: разрешены только простые per-port TCP/UDP allow и стандартный OpenSSH; количество, порядок, протокол/порт и допустимая структура каждого nft правила должны точно соответствовать декодированному iptables правилу. Произвольные `xt`, hidden match, иные target, дополнительные hooks/chains/sets, несовпадение двух views или изменение штатных файлов отвергаются. Payload совместимых модулей проверяется декодером iptables-save и эталоном, а не угадывается из неполного JSON. Для полностью native nft сохраняется прежний анализ пути. Это не общий интерпретатор чужого firewall и не смена backend на legacy.

Модель проверяет обычный NEW external/local-unicast TCP, без IPv6 routing headers. Стандартный RH0 DROP не удаляется и не обходится: он остаётся в before-chain и byte-for-byte сохраняется. Необычные header predicates остаются блокирующими. Это не разрешение опасного трафика ради прохождения тестов.

## Ошибки и повторные запуски

- Несовпадение до записи → отказ без изменений.
- Неудача/разрыв связи во время записи → `HTTPS_FIREWALL_CHANGE_UNCONFIRMED_REVIEW_REQUIRED`; возможен partial append. Нет слепого отката или удаления существующих правил. Выполнить новый `check` и изучить состояние; если kernel/persisted расходятся, потребуется согласованный ручной разбор.
- После подтверждённого append Summary фиксирует только номера портов. Если последующий public probe/TLS не прошёл, добавленные разрешения **остаются**. Studio до cutover не меняется, прежний HTTP сохраняется; это не SUCCESS HTTPS. Проверенные rules не удаляются автоматически даже при TLS recovery/rollback.
- Повторный запуск заново доказывает путь: уже открытые порты/семейства пропускаются, добавляются только ещё отсутствующие. Никаких накоплений rules или новых постоянных managers/checkpoints firewall нет.
- Если rules изменились независимо во время TLS, прежний fingerprint больше не совпадёт. Cutover прекращается; существующие правила других компонентов не «исправляются».

Append несравнимо уже flush/reload, но изменение firewall всё равно нельзя объявлять абсолютно безвредным для существующих соединений. При неоднозначности операция блокируется. На серверах с нестандартным VPN/firewall требуется отдельный план; наличие VPN не даёт права менять его правила.

## Update, restore и новый VPS

Install/update/restore приложения не стали редакторами firewall. Backup SQLite/settings содержит данные и HTTPS metadata, **не** копию правил старого VPS. На новом target сначала выполняется собственный HTTPS check/apply и внешняя проверка, потом допускается обычный restore. Hostname/loopback/Origin сохраняются действующим lifecycle. Нельзя восстанавливать firewall старого сервера поверх правил target.

На исходном VPS повторный HTTPS check/apply не требует firewall-изменений, если 80/443 уже доказанно доступны. Приложение и SQLite не перезапускаются для добавления правил; дальнейший HTTPS cutover использует прежнюю проверенную процедуру с сохранением данных.

## Проверки и безопасный запуск владельцем

- Unit fixtures: план/check без записей; 80/443 уже открыты; разные состояния IPv4/IPv6; OpenSSH; отсутствие SSH; conflicting/scoped/foreign/NAT rules; изменение состояния; ошибка append/partial success; строгий postflight; повтор; провал external proof до подготовки TLS/изменения Studio.
- Настоящий parser/serializer закреплённого UFW, извлечённого из checksum-verified официального `.deb`: dry-run, только два допустимых append, пропуск уже существующего семейства, отсутствие reload/flush/delete.
- Обязательные `Check Studio HTTPS / ufw_kernel` на x64 и ARM64: **реальный** stock UFW + nft/iptables в приватных mount/network namespaces, OpenSSH, IPv4/IPv6 veth ingress с отдельного client namespace, закрытые 80/443 до apply, доступные после, SSH/соседний порт сохранены, повтор без изменений. Host firewall/config вне namespace сравнивается до/после. Setup UFW в тесте относится только к изолированной fixture, никогда к VPS.
- Прежние Backend CI и Installer CI x64/ARM64 остаются обязательными: browser/SQLite, настоящие Caddy/systemd, update/restore, recovery и rollback.

Этот PR не подключается к VPS, не меняет DNS/firewall и не запускает deploy. После приёмки, merge владельцем и зелёного main: `Manage Studio HTTPS` → текущие server_ip/hostname/additional_ip → **check**. Проверить `firewall_plan` и отсутствие других ошибок. Только затем отдельным осознанным ручным запуском **apply** с точным подтверждением. Непустой план не является разрешением обойти неизвестную фильтрацию. Финальный SUCCESS требует внешнего HTTPS, а не наличия rules.
