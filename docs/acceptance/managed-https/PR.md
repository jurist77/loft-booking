# Managed HTTPS for Studio 19.25

Добавляет ручной `Manage Studio HTTPS` (check/apply с точным подтверждением), изолированный Caddy/Let's Encrypt HTTP-01 и сохранение HTTPS в install/update/restore. Работающий HTTP сохраняется до доказанного доверенного HTTPS; затем Studio слушает только loopback. SQLite и интерфейс не изменены.

## Соответствие требованиям

| Требование | Реализация / граница |
|---|---|
| Универсальные параметры | Проверенные public IPv4/IPv6, DuckDNS hostname, optional opposite-family IP; нет адреса конкретного VPS в алгоритме |
| Preflight | Два resolver A/AAAA/CAA, ACME directory/clock, назначенные IP, владельцы FD/inode, ресурсы, UFW/nft/legacy. Неизвестное блокирует |
| Явный apply | Только workflow_dispatch/main + текущий успешный CI + ENABLE STUDIO HTTPS; check ничего не меняет |
| Изоляция | Собственный UID/каталоги/units, native pinned Caddy; нет изменения VPN/SSH/firewall/чужих proxy |
| Сертификат | Только production Let's Encrypt HTTP-01; автоматический renew; DuckDNS token не нужен |
| Управляемый HTTPS | Env/state/backup metadata; текущие lifecycle controls для старого app restore; HTTPS backup нельзя восстановить на HTTP target |
| Cutover | Старый HTTP до локального+внешнего TLS/API доказательства; durable checkpoint/recovery; после public-verified запрет downgrade |
| Реальные проверки | CI: настоящий Caddy/systemd/TLS/browser + отдельная SQLite; production workflow только GET, ни одной брони |
| Мониторинг | Свой локальный timer + opt-in публичный GHA monitor >7 дней, тест доставки failure notification без сети |
| Секреты | Только существующий STUDIO_SSH_PASSWORD; host-key policy Studio сохранена, MITM риск документирован |
| Восстановление | SQLite не откатывается; неизвестные ручные изменения не перезаписываются; повтор HTTPS идемпотентен |
| PR без deploy | Отдельная ветка/обычный PR; merge, SSH/VPS/apply и monitor activation не выполнялись |

## Проверки

Локально: installer 65, HTTPS 27, прежние network/audit 38 и firewall 50 тестов; production Caddy JSON validation; настоящий TLS/API/SQLite COMMIT/idempotency/overlap/Origin и автоматическое продление короткоживущего CI-сертификата без restart. Также прошли 161 unit, 57 integration, HTTP health recovery, 18 API HTTP checks, 66 SERVER/DEMO browser scenarios, typecheck/lint, SERVER и Node/static DEMO builds и аудит экспорта без секретов. Актуальные результаты обязательных проверок: https://github.com/jurist77/loft-booking/pull/19/checks. Успех native TLS/systemd gate подтверждается только зелёным Installer CI; незавершённые/красные runs не являются приёмкой.

Обязательные CI x64/ARM64: существующие unit/integration/HTTP/Node build, реальное systemd обновление/rollback, браузерный путь из immutable release artifact; дополнительно настоящий HTTPS/browser SQLite flow, hard-crash recovery timer, update/restore HTTPS preservation и actual short-lived certificate renewal. Backend CI и DEMO CI остаются обязательными существующими проверками.

## Ограничения и запуск

Текущий безопасный admission допускает только inactive UFW + доказанно пустые ACCEPT nft/iptables/legacy, прямое назначение public IP, один A и/или AAAA, свободные 80/443. Не открывает порты, не принимает NAT, чужие listeners или неоднозначную фильтрацию. Read-only check выдаёт candidate: входящий путь доказывается кратким ограниченным challenge listener только внутри разрешённого apply до изменения Studio. Провайдерская доступность и production LE на реальном VPS ещё не проверены.

Настройка мониторинга и доставка уведомления требуют действий владельца; GitHub schedule не SLA. Версия Caddy/hostname не меняются автоматически. Неизвестные файлы/частичная подготовка требуют ручного анализа, не слепой очистки. После подтверждённого HTTPS автоматического возврата на HTTP нет. TLS private keys не входят в SQLite backup; новый target сначала получает собственный проверенный HTTPS.

[Пошаговая инструкция, риски, recovery и ограничения](../../managed-https.md).

После merge владельцем и успешного main CI: проверить DuckDNS → Run check → принять отчёт → отдельно разрешить apply с точным подтверждением → проверить внешние TLS/GET API/backend closure → включить monitor variables и проверить доставку тестового failure notification. Реальные контакты/рабочие POST не используются для автоматической приёмки.

Регрессионная проверка передачи порта: воспроизведён TIME_WAIT/EADDRINUSE после временной HTTP-проверки; SO_REUSEADDR позволяет Caddy занять освобождённый порт без ожидания и без SO_REUSEPORT. Десять последовательных реальных loopback handovers проходят; действующий listener по-прежнему блокирует bind. Также проверяется штатное отсутствие unit в systemd 255 без игнорирования ошибок инвентаризации.

Отдельная non-root проверка renew использует высокие loopback-порты с явными `http_port`/`https_port`: без этого Caddy добавлял неявный redirect listener на 80. Production конфигурация 80/443 не меняется. Реальные systemd/TLS, все восемь browser checks, update/restore и expiry signal уже прошли на обеих архитектурах; окончательный combined gate требует также успешного native renew и прежних installer checks.

Runner отклоняет преждевременный SUCCESS и переставленные/пропущенные этапы SSH-протокола: внешние проверки портов → сертификата → cutover обязательны до подтверждения установки. Для уже включённого HTTPS обязательно отдельное внешнее verify-existing. Регрессионные проверки используют настоящий subprocess/pipe.
