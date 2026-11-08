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

Локально: installer 64, HTTPS 20, прежние network/audit 38 и firewall 50 тестов; production Caddy JSON validation; настоящий TLS/API/SQLite COMMIT/idempotency/overlap/Origin и автоматическое продление короткоживущего CI-сертификата без restart. Финальные CI результаты и SHA добавляются после выполнения GitHub Actions.

Обязательные CI x64/ARM64: существующие unit/integration/HTTP/Node build, реальное systemd обновление/rollback, браузерный путь из immutable release artifact; дополнительно настоящий HTTPS/browser SQLite flow, hard-crash recovery timer, update/restore HTTPS preservation и actual short-lived certificate renewal. Backend CI и DEMO CI остаются обязательными существующими проверками.

## Ограничения и запуск

Текущий безопасный admission допускает только inactive UFW + доказанно пустые ACCEPT nft/iptables/legacy, прямое назначение public IP, один A и/или AAAA, свободные 80/443. Не открывает порты, не принимает NAT, чужие listeners или неоднозначную фильтрацию. Read-only check выдаёт candidate: входящий путь доказывается кратким ограниченным challenge listener только внутри разрешённого apply до изменения Studio. Провайдерская доступность и production LE на реальном VPS ещё не проверены.

Настройка мониторинга и доставка уведомления требуют действий владельца; GitHub schedule не SLA. Версия Caddy/hostname не меняются автоматически. Неизвестные файлы/частичная подготовка требуют ручного анализа, не слепой очистки. После подтверждённого HTTPS автоматического возврата на HTTP нет. TLS private keys не входят в SQLite backup; новый target сначала получает собственный проверенный HTTPS.

[Пошаговая инструкция, риски, recovery и ограничения](../../managed-https.md).

После merge владельцем и успешного main CI: проверить DuckDNS → Run check → принять отчёт → отдельно разрешить apply с точным подтверждением → проверить внешние TLS/GET API/backend closure → включить monitor variables и проверить доставку тестового failure notification. Реальные контакты/рабочие POST не используются для автоматической приёмки.
