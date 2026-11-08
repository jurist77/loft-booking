# Add read-only HTTPS readiness audit and deployment design

Studio уже установлена, но до внедрения HTTPS нужны факты о listeners 80/443,
существующих TLS/DNS механизмах и сетевом пути. Этот PR добавляет ручной
**Diagnose Studio HTTPS readiness** из main, единственный input `server_ip`.
Используется прежний root:22/`STUDIO_SSH_PASSWORD` transport и согласованное
отключение host-key check только для Studio; риск MITM явно документирован.

Новый workflow не запускался. Здесь нет install/apply, ACME выдачи, DNS изменений,
открытия портов, рестартов, миграций или чтения/изменения записей SQLite. Новый
сайт не публикуется. Client/API/DEMO/installer и чужие сервисы не меняются.

## Что добавлено

- `.github/workflows/diagnose-studio-https-readiness.yml`: workflow_dispatch only,
  main guard, contents:read, timeout, literal IPv4/IPv6, target IP masking, чтение
  input из event JSON без shell interpolation. Tool install только на runner.
- `scripts/diagnostics/probe_https_readiness.py`: фиксированный bounded read-only
  inventory. TCP/80,443 IPv4/IPv6 и безопасные категории процессов; Studio MainPID/
  inode/fd ownership и свежий снимок; health; metadata permissions; known DNS/proxy/
  ACME units/tools/paths; UFW+nft+iptables+legacy/NAT summaries. Не читаются env,
  ключи, VPN-конфиги, crontab, journal и database contents.
- `scripts/diagnostics/https_readiness.py`: существующий password SSH helper,
  совместимый private stdin stream, строгое allowlist JSON schema, redaction,
  bounded external TCP/TLS (обычная CA/IP verification), Summary без IP/PII/raw rules.
  Никакого READY_TO_APPLY: даже свободный снимок требует review и разрешения.
- `tests/diagnostics/test_https_readiness.py`: fixtures и настоящий локальный TLS
  server, не VPS; исполняются существующим Check Studio network diagnostic через
  unittest discover. Прежние файлы диагностики и firewall не редактируются.
- `docs/https-readiness.md` + README link: DuckDNS + отдельный Studio proxy как
  условный приоритет, LE IP certificates 160h как альтернатива; схема install/
  cutover/update/renew/alerts/rollback, закрытие публичного 3000 после стабильной
  HTTPS-проверки, точный Origin и trust proxy только после изоляции backend.

## Найденные архитектурные ограничения

1. Installer проверяет точный managed env и сам формирует systemd unit. Прямое
   редактирование Origin/hostname не является поддержанным обновлением:
   следующий этап обязан сохранить HTTPS при install/update/restore, без обхода
   `ENVIRONMENT_CHANGED_OUTSIDE_INSTALLER` и без возврата публичного HTTP-bind.
2. Занятый 443, неизвестный owner и неоднозначные NAT/firewall не разрешают менять
   чужой listener или VPN. 80 занят — HTTP-01 standalone с остановкой владельца
   исключён. Нельзя по UFW ALLOW/одному GET доказать безопасный сетевой путь.
3. Без выбранного hostname нельзя доказать DNS A/AAAA/CAA или проверить доменный
   сертификат по IP. Непройденная IP verification не объявляется сломанным TLS.
4. Known unit/metadata inventory не обнаруживает все custom scripts и cron;
   `not_observed`/missing инструмент не означает отсутствие механизма/ограничения.

## Проверки разработки

| Проверка | Локальный результат |
| --- | --- |
| Diagnostic tests | 38 passed: 22 HTTPS + 16 прежних network |
| Installer/backup/restore tests | 59 passed |
| Existing firewall / VPS-audit tests | 50 / 11 passed; UFW package извлечён в test fixture, не установлен |
| Unit TypeScript | 161 passed |
| TypeScript / lint | passed |
| Workflow YAML / Python AST / diff whitespace | passed |
| TLS trust/IP SAN/expiry + malicious redaction | real local test certificate, passed |
| Runtime диагностика VPS / реальный ACME / изменение firewall | **Не выполнялись** |

Тесты охватывают occupied/free 80/443, v6only/dual-stack observations, другой
процесс и замену Studio socket, нестандартный namespace/systemd, permissions,
сложные firewall/legacy/NAT/default deny, отсутствие инструментов/неполный вывод,
SSH auth failure/private fileno stream, malicious JSON/PII canaries, injection,
реальный локальный verified/untrusted TLS handshake и main/manual-only workflow.

Результаты GitHub CI на финальном SHA проверяются в Checks PR и приводятся ссылками
в итоговом отчёте; локальные результаты не подменяют native builds/CI. Никакой
workflow с SSH на реальный VPS не запускать в рамках этой проверки.

## Что требуется для следующего этапа

После принятия PR владелец отдельно запускает **read-only** аудит и передаёт
очищенный Summary. Затем выбирает контролируемый бесплатный DuckDNS hostname,
подтверждает custom mechanisms и VPN baseline, согласует сетевую схему/изменения
80/443/3000, HTTPS-aware installer, мониторинг и rollback. Только следующий
одобренный PR/manual apply сможет устанавливать proxy/TLS. Реальная готовность
существующего VPS этим PR пока не установлена. Не выполнять merge автоматически.
