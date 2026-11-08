# Fix Studio IPv4 dual-stack bind proof without relaxing firewall safety

`Enable Studio HTTP access` раньше требовал отдельную строку IPv4 wildcard и
отклонял Studio на IPv6 `::`, даже когда этот сокет принимает IPv4. Два локальных
HTTP 200 не доказывают нужный listener: их могут обслуживать разные сокеты/процессы.

Теперь IPv4 fallback требует единственный IPv6 wildcard TCP/3000 с явным
per-socket `v6only:0` из расширенного `ss -e`. Все владельцы должны совпадать с
MainPID Studio, а fd → inode дополнительно подтверждается через read-only `/proc`.
Глобальный `bindv6only` не используется. PID, inode/cookie, fd, адреса, опции и
владение повторно сверяются после обоих health и включены в preflight fingerprint.

Native IPv4/IPv6 сохраняются. Неизвестный V6ONLY, v6-only socket, отдельный IPv4
loopback, несколько неоднозначных listeners, чужой/совместный владелец и замена
сокета не разрешают apply. После bind guard продолжается прежняя полная проверка
UFW/nftables/iptables. Подтверждённые bind + локальный health сами по себе не
означают готовность firewall или внешнюю доступность.

Изменения:

- `scripts/firewall/bindings.py` — read-only разбор идентичности, fd ownership,
  per-socket dual-stack proof; приватные данные остаются на host.
- `scripts/firewall/host.py` — расширенные port-filtered ss, согласованность
  снимка до/после health, общий guard в preflight/apply/postflight и fingerprint.
- `scripts/firewall/studio_http_access.py` — включение helper в SSH payload,
  строгий очищенный `bind_proof` и код `LISTENER_STATE_CHANGED`.
- `tests/firewall/test_dual_stack.py` — 19 новых regression-тестов, включая
  продолжение firewall-проверок и загрузку настоящего embedded SSH payload.
- `tests/firewall/test_studio_http_access.py` — расширенные fixtures inode/fd и
  read-only audit нового helper; старые проверки сохранены.
- `docs/studio-http-access.md` — доказательства, отказы и ограничения.

Проверки:

| Проверка | Результат |
| --- | --- |
| Firewall fixtures + настоящий audited UFW с fake kernel I/O | 50 passed, включая 19 новых; без SSH/firewall операций на VPS |
| Existing network diagnostic | 16 passed |
| Existing installer/backup/restore | 57 passed |
| Existing VPS audit | 11 passed |
| TypeScript / lint | passed |
| Python AST / diff whitespace / secret and target-pattern scan | passed |
| GitHub CI x64/ARM64 | Не подтверждён: доступ к GitHub API из среды ограничен |

Никаких подключений к VPS, запусков реальных check/apply или изменений служб,
firewall, SSH, VPN, приложения/SQLite не выполнялось. Тесты — изолированные fixtures;
они не утверждают, что конкретный VPS уже прошёл новый guard. Отсутствующие extended
socket metadata и сложные multiple-listener конфигурации намеренно остаются отказом.

Отдельный обычный PR от актуального main после PR №15. Не merge автоматически.
