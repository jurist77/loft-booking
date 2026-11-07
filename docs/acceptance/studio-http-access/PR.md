# Add guarded manual Studio TCP/3000 UFW access workflow

После установки локальный health Studio может работать при недоступном внешнем
TCP/3000. Новый ручной **Enable Studio HTTP access** проверяет принадлежность
listener, здоровье Studio и полный поддержанный путь локальной фильтрации. В
`apply` требуется точное `ENABLE STUDIO TCP 3000`; единственное разрешённое изменение
— добавление UFW allow TCP/3000. `check` по умолчанию ничего не меняет.

При неоднозначных nftables/iptables, сторонних цепочках, конфликтующих правилах,
неподдержанном UFW, несовпадающем сохранённом/активном состоянии или loopback bind
операция отказывается от изменения. Настоящий UFW serializer предварительно
проверяет оба будущих файла в памяти. Возможные reload, capability test chains,
delete и произвольные команды заблокированы внутри процесса; установленный UFW
проверяется по source hashes. Повтор не добавляет дубликаты. Потеря SSH-ответа или
неожиданный delta требуют ручного разбора; автоматического удаления/отката нет.

SUCCESS требует подтверждённого внешнего health с runner, не только наличия allow.
Raw конфигурации, пароль, комментарии firewall и персональные данные в лог не попадают.
Сохраняется согласованная SSH-политика Studio без host-key verification и её MITM-риск.

Изменённые файлы:

- `.github/workflows/enable-studio-http-access.yml` — dispatch/main, три input,
  существующий Secret, guards до сети, отчёт и внешний health.
- `.github/workflows/studio-http-access-checks.yml` — fixture CI x64/ARM64.
- `scripts/firewall/studio_http_access.py` — coordinator, проверенный протокол SSH,
  безопасный файловый stdin, раздельные результаты external before/after.
- `scripts/firewall/rules.py` — консервативный разбор и доказательство пути/delta.
- `scripts/firewall/host.py` — чтения, UFW lock, source-integrity gate, plan/add,
  запрет побочных команд и postflight.
- `tests/firewall/test_studio_http_access.py` и `test_audited_ufw.py` — stateful fixtures
  и настоящий UFW parser/serializer/CLI с изолированными файлами и fake kernel I/O.
- `docs/studio-http-access.md` — запуск, safety profile, статусы, приёмка, ограничения.
- Этот файл — сохранённое описание обычного PR.

Проверки в среде разработки:

| Проверка | Результат |
| --- | --- |
| Новые firewall/SSH/protocol/UFW tests | 31 passed, включая 5 настоящего UFW; 0 skipped при заданном verified package |
| Existing network diagnostic | 16 passed |
| Existing installer/backup/restore | 57 passed |
| Existing VPS audit | 11 passed |
| npm test | 152 passed |
| npm run test:integration | 57 passed, настоящая SQLite |
| npm run typecheck | passed |
| npm run lint | passed |
| Python AST / YAML parse / git diff --check | passed |
| GitHub CI x64/ARM64 и Backend CI на итоговом SHA | Требует подтверждения GitHub; API из среды возвращает Forbidden |
| Реальный VPS / check / apply | Не запускались |

Ограничения: поддержан только аудированный исходник Ubuntu 24.04 UFW 0.36.2-6;
обновлённые версии/сложная фильтрация требуют отдельного аудита, без downgrade,
удаления цепочек VPN или переключения backend. Один UFW allow создаёт IPv4 и IPv6
правила TCP/3000. UFW не даёт общей транзакции для файлов/обоих семейств. Вне-VPS
NAT/firewall провайдера не контролируются. Любое изменение firewall несёт риск
существующим соединениям. HTTP — только для вымышленных технических данных до HTTPS.

Функциональный код Studio, SQLite, бронирования, существующие workflows, установщик,
VPS Manager и VPN не изменены. Реальных сетевых операций на VPS не было.

Не выполнять merge автоматически. До подтверждённого PR CI задача не объявляется
полностью завершённой. После отдельной приёмки владелец разрешает запуск check/apply.
