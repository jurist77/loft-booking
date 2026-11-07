# Diagnose Studio network

Ручная read-only диагностика Studio 19.25. Разработана без подключения к реальному VPS; workflow не запускался на сервере. Никаких попыток ремонта, установки или перезапуска.

## Запуск после приёмки PR

После согласованного владельцем merge workflow появится в main: Actions → **Diagnose Studio network** → Run workflow → branch **main** → единственное обязательное поле **server_ip**. Вводите голый IPv4/IPv6 без URL/порта/скобок. Используется существующий Secret **STUDIO_SSH_PASSWORD**, SSH **root:22**. Пароль вводить в workflow/chat/issue не требуется. Ни backup-токен, ни ключ шифрования не нужны.

Установка sshpass при необходимости происходит только на disposable GitHub runner. На VPS никакие пакеты не устанавливаются. Runtime — существующий Python3/стандартные Linux-инструменты; отсутствующий инструмент отмечается как missing, не устанавливается.

Используется существующий Studio SSH helper: пароль только в окружении sshpass, `-F /dev/null`, `StrictHostKeyChecking=no`, known-hosts `/dev/null`, `UpdateHostKeys=no`. Глобальные SSH-файлы не меняются. **Согласованный риск: MITM/ошибочный IP могут перехватить root-пароль и подменить результаты.** Проверка формата/фильтрация отчёта не аутентифицируют сервер.

Сам диагностический workflow имеет только workflow_dispatch, guard main, contents:read, таймаут 5 минут. Он не запускается по push/PR/расписанию. Отдельный **Check Studio network diagnostic** запускает только тесты на фикстурах, без SSH/VPS/реального firewall.

## Что читается

| Проверка | Что попадает в отчёт |
| --- | --- |
| `systemctl show studio1925.service` с четырьмя выбранными properties | LoadState/ActiveState/SubState из allowlist; MainPID используется только для сопоставления listener и не публикуется |
| `ss -H -4/-6 -lntp` | Только bind-адреса TCP/3000 и listener MainPID Studio (включая возможный 3100 вместо 3000); нет чужих портов, PID, имён процессов или peer-адресов |
| Локальные `GET /api/health` на 127.0.0.1:3000 и [::1]:3000 | HTTP-код, совпадение с ожидаемым `{"status":"ok"}`, безопасный код ошибки |
| Такой же GET на введённый IP:3000 с GitHub runner | Отдельный внешний результат; одна попытка, без контактов, body/headers/Location в отчёт не попадают, redirects не следуются |
| `ufw status verbose` | Active/inactive, default incoming policy, счётчики строк TCP/3000; без source CIDR/comments/других правил |
| `nft -j list ruleset` | Policy базовых input chains ip/ip6/inet, счётчики прямых literal tcp dport3000 verdict, признак indirect jumps; без имён таблиц/цепочек, sets, IP и comments |
| `iptables-save -t filter`, `ip6tables-save -t filter` | INPUT policy, прямые tcp dport3000 verdict, indirect jumps; без raw rules/counters/IP/comments |

Raw stdout firewall/ss хранится только в памяти и не публикуется/не загружается в artifacts. Лимит вывода каждого инструмента 2MiB, deadline 5 секунд; при превышении parsing прекращается и выводится output_limit/timeout. При таймауте завершается только собственный процесс команды чтения, не службы. HTTP имеет общий deadline 5 секунд и предел 512 байт; передаются только GET и Connection:close. stdout/stderr SSH/команд, конфигурации VPN/SSH, environment, journal и DB-файлы не выводятся и не читаются для отчёта.

Python probe передаётся через private TemporaryFile только на runner; на VPS выполняется `python3 -I -B -S -` без сохранения скрипта, site customizations и bytecode. Probe не использует installer lock/state, не пишет конфигурацию/данные, не вызывает installer или SQL. Как и любой GET, запрос может быть отражён существующим access log/счётчиком; существующий health endpoint выполняет свою штатную проверку, его реализация не меняется.

## Как понимать результат

Summary содержит очищенный JSON и фиксированный текст вероятной причины. **Зелёный diagnostic workflow означает, что отчёт сформирован, а не что приложение исправно.** При SSH/protocol error или неверном input/Secret job завершается ошибкой с безопасным кодом. HTTP503, отказ TCP или firewall observation остаются диагностическими данными, не запускают ремонт. status=partial означает отсутствующие/недоступные инструменты или неполные данные.

Возможные выводы: служба inactive/failed; на 3000 нет listener; Studio использует другой порт; порт принадлежит другому процессу; loopback-only bind; неподходящее семейство IP/конкретный bind; локальный health не подтверждён; вероятная фильтрация хоста; неопределённый внешний путь. Внешний ожидаемый health от другого процесса или при неизвестном ownership не считается подтверждением Studio.

Важные ограничения:

- Один успешный GET не проверяет пять экранов, бронирование, весь интернет или все клиентские сети.
- IPv6 wildcard `::` сам по себе не доказывает IPv4 dual-stack. Loopback health может не работать при bind только на конкретный адрес; это не доказательство отказа приложения.
- Сводка firewall — не полноценный evaluator: порядок правил, sets/maps, ranges, negations, jumps/conntrack/NAT и несколько backend layers могут менять результат. UFW inactive не доказывает отсутствие других firewall. Нельзя считать отсутствие прямой literal dport3000 записи разрешением трафика.
- Если локально работает, а с runner нет, возможны firewall хоста/провайдера, NAT, routing, ошибочный IP или egress runner. Точный слой не заявляется без доказательств; автоматического allow/open-port нет.
- Наблюдения не атомарны. Параллельное обновление/авторестарт Studio может дать переходное состояние; диагностика не блокирует/не изменяет установку.

Не меняются firewall/UFW/nftables/iptables rules, SSH, systemd units/enablement, VPN/Xray/3X-UI, reverse proxy, DNS, NAT, маршрутизация и чужие приложения. Никаких start/stop/restart/reload, отправки контактов, публикации сайта или установки на VPS.

## Тестирование и review

`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/diagnostics -v` — 16 tests: allowlist чтения, редактирование чувствительных полей, IPv4/IPv6/loopback/ownership/другой порт, firewall summaries/unknown tools, malicious remote JSON, input validation, timeout/лимит вывода/cleanup и настоящие GET на собственную локальную HTTP-фикстуру (без redirect). Реальный probe.collect на VPS не выполняется. Также сохраняются существующие installer tests.

PR и окончательный SHA/результаты приведены в итоговом сообщении. Если GitHub API в cloud блокируется, ветка/описание PR доступны для review, но создание PR и CI не объявляются успешными без подтверждения.
