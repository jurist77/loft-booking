# Дополнительные nftables hooks: только диагностика

## Установленная причина и пределы выводов

В HTTPS check [43008885112](https://github.com/jurist77/loft-booking/actions/runs/43008885112) получен `HTTPS_UFW_ADDITIONAL_NFT_FILTERING`. Код запуска (`54ee8fd`) проверяет не только UFW/iptables: `firewall_plan()` → `nft_profile()` отказывает при дополнительных tables/families/hooks и других nft-объектах вне проверенной модели. Разрешённый UFW TCP/80 и Studio health=200 не доказывают безопасность всего пути. Отсутствующий allow TCP/443 — отдельный вопрос; добавление allow не устраняет неоднозначность другого hook.

В [диагностике 43011928306](https://github.com/jurist77/loft-booking/actions/runs/43011928306) прежний отчёт давал только числа, общую policy и `nat_or_other_hooks`. Он не связывал hook с TCP/22/80/443. Более того, тот же код ошибки в stock_shape() вызывают дополнительные set/map/counter/flowtable и другие объекты: одна строка ошибки не доказывает даже тип дополнительного слоя. Новый отчёт отдельно считает типы этих объектов без имён/содержимого. Xray/3X-UI — возможный источник, но наличие программы не доказывает авторство. Ядро nft не хранит надёжную запись «создавшая служба»; имена и комментарии произвольны.

Метаданные обоих запусков проверены через GitHub API. Полные журналы недоступны среде разработки из-за сетевой политики хранилища GitHub Actions. К VPS при разработке не подключались. Точный состав и воздействие дополнительных hooks остаются неподтверждёнными до нового расширенного read-only отчёта.

## Дополнение существующего workflow

Новый workflow или установщик не создаётся. **Diagnose Studio HTTPS readiness** получает `nft_hooks`. Прежний bounded reader читает те же `nft -j list ruleset`, `iptables-save`, `ip6tables-save` и состояние units. Снимки повторяются для обнаружения изменений. Нет установки пакетов, trace-правил, `nft monitor`, перезапусков, чтения VPN-конфигураций или прямых запросов к БД.

Для каждого base hook выводятся:

- Безопасный ID H01/H02, family/hook/type/priority/policy. Приоритеты сравниваются только в соответствующем семействе/стадии.
- `NFT_ONLY` либо `CHAIN_NAME_PRESENT`. Второй код — только соответствие имени цепочки/table iptables-снимку, не равенство правил и не ownership.
- Структурные признаки transparent proxy, NAT, marking/tracking, opaque xt/maps. Они видны и у UDP-only правил.
- Возможные effects для TCP/22/80/443: selectors, jumps/gotos, default drop, неизвестные выражения. Для ingress/prerouting/input рассматривается destination port; для output/postrouting/egress — source port ответа локального сервера. Forward и чужие families не объявляются безопасными.
- `VPN_NAME_HINT_ONLY`, наблюдение активного известного VPN unit, `creator: NOT_PROVEN`. Подсказки не дают права менять правила.

Адреса, интерфейсы, названия tables/chains, marks, NAT destinations, комментарии, PID, VPN-конфигурации, токены и raw stderr остаются вне отчёта. Runner проверяет точную схему и ограниченный словарь. Для ограниченной сводки максимум 32 hooks используется явный SSH JSON limit 64 KiB: полный отчёт может превышать прежние 10 KB. Общий SSH helper сохраняет прежний default 10 KB для installer/update/restore и отказывает при превышении любого выбранного лимита. SSH policy/команды/аутентификация не изменены; файлов и публичных raw-артефактов отчёта не создаётся.

`DROP_POSSIBLE`/`REJECT_POSSIBLE` — возможная фильтрация; `NAT_POSSIBLE`/`TPROXY_POSSIBLE` — изменение направления; `MARK_OR_TRACKING_POSSIBLE` — потенциальное влияние через routing/conntrack. `UNKNOWN_REVIEW_REQUIRED` требует разбора. `ACCEPT_OBSERVED` не означает доступность: поздний hook может отбросить пакет.

Пустой список effects означает только отсутствие обнаруженного эффекта в данном hook для рассмотренного TCP-направления, не доказательство глобальной доступности или разрешение apply. Анализ консервативен: возможные ветви после terminal verdict сохраняются, named sets/maps не угадываются. Side effects перед несовпадающим match сохраняются. Политики, routing, conntrack, upstream filtering и будущая неизменность rules этим анализом не доказываются.

`READ_FAILED`, `DATA_INVALID`, `LIMIT_EXCEEDED`, `SNAPSHOT_CHANGED` запрещают заключение о безопасности. Изменения счётчиков не считаются изменением правил. Проверки разрешения HTTPS apply не изменены.

## Отдельно: TLS residue IDENTITY_MISMATCH

`probe_tls_residue.py` атрибутирует одну историческую неудачную установку, а не определяет необходимость очистки нового VPS. Lookup `studio1925tls` выполняется до проверки TLS-каталогов. Отсутствие пользователя на чистом сервере давало тот же `IDENTITY_MISMATCH`, что и неверные shell/UID/group.

Добавлен `identity_detail`: `USER_MISSING`, `SYSTEM_UID_MISMATCH`, `SYSTEM_GID_MISMATCH`, `HOME_MISMATCH`, `SHELL_MISMATCH`, `PRIMARY_GROUP_MISMATCH`, `EXTRA_GROUP_MEMBERSHIP`, `UID_OR_GID_ALIAS` и другие ограниченные коды. UID/GID, фактические home/shell не выводятся. Условия исторического MATCH, fingerprints/dependencies и `preservation_required` сохранены.

В Summary `USER_MISSING` + отсутствие всех отслеживаемых TLS-путей поясняется как `TLS_USER_ABSENT_NO_TRACKED_OBJECTS_OBSERVED`. Это не доказательство остатков и не разрешение quarantine. Если объекты есть или identity не установлена — всё сохранять. Точный подслучай текущего VPS должен подтвердить новый отчёт; старого общего кода недостаточно.

## Действия владельца без терминала

1. После отдельной приёмки и merge этого PR открыть GitHub → Actions → **Diagnose Studio HTTPS readiness → Run workflow**.
2. Выбрать **main**, указать нужный `server_ip`. Режима apply здесь нет.
3. Передать ссылку на запуск. В Summary появятся `nft_hooks`, `identity_detail` и объяснение identity. Зелёный job означает получение отчёта, не готовность HTTPS.
4. До разбора не запускать HTTPS apply или quarantine из-за одного `IDENTITY_MISMATCH`.

Простейший безопасный путь: сохранить VPN и действующий HTTP Studio, определить конкретные hooks, затем выбрать решение. Если доказано отсутствие влияния на HTTPS/SSH и связанные маршруты, возможна следующая точечная поддержка именно проверенного случая с before/after proof; этот PR её не добавляет. Если TCP/443 перехватывается либо остаётся неопределённость — отдельное согласование с владельцем VPN или другой уже имеющийся совместимый VPS. Не удалять/переставлять цепочки, не отключать UFW/VPN. DNS-01 не исправляет перехват HTTPS-трафика. Открытие недостающего TCP/443 и Caddy допустимы позже, после доказанного пути и отдельного подтверждения.

## Проверки

Fixtures: дополнительные inet hooks, selectors 22/80/443, диапазоны/sets, drop policy, jumps/циклы, NAT/TPROXY/mark, UDP-only proxy, reply path, effects до false match, opaque выражения, ограничения/ошибки чтения, гонки, redaction/schema. Отдельные тесты различают identity-причины и отсутствие tracked TLS-объектов. Старые HTTPS/quarantine проверки сохранены. Диагностический CI работает на x64/ARM64; VPS автоматически не опрашивается.
