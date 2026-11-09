# Проверка DNS для HTTPS

Общий `DNS_LOOKUP_FAILED` заменён контекстными кодами, например `DNS_GOOGLE_HOST_CAA_SERVFAIL`, `DNS_CLOUDFLARE_HOST_A_HTTP_503` или `DNS_GOOGLE_HOST_A_TIMEOUT`. Таблица в GitHub Summary показывает резолвер, тип записи, уровень CAA, номер попытки, HTTP/DNS status, форму Answer и итог. Адреса, hostname, URL, содержимое ответов и ошибки с секретами не печатаются.

Сбой исходного запуска 42554940582 не содержит детальной телеметрии. При повторении на GitHub runner Google вернул HTTP 200 и DNS Status 2 для CAA hostname; это SERVFAIL, а не отсутствие записи. Оба A были получены; AAAA отсутствовал корректно (NOERROR без Answer). Cloudflare CAA вернул NOERROR без Answer. Это объясняет воспроизведённый отказ, но не доказывает его внутреннюю причину у Google/DuckDNS или точное содержимое исторического ответа.

## Семантика

- `RCODE_0` + `MISSING` / `EMPTY` = корректный NODATA. Пустой AAAA разрешён, если IPv6 не ожидается. Пустой CAA означает переход к родительскому уровню.
- `RCODE_2` / `SERVFAIL` = резолвер не смог подтвердить ответ. Нельзя пропускать его и подменять ответом другого резолвера или родительским CAA.
- NXDOMAIN, REFUSED, HTTP 403/404, TLS error, неверный JSON, null/non-array Answer, CNAME/неожиданные записи, неподтверждённый Question и truncated response блокируют проверку.
- Все DoH-запросы явно используют `cd=false` и `do=true`. Ответ с отключённой/некорректной меткой CD отклоняется (`DNSSEC_CHECKING_DISABLED`). AD=true не требуется для корректно неподписанных зон; DNSSEC SERVFAIL не обходится.
- IP каждого резолвера должен точно совпасть с ожидаемыми A/AAAA. Успех одного недостаточен.
- CAA проверяется независимо у Google и Cloudflare: hostname → каждый родительский label → TLD → root, до первого непустого применимого RRset. Например, `booking.space.example.co.uk` → `space.example.co.uk` → `example.co.uk` → `co.uk` → `uk` → `.`; `studio1925.dynv6.net` → `dynv6.net` → `net` → `.`. Список строится из проверенного FQDN, без списка провайдеров или public-suffix shortcut. Ограничения issuer/account и неизвестные критические теги не игнорируются.
- Для SERVFAIL, HTTP 429/5xx и временных транспортных ошибок — максимум две попытки обычно с паузой 1 секунда. Retry-After до 5 секунд соблюдается; более длинный/невалидный Retry-After прекращает повторы вместо преждевременного запроса. Постоянная ошибка остаётся ошибкой. После 60 секунд новые запросы прекращаются; текущий ограничен отдельным deadline 10 секунд (общий предел около 70 секунд).

## Повторный публичный DNS-only check

Workflow **Check Studio HTTPS** → Run workflow: `hostname`, ожидаемый `server_ip`, необязательный `additional_ip` другого семейства. В коде нет адреса конкретного VPS. Этот режим читает только публичный DNS: не использует SSH, Secrets, VPS, ACME или apply. Для проверки PR через CLI доступен запуск существующего workflow по ID/ref ветки:

```bash
gh workflow run https-checks.yml --ref <reviewed-branch> \
  -f hostname=<registered-public-fqdn> -f server_ip=<expected-public-IP> -f additional_ip=
```

`REQUIRED` — запрос участвует в решении. `DIAGNOSTIC` — дополнительный запрос к неиспользованному предку CAA для анализа; он не заменяет ближайший CAA и не исправляет отказ обязательного lookup. Красный live check при зелёных offline тестах означает, что DNS ещё не готов.

## Полный Manage check

`Manage Studio HTTPS` остаётся main-only. После merge владельцем и зелёных main checks запускать только `mode=check`, с пустым confirmation. Исправленный Summary станет доступен в полном workflow после merge. Не выполнять apply, пока оба резолвера и CAA не подтверждены. Если Google продолжает SERVFAIL, ожидать восстановления/уточнять проблему у DNS-провайдера; этот PR не меняет DNS и не объявляет его исправным по одному Cloudflare.

## Новый hostname dynv6: безопасный повтор после приёмки PR

После ручного merge владельцем и зелёных проверок актуального main:

1. GitHub → Actions → **Manage Studio HTTPS** → Run workflow, branch `main`.
2. `server_ip`: `2.27.207.130`.
3. `hostname`: `studio1925.dynv6.net`.
4. `additional_ip`: пусто, поскольку IPv6 не используется и AAAA должен отсутствовать.
5. `mode`: **check**; `confirmation`: пусто.

Это только проверка. В этом PR Manage не запускается; ни check, ни успешный DNS-only результат не разрешают apply автоматически. Изменение существующего committed HTTPS hostname по-прежнему блокируется `HTTPS_HOSTNAME_CHANGE_REQUIRES_REVIEW`: общая поддержка FQDN не переносит уже установленный сертификат молча.

Внешний `SERVFAIL`, несовпадение A/AAAA, ошибка транспорта или неверный авторитетный ответ — отдельная проблема DNS. Зелёные offline тесты программы её не исправляют. После устранения внешнего сбоя требуется свежий DNS-only check; нельзя удалять второй резолвер, считать SERVFAIL пустым CAA или отключать DNSSEC.
