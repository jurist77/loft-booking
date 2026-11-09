# Проверка DNS для HTTPS

Общий `DNS_LOOKUP_FAILED` заменён контекстными кодами, например `DNS_GOOGLE_HOST_CAA_SERVFAIL`, `DNS_CLOUDFLARE_HOST_A_HTTP_503` или `DNS_GOOGLE_HOST_A_TIMEOUT`. Таблица в GitHub Summary показывает резолвер, тип записи, уровень CAA, номер попытки, HTTP/DNS status, форму Answer и итог. Адреса, hostname, URL, содержимое ответов и ошибки с секретами не печатаются.

Сбой исходного запуска 42554940582 не содержит детальной телеметрии. При повторении на GitHub runner Google вернул HTTP 200 и DNS Status 2 для CAA hostname; это SERVFAIL, а не отсутствие записи. Оба A были получены; AAAA отсутствовал корректно (NOERROR без Answer). Cloudflare CAA вернул NOERROR без Answer. Это объясняет воспроизведённый отказ, но не доказывает его внутреннюю причину у Google/DuckDNS или точное содержимое исторического ответа.

## Семантика

- `RCODE_0` + `MISSING` / `EMPTY` = корректный NODATA. Пустой AAAA разрешён, если IPv6 не ожидается. Пустой CAA означает переход к родительскому уровню.
- `RCODE_2` / `SERVFAIL` = резолвер не смог подтвердить ответ. Нельзя пропускать его и подменять ответом другого резолвера или родительским CAA.
- NXDOMAIN, REFUSED, HTTP 403/404, TLS error, неверный JSON, null/non-array Answer, CNAME/неожиданные записи, неподтверждённый Question и truncated response блокируют проверку.
- IP каждого резолвера должен точно совпасть с ожидаемыми A/AAAA. Успех одного недостаточен.
- CAA проверяется от hostname к ближайшему применимому RRset, затем при отсутствии записей — DuckDNS / TLD / root. Ограничения issuer/account и неизвестные критические теги не игнорируются.
- Для SERVFAIL, HTTP 429/5xx и временных транспортных ошибок — максимум две попытки обычно с паузой 1 секунда. Retry-After до 5 секунд соблюдается; более длинный/невалидный Retry-After прекращает повторы вместо преждевременного запроса. Постоянная ошибка остаётся ошибкой. После 60 секунд новые запросы прекращаются; текущий ограничен отдельным deadline 10 секунд (общий предел около 70 секунд).

## Повторный публичный DNS-only check

Workflow **Check Studio HTTPS** → Run workflow: `hostname`, ожидаемый `server_ip`, необязательный `additional_ip` другого семейства. В коде нет адреса конкретного VPS. Этот режим читает только публичный DNS: не использует SSH, Secrets, VPS, ACME или apply. Для проверки PR через CLI доступен запуск существующего workflow по ID/ref ветки:

```bash
gh workflow run https-checks.yml --ref <reviewed-branch> \
  -f hostname=<hostname.duckdns.org> -f server_ip=<expected-public-IP> -f additional_ip=
```

`REQUIRED` — запрос участвует в решении. `DIAGNOSTIC` — дополнительный запрос к неиспользованному предку CAA для анализа; он не заменяет ближайший CAA и не исправляет отказ обязательного lookup. Красный live check при зелёных offline тестах означает, что DNS ещё не готов.

## Полный Manage check

`Manage Studio HTTPS` остаётся main-only. После merge владельцем и зелёных main checks запускать только `mode=check`, с пустым confirmation. Исправленный Summary станет доступен в полном workflow после merge. Не выполнять apply, пока оба резолвера и CAA не подтверждены. Если Google продолжает SERVFAIL, ожидать восстановления/уточнять проблему у DNS-провайдера; этот PR не меняет DNS и не объявляет его исправным по одному Cloudflare.
