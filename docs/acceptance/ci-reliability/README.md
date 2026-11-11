# Восстановление CI и штатного допуска установки

## Причина → изменение → проверка

| Наблюдение | Вывод и изменение | Проверка |
|---|---|---|
| Backend run 43034378912 attempt 3 упал на `Install browser for real SERVER and DEMO client journeys`; Installer run 43034379152 attempt 2 — на `Install browser on the disposable release runner` в обоих native jobs | Сбой подготовки браузерного окружения, до браузерной приёмки/публикации; это не ошибка SQLite или установка на VPS | Проверены REST run/attempt/job metadata; все следующие обязательные тесты сохранены |
| Workflows, verify-main.py, package.json и package-lock.json между успешным a6bfd88 и merge 763878a идентичны; backend/installer workflow не менялись и в PR28–29 относительно 1dfad0b | PR28–29 не добавляли неработающую зависимость. По предоставленным владельцем журналам причиной был DNS на загрузке системных browser dependencies. Точный недоступный DNS/mirror узел не установлен: полные job logs недоступны из среды разработки из-за политики storage-domain | Git diff + совпадающие failing step IDs. Не приписывать сбой смене Ubuntu без image-version из журнала |
| Backend использовал ubuntu-latest; Installer уже использовал ubuntu-24.04 / ubuntu-24.04-arm и тоже упал | Плавающий major Ubuntu — отдельный риск, не общая причина этих трёх отказов | Backend закреплён на Ubuntu 24.04 и Node 24.12.0, как native package CI |
| `playwright install --with-deps chromium` вызывает APT для Chromium runtime и `tools`: Xvfb, дополнительных азиатских/прочих font packs | Для наших headless-тестов со своим executablePath не нужны Xvfb и второй headless-shell. Не выполнять широкую APT-установку при каждом job | Новый общий CI-only helper скачивает full Chromium выбранного npm lockfile и выполняет реальный headless launch/DOM/click/render. Полные e2e остаются обязательными |
| Официальные runner-images Ubuntu 24.04 x64/ARM64 содержат gnupg2 и libnss3-tools | Безусловный apt update/install этих уже установленных инструментов — избыточная сеть | Проверить gpg/certutil; только при отсутствии установить ровно необходимый инструмент, с bounded Acquire::Retries и строгим APT update Error-Mode=any |
| verify-main отверг main после красных обязательных CI | Штатная защита, не дефект; её не обходить | Дополнительные тесты всех четырёх проверок: missing/failure/skipped/cancelled/timed_out/in_progress не пропускаются; старый успешный run не перекрывает новый отказ |

Ссылки на исходные запуски: [Backend](https://github.com/jurist77/loft-booking/actions/runs/43034378912), [Installer](https://github.com/jurist77/loft-booking/actions/runs/43034379152). Прежний успешный [Backend](https://github.com/jurist77/loft-booking/actions/runs/43030064736) и [Installer x64/ARM64](https://github.com/jurist77/loft-booking/actions/runs/43030064821) относятся к a6bfd88.

## Минимальная схема

Никаких новых services, контейнеров, зеркал APT, browser caches, build repositories или deployment managers. Browser helper выполняется только на disposable CI runner; не включается packager в SERVER root filesystem. Он не вызывает sudo/APT, не меняет DNS/TLS и не пропускает host validation. Playwright из локального node_modules после npm ci сохраняет штатные ограниченные download retries/mirrors и TLS verification; connect timeout 60 секунд. Постоянный отказ CDN или реальное отсутствие runtime libraries означает failed job, не успешный skip. Поэтому это уменьшение ненужной сетевой зависимости, не обещание работы без интернета.

Системные библиотеки не маскируются: реальный Chromium smoke и неизменённые SERVER/DEMO/HTTPS браузерные suites обязаны пройти на actual runner. Внешний major OS не плавает, но weekly rebuild hosted image целиком GitHub runner label не закрепляет; исчезновение нужной библиотеки будет обнаружено тестом. Официальные списки инструментов при анализе: runner-images Ubuntu2404-Readme / Ubuntu2404-Arm64-Readme, образы 20261101.360.1 / 20261101.172.1. Это не доказательство версии runner из неуспешного запуска.

## Restore и старые релизы

Reusable installer-package может собирать старый выбранный source_sha. CI-helper нельзя брать только из такого checkout: старый релиз его ещё не содержит. Переиспользован уже существующий checkout `github.workflow_sha` в `.studio-verified-control`; он перемещён после упаковки и до browser setup. Helper берётся из reviewed workflow revision, но запускается в selected app cwd и использует его lockfile/Playwright. App archive не меняется. Копирование current lifecycle controls остаётся после проверки browser journeys из точного артефакта. Checkout не перенесён перед typecheck/build/package: это исключает попадание второго исходного дерева в сборку/артефакт. Дополнительный checkout не добавлен.

Сохранены настоящие Caddy validation, TLS/Origin, browser/SQLite, systemd install/repeat/update, encrypted backup/restore, recovery и schema-aware rollback. Долгая проверка сбоев/тайм-аутов systemd не удалена ради скорости: она проверяет восстановление. Установщик, gate, receiver, SQLite, networking и приложение не переработаны.

## Штатная разблокировка после приёмки

PR CI проверяет candidate/merge SHA и не разрешает установку вместо main. После merge владельцем новый **main SHA** должен получить успешные push runs:

1. Check backend foundation.
2. Check read-only VPS audit tool.
3. Check universal installer — x64 и ARM64.
4. Check Studio HTTPS — x64/ARM64 там, где предусмотрено.

Только после этого `verify-main.py` штатно разрешит validate job `Install Studio 19.25` для того же main SHA. Проверяются event=push, точный commit и completed/success самого нового run каждого workflow. Pending/skipped/cancelled/failure не принимаются. PR не выполняет merge или реальную установку, поэтому до merge и наблюдения этих четырёх main runs нельзя объявлять текущую main установку разблокированной.

После четырёх зелёных main runs владелец сможет отдельно запустить существующий Install Studio 19.25. В этом задании этот workflow не запускается. Успешный CI не является доказательством успешной установки/HTTPS на настоящем VPS.

## Проверки изменения

- Isolated shell fixtures: обе архитектуры, отказ неподдерживаемой OS/CPU до download, DNS/download failure с nonzero и без smoke, browser/runtime failure с nonzero, locked full browser, отсутствие APT/validation bypass в helper.
- Workflow contracts: фиксированная платформа, все прежние тесты, порядок build/archive → current controls → browser → copy lifecycle → Caddy/systemd/publish, совместимость старого source_sha.
- Exact main gate: все четыре обязательных workflow и все недопустимые состояния, exact SHA и push.
- Installer unit и неизменённые full Backend/Installer/HTTPS/HTTP/audit CI на итоговом SHA. Ссылки/окончательные статусы приложены в PR; основной код приложения и VPS не изменены.
