# Fix booking confirmation on HTTP-IP and require browser checks for releases

На HTTP-IP браузер не предоставляет secure-context-only `crypto.randomUUID()`.
Клиент вызывал его до POST и показывал общий текст о неподтверждённом результате.
Сбой воспроизведён до исправления в настоящем Chromium на production SERVER build:
isSecureContext=false, randomUUID=undefined, getRandomValues=function, POST=0,
bookings/events=0 **в отдельной тестовой SQLite**, сообщение совпадает с обращением.

Это не утверждение об исторической заявке на VPS: production SQLite/версия не
читались, исход конкретной прежней операции остаётся неизвестным. Заявка могла
сохраниться при другом сценарии — потере HTTP-ответа после COMMIT.

Исправление: UUID v4 через CSPRNG getRandomValues при отсутствии native randomUUID.
Без слабого random, новых зависимостей и изменения SQL/API/business rules. Ошибка
подготовки ID до POST теперь отличима от неопределённого HTTP-результата. Старый
неподтверждённый ID не теряется при ошибке создания нового номера. Повторы одной
заявки сохраняют ID; подтверждение по-прежнему требует 201 и совпавший результат.

Release workflow x64/ARM64 теперь обязательно проверяет SHA256 и запускает **Node
и Next из распакованного native package** с новой изолированной SQLite. Полный
browser suite desktop/mobile выполняется в localhost и в настоящем небезопасном
HTTP context. Проверка явно требует отсутствия randomUUID; crypto не подделывается.
Весь трафик TEST-NET направляется только к loopback, без связи с VPS/интернет-сайтом.
Package publication и прежняя systemd/rollback приёмка остаются после browser gate.
Нет continue-on-error, optional gate или ослабления прежних тестов.

Реальный POST/COMMIT с потерянным ответом проверяется до abort: 201, ID и confirmed
в тестовой SQLite. После повтора — тот же ID, одна бронь, одно событие. Также
сохранены проверки пересечений, конкуренции, двойного клика, 400/409/429/503,
восстановления, reload/занятости, пяти экранов и mobile/desktop widths 320–1440.

Проверки разработки:

| Проверка | Результат |
| --- | --- |
| Unit (включая CSPRNG, подготовку ID, сохранённый результат/потерю ответа, loopback proxy) | 161 tests |
| Real SQLite integration | 57 passed |
| Real API HTTP | 18 сценариев passed |
| Health/recovery + persistent failure negative control | passed |
| SERVER browser из production build | 40 passed: 20 localhost + 20 insecure HTTP |
| Browser из Ubuntu 24.04 x64/Node 24.12.0 fixture-пакета | 40 passed, свежая SQLite для каждого origin |
| Static DEMO E2E | 26 passed |
| Installer/backup/restore unit | 59 passed, включая release-gate contract |
| Existing diagnostic/firewall/VPS-audit | 16 / 50 / 11 passed |
| TypeScript / lint | passed |
| SERVER build / Node DEMO / static DEMO / export audit / isolation | passed |
| Ubuntu 24.04 x64 native package build | passed; локальный fixture, не опубликован |
| ARM64 local validation | Проверяется отдельно; native GitHub CI ещё не подтверждён |
| Final-SHA GitHub CI x64/ARM64 | Не подтверждён: API из среды ограничен |

Главные файлы: `src/lib/request-id.ts`, `server-booking-service.ts` и unit tests;
`scripts/verify-server-ui.mjs`, тестовый `scripts/lib/insecure-browser-proxy.mjs`,
`playwright.server.config.ts`, `e2e-server/booking.spec.ts`, npm script;
`.github/workflows/installer-package.yml` и `tests/installer/test_release_browser_gate.py`.
Инструкция/доказательства: `docs/booking-confirmation-recovery.md`; ссылки добавлены
в существующие client-flow и installer docs.

Ограничения: HTTP только для вымышленных технических данных до HTTPS. ID хранится
в памяти вкладки и теряется при reload, как прежде; автоматического решения для
исторической неопределённой операции нет. Надёжность SQLite и production origin
policy не ослаблены. Локальные package fixtures имеют отдельный тестовый version
marker; они не объявляются готовым опубликованным релизом. Native ARM64/systemd CI
и успешность GitHub CI нельзя заменять результатами эмуляции/локальных тестов.

Не было deploy, SSH на VPS, чтения/изменения реальных записей, создания тестовых броней
на VPS, изменений VPN/firewall/SSH/других приложений. Новый production diagnostic API
не добавлен; отдельный DB workflow для воспроизведения client-side сбоя не потребовался.
Отдельный обычный PR от main после PR №16. Не выполнять merge автоматически.
