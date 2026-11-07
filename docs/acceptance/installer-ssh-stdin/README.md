# Исправление stdin установщика — 07.11.2026

Основа: main `bbb0effeecf52d646836f16d730a56f642a65f5a` после merge PR №12. Отдельная ветка: `fix/installer-ssh-stdin`; исправление предназначено для отдельного PR, не изменения PR №12.

## Подтверждённая причина

Реальный локальный Popen с прежним `Peer.call()` воспроизвёл `SSH_TIMEOUT_OR_TRANSPORT_FAILED` без сетевого подключения. `io.BytesIO.fileno()` выбрасывает `io.UnsupportedOperation`, наследующий OSError, до запуска SSH. Моки Popen скрывали эту проверку дескриптора.

Теперь Peer.call пишет только installer source в private anonymous TemporaryFile (0600), выполняет seek(0) и держит файл открытым до завершения execute/communicate. Пароль по-прежнему передаётся только через отдельное окружение sshpass, не через stdin, argv или файл. При ошибке поток закрывается. UnsupportedOperation получает отдельный безопасный код SSH_STREAM_UNSUPPORTED вместо сообщения о сбое транспорта.

Настоящий timeout-test дополнительно обнаружил незакрытые stdout/stderr pipes после wait. Они теперь закрываются в finally; caller-owned stdin и output_file не закрываются транспортом. Процесс по-прежнему завершается и reap выполняется существующим механизмом.

## Проверки

Команда: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/installer -p 'test_*.py' -v` — **57 passed**, включая 6 новых regressions с реальными локальными дочерними процессами:

| Проверка | Что проверяется |
| --- | --- |
| Первая info-команда | Реальный OS stdin/fileno, полный source и EOF, JSON-ответ |
| Daily / pre-update backup | Полный бинарный tar без обрезки и правильные purpose/hold |
| Restore | Info, pre-restore backup, encryption/readback в FakeStore, полный framed code/archive/bundle, hashes/receipt/confirmation |
| Ошибка процесса | Ошибка SSH не превращается в SUCCESS, source закрывается |
| Таймаут | Процесс завершён/reaped, source и Popen-owned pipes закрыты |
| Несовместимый локальный stream | Ошибка явно локальная, не SSH timeout |

Настоящий Popen не подменяется фиктивным результатом: spy вызывает оригинальный API ОС, а SSH argv заменяется на фиксированный Python receiver. Receiver читает/проверяет байты, но не исполняет installer/bootstrap. SSH/VPS/рабочий backup repo не используются; источник/SQLite/GPG/файлы локальные и тестовые. Архив установки содержит синтетические байты и не запускается.

CI x64/ARM64 использует существующий `.github/workflows/installer-package.yml`; новые tests автоматически входят в discover. После открытия PR должны пройти обе native jobs и Backend CI. Ссылки и фактический результат приводятся в итоговом сообщении; локальная Linux-проверка не подменяет native CI.

## Границы

Изменены только Peer.call, диагностика/cleanup SSH.execute, tests и этот отчёт. VPS Manager, клиентский путь, бизнес-правила, SQL-миграции, службы VPS, согласованная SSH-политика и архитектура не меняются. Реальная установка и merge не выполнялись.

Git HTTPS доступен; api.github.com в текущей cloud-среде возвращает Forbidden. Если это сохраняется при gh pr create, ветка/коммит и готовое [описание PR](PR.md) доступны для review, но PR и его CI нельзя объявлять созданными/проверенными. API-домен уже сохранён в draft настроек; для применения требуется действие владельца в настройках среды Review/Save→Publish. Результат фактической попытки создания PR указывается отдельно.
