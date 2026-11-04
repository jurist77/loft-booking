# feat: installer, encrypted backups and explicit restore for Studio 19.25 (2.5.2)

Готовое обновлённое описание для PR №12. Содержимое ветки отправлено в существующий draft PR; автоматическое редактирование его title/body пока блокирует Forbidden от api.github.com в cloud runtime. Merge и реальное развёртывание не выполнялись.

Установка и обновление Studio 19.25 управляются вручную через Actions с одним IP. Проверенный immutable main SHA собирается off-VPS для Ubuntu 24.04 x64/ARM64; данные SQLite/photos/settings сохраняются отдельно от кода. Исправный same-SHA запуск ничего не переустанавливает и не перезапускает.

Перед update обязательны согласованный SQLite Backup API snapshot, GPG AES-256, private Release upload и обратная проверка hash. Без копии миграции не начинаются. Daily 03:15 Москва делает максимум две попытки, сохраняет 7 успешных дней; completed pre-update ограничены тремя, незавершённые закреплены. Очистка удаляет только собственные Releases/assets/tags. Restore: сначала list, затем точный tag и `RESTORE STUDIO 19.25`, decrypt/integrity/schema/version checks, сохранение текущего DATA и проверенный запуск. Внешние операции в тестах mock.

Нужны Secrets `STUDIO_SSH_PASSWORD`, `STUDIO_BACKUP_TOKEN`, `STUDIO_BACKUP_PASSPHRASE` (>=32), `STUDIO_SSH_KNOWN_HOSTS`; Variables `STUDIO_BACKUP_REPOSITORY`, `STUDIO_BACKUP_SERVER_IP`. Отдельный initialized private backup repo; fine-grained token только на него с ContentsRW + MetadataRead. Не включать immutable Releases/защиту служебных тегов, запрещающую ротацию. Основной GITHUB_TOKEN не используется для cross-repo хранения. Значения Secrets не передаются в чат/PR.

Root создаёт только собственного непривилегированного пользователя, каталоги, релизы и unit; запускает свои sandbox CLI и управляет только Studio. VPN/proxy/firewall/DNS/sshd не меняются. Hostkey verification отключена только Install по решению владельца: есть риск MITM/root-password theft. Backup/restore требуют trusted known_hosts. Временный `http://IP:PORT` — **только вымышленные контакты**, без HTTPS. Внутренние health/acceptance и внешняя reachability выводятся раздельно.

Локально: 41 installer tests, 152 app unit, 57 real SQLite integration, 18 групп API HTTP; health recovery/negative control, 20 SERVER + 26 DEMO E2E, typecheck/lint, SERVER/Node DEMO/static DEMO builds/audit и изолированный booking/conflict/restart acceptance прошли. Первый Node DEMO startup probe однажды дал INVALID_NODE_DEMO; полный повтор прошёл без ослабления теста, точная причина transient не установлена. Новый native run выявил TypeError в тестовом framing adapter; keyword исправлен, добавлен regression на настоящем stream. Требуется успешный повтор текущего SHA в Checks; старые зелёные runs другой редакции не считаются доказательством.

На настоящих VPS/SSH и рабочем backup repo ничего не запускалось. Не проверены реальные ресурсы/VPN peaks/reboot/публичный маршрут/права и квоты backup repo. Отказ после несовместимой committed migration оставляет сайт остановленным, не делает destructive DB rollback. Локальные recovery/release/checkpoint каталоги требуют отдельной политики очистки. Schedule/email GitHub не дают SLA.

Native CI дополнительно выявил остановку snapshot перед update: readonly проверка временного SQLite backup оставляла orphan partial WAL/SHM. Причина воспроизведена на реальной SQLite; verifier собственного temporary output исправлен, production source WAL/FULL не ослаблены, integration regression проверяет отсутствие orphan files. Итог native CI должен подтверждать именно последнюю редакцию.

Полные файлы, матрица требований, тесты и оставшиеся ограничения: `docs/acceptance/v2.5.2/README.md`. Пошаговая настройка, Install/Daily/Restore и recovery: `docs/universal-installer.md`.
