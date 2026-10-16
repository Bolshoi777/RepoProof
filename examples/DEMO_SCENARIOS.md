# Демо-сценарии, которые нужно реализовать тестовыми фикстурами

## 1. `healthy-http`
Node.js HTTP сервер: README install/launch, `/health` 200 + body `ok`. Expected `VERIFIED`. Видео показывает статус и доказательство.

## 2. `misleading-http`
Тот же успешный процесс запуска, но `/health` отвечает 404. Expected `BEHAVIOR_FAIL`, этап `launch` PASS. Это главное маркетинговое демо.

## 3. `broken-readme-command`
Python package с рабочей CLI, но документация указывает старое имя `old_cli`. RepoProof должен доказать расхождение и получить `DOCS_FAIL` только если правило из ТЗ выполняется; иначе `LAUNCH_FAIL` с диагностической гипотезой.

## 4. `no-oracle`
Python CLI печатает `started` и возвращает 0, но отсутствует функциональная проверка. Expected `PARTIAL`, никогда `VERIFIED`.

## 5. `no-worker`
RepoProof на хосте без VM: `inspect` работает; `verify` даёт `BLOCKED_SECURITY` с исправимой рекомендацией. Нельзя автоматически выполнить на хосте.

Все сценарии должны содержать исходные файлы fixture-проектов, seed/environment pin, автоматический expected verdict и real evidence. В этом комплекте **только сценарии**, сами fixture apps ещё не реализованы.
