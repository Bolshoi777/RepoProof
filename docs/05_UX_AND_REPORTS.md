# GUI/UX и структура отчётов

## 1. Принципы дизайна

Windows-приложение — спокойная инженерная утилита: компактный современный dark/light, понятная иерархия статусов, минимум кликов от URL до статического анализа, подробности по требованию. Не имитировать «крутой ИИ» анимациями.

## 2. Экран A — Welcome/Inspect

Компоненты: URL input, Browse Folder, Inspect button, recent runs (с SHA и verdict), status worker `Ready / Inspect-only / Unsafe unavailable`, link to documentation. При первом запуске заранее объяснить, что Inspect не исполняет код, а Verify требует отдельной изолированной среды.

## 3. Экран B — Plan Review

Список обнаруженных шагов: source README line link, полный command text, interpreted phase, expected network, options, confidence in extraction. Пометить неразрешённые env placeholders. Кнопки: `Inspect only`, `Approve verification`, `Cancel`. Если хотя бы один security gate недоступен, Verify заблокирован.

## 4. Экран C — Running

Сверху `Install / Launch / Behavior` с реальными состояниями; снизу логи шага с live streaming, duration, current command, Abort. Кнопка Cancel активна всегда. Никаких фиктивных процентов без измеримого total.

## 5. Экран D — Results

Выводить в порядке: (1) вердикт, (2) что именно проверено, (3) first verified failure, (4) доказательства, (5) ограничения, (6) техническая информация. Вкладки `Overview`, `Steps`, `Evidence`, `Environment`, `Suggestions`.

### Пример честного summary

```text
Result: BEHAVIOR_FAIL
Repository: owner/project@abc123...
Verified: checkout PASS, deps PASS, process started PASS
Not verified: GET /health expected 200; actual 404
Evidence: run-42/steps/verify-health.json, stdout.log (sanitized)
Confidence: deterministic observation, no inferred root cause
```

## 6. Отчёт HTML

Должен работать при двойном клике по `report.html` без сети. Жёсткая типизация всех входных данных; escapes не только stdout, но и названий репозиториев, путей, commit messages и error strings. Нет загрузки CSS/JS со сторонних CDN. Максимальный объём stdout ограничен, большие logs — отдельные файлы. Импорт чужого отчёта не выполняет JS.

## 7. Доступность и качество

- Tab navigation, aria descriptions для интерактивных элементов.
- Цвет дублируется текстом/icons; не полагаться только на зелёный/красный.
- High DPI 125–200%, ресайз окна, корректное обрезание длинных commit SHA и путей.
- Внятное error UI при Docker/VM missing: `Execution is unavailable. You can still inspect repositories.`
- Для каждого status есть tooltip: что доказано и что не доказано.

## 8. Демо для релиза

Записать настоящее 15–30 секунд видео: вставить URL контролируемого demo repo, Inspect, согласование, запуск, статус `BEHAVIOR_FAIL` при 404, переход к доказательствам. Не подделывать результаты визуально. Отдельно показать успешный `VERIFIED` на другой реальной фикстуре.
