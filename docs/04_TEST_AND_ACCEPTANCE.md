# Quality assurance: обязательные тесты и правила приёмки

## 1. Пирамида качества

- Unit: Markdown extraction, path normalization, plan validation, proof verdict state machine, redact, schema serialize/deserialize.
- Component: Inspector fixture repos, parser with line source, CLI output, report rendering.
- Integration: Worker attestation, local isolated app installation, HTTP readiness, cancel.
- E2E: Windows clean install + isolated run on independent sample repo.
- Security: отдельная лаборатория из `03_SANDBOX_SECURITY.md`.
- Regression: стабильные golden JSON, HTML sanitized snapshots, повторяемые root-cause cases.

## 2. Статусы и отрицательные случаи

| Case | Setup | Launch | Oracle | Итог |
|---|---|---|---|---|
| T01 | PASS | PASS | PASS | VERIFIED |
| T02 | PASS | PASS | FAIL | BEHAVIOR_FAIL |
| T03 | PASS | FAIL | NOT_RUN | LAUNCH_FAIL |
| T04 | FAIL | NOT_RUN | NOT_RUN | INSTALL_FAIL |
| T05 | PASS | PASS | ABSENT | PARTIAL |
| T06 | PASS | PASS | UNKNOWN_EXTERNAL | INCONCLUSIVE |
| T07 | NOT_RUN | NOT_RUN | NOT_RUN | BLOCKED_SECURITY |
| T08 | UNSUPPORTED | NOT_RUN | NOT_RUN | UNSUPPORTED |
| T09 | PASS | PASS | BROKEN_ORACLE_ENGINE | ERROR_INTERNAL |
| T10 | CANCELLED | NOT_RUN | NOT_RUN | CANCELLED |

Обязательно уточнить приоритет DOCS_FAIL над INSTALL_FAIL на известных ошибках инструкций: verdict должен иметь evidence и не строиться только по эвристикам.

## 3. Минимум 30 тестов

Полная таблица в `examples/fixture_matrix.csv`. Для каждого ID фиксируем: входные файлы, ожидаемую фазу, наблюдение, expected verdict, реализацию теста, лог запуска и last result.

Категории:
- Здоровый Python CLI с proof output.
- Здоровый Node CLI с proof output.
- HTTP API status and body.
- Неправильная команда README.
- Отсутствующая версия зависимости.
- Ошибка build/install hooks.
- `exit 0` при ложном выходе.
- HTTP порт открыт, маршрут 404.
- Timeout и cancellation.
- Отсутствующий token.
- Неоднозначный Markdown code block.
- Некорректная кодировка/очень длинный stdout.
- Попытки XSS/secret in report.
- Отсутствующий аттестованный worker.
- Несовпадение SHA / устаревший replay.

## 4. Репозитории для честного real-world испытания

Создать список внешних проектов с лицензией/документацией и без секретов, предварительно изучить их системные требования, все исполнения проводить только в VM. Минимум 10 независимых публичных проектов из 2 стеков, включая неуспехи. Не делайте ложные выводы о безопасности или качестве конкретного upstream.

Выделить демонстрационные demo-fixtures под управлением команды отдельно от настоящих внешних проектов: demo-fixtures доказывают ожидаемое поведение тестов, но не реальное качество GitHub ecosystem.

## 5. Release gates

- G1 inspect-only: unit parser paths + no execution + report summary.
- G2 executor: все sandbox security negative tests; без него execute недоступен.
- G3 verifier: 100% истинных expected verdict на контролируемой матрице; особенно 0 false `VERIFIED`.
- G4 product: Windows clean install, UI responsiveness, HTML XSS/secret checks, cross GUI/CLI report consistency.
- G5 release: лицензия, README, checksum, 10+ внешних репозиториев, known limitations, reproducible demo, независимый reviewer.

Не смешивать «100% на синтетических тестах» с 100%-точностью на реальных репозиториях.

## 6. Формат фиксации результата

Каждая задача в `STATUS.md`: `test name`, `command`, `environment`, `exit code`, `date`, `logs/evidence path`, `PASS/FAIL/NOT_RUN`. Недостоверно написанные или отсутствующие test logs блокируют маркировку `DONE`.

## 7. Примеры Go unit tests (псевдотесты до реализации)

```go
func TestSuccessExitWithoutOracleIsNotVerified(t *testing.T) { ... }
func TestHTTP404IsBehaviorFail(t *testing.T) { ... }
func TestWorkerUnavailableBlocksExecution(t *testing.T) { ... }
func TestReadmeScriptNeverExecutesDuringInspect(t *testing.T) { ... }
func TestEscapedReportCannotExecuteScript(t *testing.T) { ... }
```

После реализации заменить псевдотесты настоящими `go test` и писать точные результаты.
