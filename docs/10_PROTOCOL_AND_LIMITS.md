# Контракт VM worker / ограничения вердиктов

Это архитектурный контракт для реализации, а не готовая рабочая интеграция. Каждый RPC message versioned и authenticated между доверенным host controller и гостевой VM; непрозрачные stdout/stderr ни при каких условиях не трактуются как управляющие команды.

## Commands

```text
Probe() -> Attestation
Prepare(source_digest, image_digest, policy_digest) -> worker_run_id
StageSnapshot(run_id, source_archive_digest) -> staged_digest
RunStep(run_id, phase, step_id, command_spec, timeout_ms) -> stream<StepEvent>
Query(run_id) -> lifecycle_status
Cancel(run_id) -> cancellation_result
Destroy(run_id) -> destruction_receipt
```

## StepEvent structure

```json
{
  "schema_version": "1",
  "run_id": "uuid",
  "step_id": "install-1",
  "seq": 123,
  "utc": "2026-10-08T20:00:00Z",
  "kind": "stdout|stderr|exit|timeout|resource|artifact|heartbeat",
  "payload_ref": "evidence/steps/install-1-stdout.bin",
  "exit_code": null
}
```

`seq` монотонно возрастает в пределах worker run. Внешний network disconnect или отсутствие `exit` события -> unknown runtime outcome, не success. `Destroy` подтверждает очистку VM или откат snapshot; без receipt хранить orphan cleanup job. Worker controller не должен принимать методы, которые дают гостевой VM доступ к host shell.

## Rules for local source folders

Если `git` SHA недоступен, снимок должен содержать `source_fingerprint` как SHA-256 детерминированного манифеста файлов (путь, длина, hash) после применения правил исключения. `commit` = null, не фиктивный SHA. Формат хранения JSON должен поддерживать оба типа источников.

## Изолированная установка зависимостей

Установка packages может выполнять arbitrary code. Весь install, не только `start`, должен происходить в worker. Нельзя устанавливать зависимости на хост ради «быстрого теста». На install network фиксировать какой egress policy действовал; не объявлять все данные offline-verified при сетевой установке.

## Oracle properties

- Side effects observed only in VM scope.
- Expected values typed and deterministic (bounded regex, numeric, path).
- Timeouts explicit; no infinite waits.
- Readiness oracle cannot substitute functional oracle.
- If own oracle engine crashes, result is `ERROR_INTERNAL`, не bug чужой программы.
- `BEHAVIOR_FAIL` is a claim about a specific tested behavior under tested environment, не универсальная оценка качества repo.
