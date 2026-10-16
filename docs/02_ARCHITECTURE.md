# Архитектура и контракты компонентов

## 1. Целевая структура монорепозитория

```text
repoproof/
├── cmd/repoproof/                # CLI
├── internal/
│   ├── inspector/                # статический анализ без исполнения
│   ├── readme/                   # Markdown AST, source span
│   ├── planner/                  # plan + policy checks
│   ├── orchestrator/             # state machine
│   ├── worker/                   # client, VM adapter, NEVER host shell
│   ├── verifier/                 # CLI / HTTP / filesystem assertions
│   ├── reporter/                 # JSON + static HTML
│   ├── evidence/                 # immutable artefacts + hashing
│   ├── policy/                   # explicit allow-lists, defaults
│   └── store/                    # SQLite metadata
├── frontend/                     # Wails Svelte/TypeScript
├── fixtures/                     # clean synthetic apps
├── tests/                        # e2e with isolated runner
├── .github/workflows/
├── docs/                          # user/dev/release docs
├── repoproof.yaml                # proof contract for own repo
└── go.mod
```

Это будущая структура **исходного приложения**. Файлы этого комплекта сейчас являются проектной документацией, а не реализацией этих модулей.

## 2. Потоки данных

```text
User URL/local -> Inspector (read-only) -> SourceSnapshot(SHA,manifest)
   -> ReadmeParser -> CandidatePlans -> Policy/ManualReview
   -> Orchestrator -> IsolatedWorker (VM boundary)
   -> StepObservations -> DeterministicVerifier
   -> VerdictEngine -> EvidenceStore -> JSON + Static HTML + GUI
```

`Worker` не может произвольно изменять исходный checkout пользователя. Код из GitHub не пересылается удалённой LLM. LLM при желании может помогать автору кода приложения, но не принимать решение об истинности runtime verdict.

## 3. Стандартные интерфейсы (Go-style conceptual)

```go
type Inspector interface {
    Inspect(ctx context.Context, source SourceRef) (Snapshot, error)
}
type Planner interface {
    Plan(ctx context.Context, snapshot Snapshot) ([]CandidatePlan, error)
}
type Executor interface {
    Attest(ctx context.Context) (WorkerAttestation, error)
    Run(ctx context.Context, approved ApprovedPlan) (EventStream, error)
    Destroy(ctx context.Context, id string) error
}
type Verifier interface {
    Verify(ctx context.Context, contract ProofContract, events []StepEvent) (ProofResult, error)
}
type ReportWriter interface {
    Write(ctx context.Context, result ProofResult) (ReportPaths, error)
}
```

Модели (`SourceRef`, `ApprovedPlan` и др.) должны быть сериализуемыми, валидироваться схемами, содержать version и исключать возможности внедрения произвольных shell-команд в policy fields.

## 4. Inspector

- URL только `https://github.com/owner/repo` и поддерживаемые пути/refs. Запрет URL с встроенными credentials и опасных redirects.
- Resolve `ref` -> commit SHA. Pin all repo content to SHA, клонирование с ограничением размера/времени.
- Не следовать symlink за пределы checkout при статическом анализе.
- README парсится как Markdown AST. Хранить `source_file`,`line_start`,`line_end`, текст команды, контекст, предполагаемую фазу.
- `package.json`, `pyproject.toml`, `requirements*.txt`, `Pipfile`, `poetry.lock`, `uv.lock` использовать как признаки, не считать отдельный файл гарантией поддержки.

## 5. Planner

- Каждая команда имеет ID, phase, origin, cwd, env placeholders, timeout, network need, user approval flag.
- Автоматический план разрешён лишь при однозначном parser profile; остальные случаи `NEEDS_REVIEW`.
- Команды из README никогда не являются `trusted instructions`, любые «ignore previous...» остаются недоверенным текстом.
- Предложение исправления — JSON patch/markdown diff; не исполнить, пока не утвердили plan.

## 6. Worker protocol

Фазы: `PREPARE -> PROVISION -> INSTALL(egress policy) -> SNAPSHOT -> LAUNCH(no-egress) -> VERIFY -> COLLECT -> DESTROY`.

Worker события имеют `run_id`, `step_id`, `timestamp_utc`, `event_kind`, `stream`, `payload_ref`, `exit_code`, `timeout`, `worker_id`. Никаких строк stdout как команд управления.

**Attestation:** worker сообщает версию runtime, идентификатор образа, digest policy, факт наличия ограничений, networking mode, resource limits. Нельзя доверять self-report от исполняемого проекта; аттестацию выпускает контролирующая сторона VM.

Для MVP можно выделить заранее подготовленные тестовые VM с образами Python/Node; CI для доверенных собственных фикстур может исполняться отдельно. Если безопасный worker ещё не готов — включён только inspect-mode.

## 7. Verifier

Три слоя наблюдения: (a) setup assertions, (b) launch readiness, (c) functional oracle.

**Supported assertions v1:**
- `exit_code_equals`, `stdout_contains`, `stdout_regex` с bounded regex/timeouts;
- `file_exists`, `file_sha256`, `file_content_contains` внутри рабочей среды;
- `http_status`, `http_body_contains`, `http_json_path_equals` в пределах внутренней тестовой сети;
- `process_ready` исключительно как readiness, не самостоятельный proof.

Контракт из `specs/repoproof.example.yaml`. Отсутствующий/неподтверждённый oracle запрещает VERIFIED. Ошибка оракула самого RepoProof -> `ERROR_INTERNAL`, а не обвинение чужого репозитория.

## 8. Evidence и отчёты

- Каждое наблюдение привязывается к snapshot SHA + run_id + step_id + worker image digest.
- Хешировать сырые артефакты внутри доверенного контроллера; отчёт показывает отредактированную пользовательскую версию.
- Два уровня данных: private raw (локально, с явным retention policy) и sanitized export.
- Статический HTML без remote dependencies, все пользовательские строки HTML-escaped; Content Security Policy без inline script, если архитектура отчёта позволяет.
- Versioned JSON Schema: `specs/report.schema.json`.

## 9. CLI interface

```text
repoproof inspect ./folder --json inspect.json
repoproof inspect https://github.com/owner/repo
repoproof plan ./folder --output plan.json
repoproof verify ./folder --contract repoproof.yaml --report html --approve-plan
repoproof replay ./reports/run-uuid.json
repoproof doctor
```

`verify` без рабочей изоляции должен возвращать `BLOCKED_SECURITY` и соответствующий документированный exit code. `--approve-plan` не должен включать опасные capabilities вроде host mounts.

**Предлагаемые exit codes:** 0=VERIFIED, 10=CHECK_FAILED, 11=PARTIAL/INCONCLUSIVE, 12=UNSUPPORTED, 13=BLOCKED_SECURITY, 20=INTERNAL_ERROR, 130=CANCELLED. Уточнить до появления внешних пользователей и покрыть tests.

## 10. GUI

Главный экран: URL/папка, Inspect, список последних результатов. Экран review: исходные команды, фазы, сеть, затраты, риск. Экран run: progress, step timeline, abort. Экран result: summary, evidence, first failure, downloads.

GUI должен поддерживать компактный режим, виртуализацию длинных логов и не блокировать поток окна при работе worker.
