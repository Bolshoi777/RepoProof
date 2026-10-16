# Security tests matrix (threat model §7)

Честный учёт 12 блокирующих security-тестов из `docs/03_SANDBOX_SECURITY.md`.
Статусы: COVERED-UNIT — покрыт юнит-тестом без исполнения; LAB-ONLY — требует
изолированную лабораторию/VM и НЕ МОЖЕТ выполняться на host (запуск
разрушительных фикстур на host запрещён); PARTIAL — покрыт частично.

| # | Кейс | Статус | Доказательство | Примечание |
|---|---|---|---|---|
| 1 | host-file-read | LAB-ONLY | — | Нужен аттестованный worker (DEBT-006) |
| 2 | host-file-write | LAB-ONLY | — | То же |
| 3 | secret-access | LAB-ONLY | — | То же; display-redact уже в `internal/redact` |
| 4 | socket-access | LAB-ONLY | — | То же |
| 5 | network-egress (offline-фаза) | LAB-ONLY | — | То же |
| 6 | local-network (RFC1918) | LAB-ONLY | — | То же |
| 7 | fork-bomb/resource limits | PARTIAL | `RunWithTimeout`, `CappedWriter`, `Registry` в `internal/worker` + Job Object memory/process/CPU limits, bounded workspace scan and tree join | Формальный fork-bomb/stress lab — NOT_RUN |
| 8 | symlink/path-traversal | PARTIAL | `TestSymlinkNotFollowed` (SKIP без привилегии, DEBT-001), `TestMalformedHEADHasNoCommit` (ref `..`/abs), `.git`-skip | Полный прогон — в CI/lab |
| 9 | log-XSS | COVERED-UNIT | `TestHTMLXSSNeutralized`, `TestInspectHTML`, ноль `<script` в шаблоне | HTML без скриптов по построению |
| 10 | log-secrets | COVERED-UNIT | `internal/redact` (8 кейсов, idempotent, bounded) + HTML/proof JSON redaction tests | Allowlist-подход, не DLP; exact bytes остаются только в content-addressed evidence objects |
| 11 | cancellation | COVERED-UNIT | `TestRunWithTimeoutCancel`, `Registry.Destroy` idempotent | Orphan-cleanup — за backend |
| 12 | renderer-failure | COVERED-UNIT | `TestRendererWithMalformedInput` (битые байты, незакрытый fence), tamper-тесты JSON, corrupt-journal | Bidi-override символы (U+202E) проходят как текст — известное ограничение отображения |

Правила: LAB-ONLY кейсы нельзя «закрывать» синтетикой на host; закрытие G2 gate требует прогона всех 12 в лаборатории с логами. Этот файл — учёт, а не пропуск.

## Amendment acceptance G.1–20 (N1–N3 live)

| ID | Результат | Evidence |
|---|---|---|
| G.1 (static без Docker/WSL) | PASS | inspect/plan без исполнения; нативные тесты не требуют демона |
| G.2 (нет артефактов после прогона) | PASS | реестр Mappings: 0 repoproof-профилей после сьютов; Finalize/RecoverOrphans с proof |
| G.3 (deny чтение user docs/ssh) | PASS | N1: чтение снаружи DENIED (exit 1) |
| G.4 (deny запись снаружи) | PASS | N1: запись наружу DENIED, файла нет |
| G.5 (deny credential store/high-integrity) | PARTIAL | Low integrity доказан (S-1-16-4096); прямой штурм store — NOT_RUN (нет такого теста сознательно) |
| G.6 (network-off) | PARTIAL | zero-capability deny-by-default; loopback реально недоступен (ping умирает) — формальный egress-тест − NOT_RUN |
| G.7 (install scripts внутри) | PASS (python) / NOT_RUN (npm) | pip --no-index --find-links из staged six-1.16.0 живьём + import carries version → VERIFIED; хуки только внутри; npm ждёт Node-совместимости (DEBT-017) |
| G.8 (cancel/timeout убивает дерево) | PASS | N2: ≥2 в job → Cancel → оба вернулись, beats замерли |
| G.9 (лимиты, отзывчивость) | PARTIAL | memory/process round-trip + CPU hard cap (`TestCPUCapAppliedLive`) + bounded/reparse-aware sampled disk monitor (`TestWorkspaceBudgetMonitorStopsOnGrowth`) + Job termination/join; full stress — NOT_RUN |
| G.10 (kill mid-run + restart) | PASS (first-party live) | abandon→RecoverOrphans: owned убран, foreign/escape пропущены с ошибкой; missing-workspace retry и profile cleanup — `TestRecoveryAfterWorkspaceGoneLive`; [evidence](evidence/lifecycle-concurrency-recovery-2026-10-15-atomic.txt) |
| G.11 (параллельные runs) | PASS (first-party live) | `TestParallelSessionsIsolationLive` (5x repeat) + `TestConcurrentFinalizeIsIdempotentLive` + `TestConcurrentCancelCopiesLive`: две AppContainer-сессии одновременно, cancel/finalize A не затрагивает B, copied-session cleanup is idempotent, owned cleanup verified; [targeted evidence](evidence/lifecycle-concurrency-recovery-2026-10-15-atomic.txt), [full sandbox rerun](evidence/build-release-dev25.txt) | Независимый security lab всё ещё обязателен для G2 |
| G.12 (traversal/junction в cleanup) | PARTIAL | canonical `verifyOwnership` + foreign/escape recovery tests; privileged junction creation lab — NOT_RUN |
| G.13 (no host fallback) | PASS | `verify` → 13, env-независимый строгий тест; LaunchInContainer terminate-and-refuse |
| G.14/15 (Python/Node happy+broken) | PARTIAL | python: provision+golden живьём (ниже); node 22: provision OK, запуск падает в zero-cap (см. finding); cmd proof-of-chain: VERIFIED/BEHAVIOR_FAIL |
| G.16 (Linux-only → unsupported) | PASS (уровень детекта) | матрица стеков + UNSUPPORTED; живой Linux-кейс невозможен здесь по определению |
| G.17 (HTTP contained) | UNSUPPORTED (доказано) | живое измерение 3 направлений: host↮in заблокированы (требование), in↔in недоступен → HTTP-фаза UNSUPPORTED без ослабления изоляции (§D); evaluators http_status/body готовы к будущим backend |

## Findings: loopback isolation (N4 live, 2026-10-09)

- Внутриконтурный loopback в zero-capability AppContainer НЕДОСТУПЕН: сервер внутри поднят, 30 проб из того же профиля — ни одна не соединилась.
- host→in: активно refused (требование выполнено). in→host loopback: заблокирован (network-off по умолчанию, требование выполнено).
- Решение N4: HTTP-фаза — UNSUPPORTED без глобальных firewall-исключений и без брокера, ослабляющего изоляцию. Контрактные http-assertions и evaluator остаются в коде для будущих backend; живого HTTP-proof в zero-cap нет и не заявляется.
| G.18 (GUI evidence/disk) | PARTIAL | Wails GUI JSON+offline HTML export bindings, visual pass, SPDX/package build and portable install smoke проверены; clean-machine disk/HiDPI acceptance — NOT_RUN |
| G.19 (static не исполняет) | PASS | hostile/marker-тесты на всех уровнях |
| G.20 (регрессия) | PASS | first-party unit/desktop/app suites + `go vet ./...`; live external/security lab suites отдельно отмечены |

Stop-the-line (3,4,6,7,8,10,12,13): 6 и 7 — PARTIAL (механизм доказан, формальные штурмы/менеджеры — NOT_RUN); остальные из списка — PASS. READY не заявляется.

## Findings: runtime compatibility (N3b live)

- CPython 3.13.16 portable РАБОТАЕТ в zero-capability AppContainer: happy VERIFIED, broken BEHAVIOR_FAIL (`TestPythonGoldenLive`). Нефатальное предупреждение shim «Failed to find real location» — зафиксировано, на вердикт не влияет. Digest запинан TOFU (первый аудированный fetch 2026-10-09, дальше tamper-evident).
- Node 22.18.0 portable НЕ РАБОТАЕТ в AppContainer: падает на старте платформы во всех 8 комбинациях job × env × capabilities (код 134, `node::InitializeOncePerProcess`); capabilities (internetClient/privateNetwork/enterpriseAuth) не влияют — несовместимость структурная. Capability research закрыт отрицательным результатом; инфраструктура caps (`LaunchInJobCaps`, S-1-15-3-* allowlist, reject-тест) остаётся для будущих рантаймов. Provision работает. Статус: UNSUPPORTED утверждён. Не баг RepoProof: тот же бинарь вне контейнера исправен.

## Sandbox acceptance SBX-01..SBX-20 (RP-SBX-CHANGE-001 P0)

Стенд P0: Docker CLI 29.2.0 есть, daemon down. Статусы: PASS / FAIL /
NOT_RUN (демон/интеграция недоступны — честно, без моков вместо них).

| ID | Результат | Evidence |
|---|---|---|
| SBX-01 (нет Docker) | PASS (ветка no-daemon) | живой прогон: `verify`→14 BLOCKED_ENVIRONMENT, `inspect`→0; `TestProbeNoDockerOnPATH`, `TestVerifyFailsClosed` |
| SBX-02,03,04,05,06,07,08,09,10,12,13,14,15,17,20 | NOT_RUN | требуют демона (P2–P4); запрещены моки вместо интеграции |
| SBX-11 (XSS/секрет в логе) | PASS (display-уровень) | `TestHTMLXSSNeutralized`, redact-тесты; полный прогон с демоном — NOT_RUN |
| SBX-16 (регрессия) | PASS | `go test ./...` 9/9 пакетов PASS после изменений |
| SBX-18 (broken runtime policy) | PASS (ветка wrong-mode) | injected windows-mode → BLOCKED_SECURITY |
| SBX-19 (traversal/symlink) | PARTIAL | как в §7-матрице выше; демон-часть — NOT_RUN |
