# Implementation roadmap и Definition of Done

Цель: последовательная разработка без преждевременного GUI и ложных заявлений. Этап завершается не по времени, а по **критериям приёмки**. Оценки сроков не являются обещанием.

## G0 — product baseline и технический spike (P0)

- [ ] Сверить существующие RepoProof/Runme/repo2docker и отличия.
- [ ] Утвердить scope v1 и `VERIFIED` contract.
- [ ] Выбрать VM backend после экспериментальной проверки безопасности и стоимости.
- [ ] Создать пустой Go module, test harness, logging conventions, schema validation.
- [ ] Сверить и закрепить лицензии зависимостей.

**Gate:** ADR + task breakdown + traceability matrix. Никаких непроверенных заявлений «sandbox secured».

## G1 — read-only vertical slice

- [ ] CLI inspect path; загрузка readme и известных config files.
- [ ] repo snapshot/sha без исполнения.
- [ ] Markdown AST и code spans с привязкой к строкам.
- [ ] Поддержка Python и Node detection.
- [ ] Structured JSON report (inspect level), basic HTML.
- [ ] Unit fixture suite; no-exec guard tests.

**Gate:** `repoproof inspect <fixture>` работает без VM и host execution; `go test ./...` зелёный; все отрицательные примеры честно отмечены.

## G2 — isolated executor

- [ ] Отдельный interface Worker/Attestation, без host fallback.
- [ ] Реализовать и аттестовать VM profile (isolation boundary documented).
- [ ] Snapshot/restart, timeout, cleanup, cancellation.
- [ ] Install vs verify networking policy.
- [ ] Sandbox security negative tests и recovery after crash.

**Gate:** `execute` доступен только на аттестованном worker, 12 security сценариев из threat model проходят в тестовой лаборатории.

## G3 — behavioral proof

- [ ] deterministic proof contract parser + schema.
- [ ] Python CLI install/launch/oracle.
- [ ] Node CLI install/launch/oracle.
- [ ] HTTP readiness/status/body oracle.
- [ ] verdict state-machine + evidence hash + report schema.
- [ ] replay for fixed SHA and environment fingerprint.
- [ ] 30+ fixtures including bad README, missing deps, false 0, 404.

**Gate:** zero false VERIFIED on complete synthetic matrix, 10 independent external cases processed with truthful unsupported and inconclusive statuses.

## G4 — product UX

- [ ] Wails desktop app, one source of truth in Go Core.
- [ ] compact screens Inspect, Plan, Run, Report.
- [ ] sanitised offline HTML, JSON download, logs with truncation.
- [ ] Installer/portable Windows release, no Go/Node needed at runtime.
- [ ] Keyboard navigation/HiDPI/responsiveness.

**Gate:** clean Windows install E2E + abort/re-run + reports consistent with CLI.

## G5 — independent review and first public release

- [ ] Independent `repoproof-security` audit; fixes done.
- [ ] Independent `repoproof-release-auditor` review; blockers zero.
- [ ] Self-hosted test: RepoProof проверяет собственный Quick Start.
- [ ] README English, docs English summary, real GIF/video.
- [ ] LICENSE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG.
- [ ] GitHub Releases binaries, sha256sum, signed if feasible, SBOM/dependency scan.
- [ ] Published limitations and results with reproducible examples.
- [ ] Name/trademark availability check and release identity decision.

**Gate:** можно воспроизвести рекламируемый сценарий по публичной документации на чистой тестовой машине; никаких незакрытых критических безопасности.

## Strict task protocol for agent

Каждая задача: `ID`, `motivation`, `scope`, `acceptance`, `tests`, `files`, `risk`, `evidence`. Маленькая локальная модель решает один task per turn. Агент не переходит к G3 до G2 security gate; UI может разрабатываться параллельно на синтетических данных, но это mock UI и не является готовым инструментом.
