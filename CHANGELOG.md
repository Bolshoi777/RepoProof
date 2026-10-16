# Changelog

All notable changes, newest first. Entries mirror the git history; every
claim below is backed by tests recorded in `docs/STATUS.md` at the time.

## Unreleased (main branch)

### Security packaging
- Public Windows binaries are built with Go -trimpath so developer checkout and module-cache paths are not embedded in release executables.

### Added
- README parsing now covers indented blocks, blockquote fences and setext headings while preserving source line spans.
- Verify UI and exported proof HTML provide phase filters for setup, launch, behavior and system timeline entries without executing report data.
- Windows self-check workflow inspects a clean checkout and validates acceptance-matrix integrity; bug and feature issue forms are included.
- `doctor` now reports the native sandbox probe result and reason used by the GUI support badge.
- Added a release handoff and read-only gate audit for independent security, clean-machine, E2E, license and signing evidence.
- Release gate audit now rejects placeholder/`NOT_RUN` receipts, incomplete 12-scenario lab results, duplicate external repositories and malformed or unpinned hashes.
- Contract `max_wall_seconds` now bounds the complete orchestration chain and reports an overrun as `INCONCLUSIVE`.
- Contract `max_output_bytes` now propagates into the native session output cap and report truncation.
- Added an explicitly development-only `-SkipValidation` packaging mode for incremental snapshots; the normal build path still runs the full validation suite.
- GUI inspect errors now show actionable backend messages instead of `[object Object]`.
- Browser-copied GitHub repository links are normalized from common subroutes to the repository root.
- GUI inspection now materializes a GitHub target once for both the report and plan, with an elapsed status message while the read-only clone is prepared.
- GUI inspection can be cancelled while a remote snapshot is being prepared; cancellation is propagated to the bounded Git operation and cleanup path.
- GUI verify actions now stay disabled with an explicit tooltip until the worker attestation gate is available.
- Portable PowerShell install flow with archive path validation and EXE checksum verification.
- W2b: run progress timeline, cancellation to CANCELLED, Ctrl+C wiring.
- `approve` helper: approval drafting with explicit PENDING/ACKNOWLEDGED flow.
- `replay` command with environment-limits comparison (fresh VERIFIED reuses,
  tampering goes STALE).
- Proof HTML rendering (`verify --html`) with executed-steps table.
- `internal/app` service layer shared by CLI and GUI; CLI delegates to it.
- Wails desktop skeleton with tested bindings (Inspect/Plan/Approve/Verify/
  Cancel/SaveProof), no-npm frontend.
- URL cloning with pinned commits wired into inspect.
- Registry-egress fetch core (npm/PyPI allowlist) + strict pydeps staging.
- Auto-deps wiring: requirements → staged wheels → pip prologue in-chain.
- Exit codes finalized (ADR-009); UNSUPPORTED reachable through the chain.
- Release packaging: desktop portable zip next to CLI release.
- This English user guide.

### Changed
- Acceptance fixtures no longer claim Node/HTTP `VERIFIED` on the current backend; unsupported capability rows remain explicit until a compatible attested worker exists.
- Worker attestation Gate now rejects malformed image/policy digests and requires the explicit `sha256:<64 hex>` form.
- Sandbox direction: per-repo VM → disposable Docker → native AppContainer,
  no Docker/WSL required (ADR-006/007/008).
- Contract-vs-plan runtime mismatch is noted, never silent.
- Proof schema gained `BLOCKED_ENVIRONMENT`, `app_version`, `limits`, `steps`.

### Added
- W2b: run progress timeline (`authorized → session ready → step … → verdict`),
  cancellation before/during runs maps to CANCELLED, Ctrl+C wired through
  signal.NotifyContext (`e01155e`).
- W2: `verify <path> --contract --approve-file [--json] [--evidence-dir]`
  end-to-end CLI chain with schema-validated proof reports; `BLOCKED_ENVIRONMENT`
  added to the report schema enum (`135e516`).
- W1: `internal/orchestrate` — authorize → resolve → setup → launch →
  oracle → verdict → sealed evidence, with live VERIFIED run (`7bac5fe`).
- N4: `http_status` / `http_body_contains` evaluators; live loopback
  measurement (inside↔inside unavailable, host↮container blocked) with the
  recorded decision: HTTP phase is UNSUPPORTED in zero-cap containers (`87b9c1d`).
- G3-06: environment fingerprinting with explicit replay-mismatch
  warnings (`0755523`).
- G3-05: content-addressed evidence store with sealed hash chain (`a50c685`).
- G3-contracts: strict proof-contract parser (yaml.v3, first dependency),
  loopback-only oracles; example migrated to the strict schema (`91346c2`).
- N3b: pinned portable provisioning (zip + tar.gz); live CPython 3.13.16
  goldens (VERIFIED / BEHAVIOR_FAIL); Node 22 documented as incompatible
  with zero-capability containers (`1a0966f`).
- N3: runtime resolver, CLI assertion evaluators, live cmd proof-of-chain (`a650667`).
- N2: Job Object limits, sanitized env, session lifecycle, owned-only
  orphan recovery (`f5c3c10`).
- N1: native AppContainer spike with live containment proof, no admin (`868783e`).
- G3-04: pure proof-verdict function with exhaustive no-false-VERIFIED
  check over 1728 input combinations (`c9ae10e`).
- SBX-P0/P1: container runtime probe with `BLOCKED_ENVIRONMENT` (later
  retired to legacy by ADR-008) (`556917d`).
- G2-04: secret-redaction engine with HTML integration (`0fb84e1`).
- G2-03: timeout, output cap, cancellation, crash-safe run journal (`a8a4bd7`).
- G2-02: explicit approval and execute gating (`3d82012`).
- G2-01: worker attestation contract with fail-closed gate (`be1bb76`).
- G1 (01–06): inspect-only CLI — static walk, git SHA pinning, README
  command extraction, stack matrix, candidate plans, schema-validated
  JSON and self-contained HTML (`c48e3f8`…`d885b87`).
- G0-01: Go module skeleton with fail-closed verify stub (`94eb387`).

### Changed
- Sandbox direction: per-repo VM (ADR-006) → disposable Docker (ADR-007) →
  native AppContainer, no Docker/WSL required (ADR-008).
- `specs/repoproof.example.yaml` migrated from the loose proposal to the
  strict v1 contract schema.
- `specs/report.schema.json` status enum gained `BLOCKED_ENVIRONMENT`.

### Known limitations (not defects, design constraints)
- Node.js 22 cannot start in zero-capability AppContainers (exit 134);
  Node runtime is UNSUPPORTED pending capability research.
- HTTP verification phase is UNSUPPORTED in zero-capability containers
  (loopback unavailable); no global exemptions are applied.
- Secret redaction is an allowlist, not DLP; bidi-override display limits apply.
- Disk hard quota is unenforceable on this backend; a declared budget is
  reported with that limitation.
- Independent security audit and clean-machine install test are pending
  (required before any public release claim).
