# RepoProof

[![Go tests](https://github.com/Bolshoi777/RepoProof/actions/workflows/go-test.yml/badge.svg)](https://github.com/Bolshoi777/RepoProof/actions/workflows/go-test.yml)
[![Self-check](https://github.com/Bolshoi777/RepoProof/actions/workflows/self-check.yml/badge.svg)](https://github.com/Bolshoi777/RepoProof/actions/workflows/self-check.yml)

**Inspect a GitHub project. Review the exact first-use plan. Keep evidence for every conclusion.**

RepoProof is a Windows desktop and CLI tool for inspecting how a repository is installed and launched. It reads a pinned source snapshot, extracts candidate commands from the README, detects the project stack, and produces bounded JSON/HTML reports.

Inspection is read-only. Repository code, README commands, package lifecycle hooks, and browser JavaScript are treated as untrusted. Verification is fail-closed and stays disabled until an isolated worker has an independent security attestation.

## What you get

- **One pinned source snapshot** for inspection and planning, including browser-copied GitHub links such as `/tree/main?tab=readme`.
- **Evidence-linked commands** with README line ranges, detected stack, commit, and source fingerprint.
- **A Windows GUI** with elapsed progress, cancellation, plan review, and sanitized report export.
- **A CLI** for repeatable inspect, plan, approval, verify, check, and replay workflows.
- **Fail-closed execution**: no PowerShell, `cmd`, WSL, Docker, or host fallback for third-party code.

## Current release status

The current Windows package is an **inspect-only development snapshot** (`0.1.0-dev40`). It is useful for safely reviewing public repositories. `Verify` and `Auto-check` remain disabled until the independent native-worker and security-lab gates are complete. The project does not claim that a repository is safe or universally working.

## Quick start on Windows

1. Download the Desktop ZIP from the [Releases page](https://github.com/Bolshoi777/RepoProof/releases).
2. Verify the included `.sha256` sidecar.
3. Extract the ZIP and launch the single Desktop `.exe`, or install it without administrator rights:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\install-portable.ps1 `
     -PackagePath .\repoproof-desktop-0.1.0-dev40-windows-amd64.zip
   ```

4. Paste a public HTTPS GitHub URL into **Inspect**. Review the pinned commit and candidate commands. The GUI shows elapsed time while a remote snapshot is prepared and provides **Cancel inspect**.

The ZIP must be extracted before launching. Git is required only for HTTPS repository inspection; no Go, Node, Python, Docker, or administrator rights are required for inspect-only use.

## CLI example

```powershell
$target = "https://github.com/psf/requests/tree/main?tab=readme"
repoproof inspect $target --json .\inspect.json --html .\inspect.html
repoproof plan $target --json .\plan.json
```

Keep contracts, approvals, reports, and evidence outside the inspected repository. A successful install, build, or exit code is never by itself a `VERIFIED` result.

## Scope and limits

The v1 execution scope is Python and Node CLI projects. Node 22 and HTTP verification are currently reported as `UNSUPPORTED` on the native zero-capability backend. Public GitHub HTTPS repositories are supported; private credentials, submodules, LFS, arbitrary dependency ranges, and unbounded redirects are refused explicitly.

When the worker is not independently attested, execution requests return `BLOCKED_SECURITY`. This is an intentional safety property, not a hidden fallback.

Read the [user guide](docs/USER_GUIDE_EN.md), [security model](docs/03_SANDBOX_SECURITY.md), [security test matrix](docs/SECURITY_TESTS.md), and [contributing guide](CONTRIBUTING.md) before using or extending the project.

## Development

```powershell
go vet ./...
go test ./...
powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Version 0.1.0-dev40
```

The normal release script runs validation, creates an SPDX SBOM, builds the CLI and Wails Desktop packages, and writes SHA-256 sidecars. Public release still requires independent attestation, security-lab, clean-machine, license, signing, E2E, and provenance evidence.

## Security

RepoProof never mounts SSH keys, API tokens, Git credentials, a home directory, or a Docker socket into a worker. Reports escape untrusted strings and redact recognized secret shapes, but redaction is an allowlist rather than DLP. Please read [SECURITY.md](SECURITY.md) before posting logs or proof reports to a public issue.

## License

See [LICENSE](LICENSE).
