# Contributing to RepoProof

RepoProof is a security-sensitive Windows tool. Keep changes small, evidence-based, and easy to review.

## Before opening a pull request

- Read the product scope in `docs/01_PRODUCT_TZ.md` and the security model in `docs/03_SANDBOX_SECURITY.md`.
- Never execute code from a third-party repository on the host. Do not add host fallbacks.
- Add a focused positive and negative test for behavior changes.
- Run the smallest relevant checks first (`gofmt`, `go vet` for affected packages, and targeted `go test`).
- Keep generated reports, approval files, credentials, local paths, and temporary artifacts out of commits.
- Update user-facing documentation when behavior or limits change.

## Security boundaries

`inspect`, `plan`, and `approve` are read-only. `verify` and `check` must remain fail-closed unless the worker is independently attested. Do not weaken redaction, path guards, resource bounds, or cleanup behavior to make a test pass.

## Pull requests

Describe the user-visible behavior, the security impact, and the exact checks run. Never include real tokens, private repository content, absolute home-directory paths, or unredacted logs. Do not claim `VERIFIED` without a real behavioral contract, pinned commit, and sealed evidence.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and [LICENSE](LICENSE) for terms.
