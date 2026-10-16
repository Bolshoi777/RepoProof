# Security policy

Dev-only status: RepoProof has **not** passed an independent security audit
yet, and there has been no public release. Do not treat the sandbox as an
absolute boundary.

## Scope

RepoProof is a local-only Windows tool. It has no network services, no
accounts, no cloud components, and no background daemons. The main
security-relevant surface is the sandboxed execution of untrusted
repository content (native AppContainer backend, `internal/sandbox/`).

## Guarantees (actually enforced, not aspirational)

- `inspect`, `plan`, `approve`, and `replay` never execute repository content.
- `verify`/`check` never fall back to host execution: without a usable
  sandbox the run is refused (`BLOCKED_SECURITY`/`BLOCKED_ENVIRONMENT`).
- The sandbox never mounts `~/.ssh`, API tokens, git credentials, the home
  directory, or the Docker socket into the guest.
- Proof reports and logs are treated as untrusted data: HTML output is
  escaped, secrets are redacted by allowlist (see Hard limitations in
  `docs/USER_GUIDE_EN.md` — it is an allowlist, not DLP), and no executable
  code from README files or logs is embedded in reports.

## Known limits (not bugs)

See `docs/USER_GUIDE_EN.md` (Hard limitations) and `docs/SECURITY_TESTS.md`:
disk quota is a declared budget, not hard enforcement; CPU capacity is a
reference, not a cap; the independent audit and the clean-machine install
test are still pending.

## Reporting a vulnerability

Open a GitHub issue with `[security]` in the title. Sanitize before posting:
remove secrets, tokens, absolute paths, and hostnames from logs and proof
reports (the tool redacts by allowlist — check the pasted text yourself).
Do not post exploits against third parties.
