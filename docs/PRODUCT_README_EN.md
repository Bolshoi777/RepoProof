# RepoProof

RepoProof is a Windows desktop and CLI tool for inspecting a GitHub
repository's first-user setup path and producing bounded, evidence-backed
results. Inspection is read-only. A verification run is allowed only after
an isolated native worker is independently attested.

## Quick start

1. Download the CLI or Desktop ZIP and verify its SHA-256 sidecar.
2. Run `install-portable.ps1 -PackagePath .\repoproof-*.zip`, or unzip the
   package manually. No Go, Node, Python, Docker or administrator rights are
   required for inspection.
3. Start with `repoproof inspect https://github.com/owner/repository` or open
   the Desktop app and paste the HTTPS GitHub URL.
4. Review the detected commands and source commit before creating a contract.

### Windows GUI quick start

1. Download `repoproof-desktop-*-windows-amd64.zip` and extract it to a
   writable folder.
2. Double-click the single `repoproof-desktop-*-windows-amd64.exe` inside
   the extracted folder, or install it with the portable script:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\install-portable.ps1 `
     -PackagePath .\repoproof-desktop-0.1.0-dev30-windows-amd64.zip
   ```

   The installed GUI is placed under
   `%LOCALAPPDATA%\Programs\RepoProof\Desktop`.
3. Paste a public HTTPS GitHub URL into **Inspect** and review the plan.

The ZIP itself is an archive and cannot be launched directly. If the GUI
window is not visible after installation, run the installed EXE from the
path above or use `Alt+Tab` to select it. Until an independent native
attestation is present, the sandbox badge remains `inspect-only` and execute
requests return `BLOCKED_SECURITY` by design.

## CLI workflow

```powershell
$target = "C:\path\to\repository" # or an HTTPS GitHub URL
$runDir = Join-Path $env:USERPROFILE "RepoProof-runs\demo"
New-Item -ItemType Directory -Force $runDir | Out-Null
repoproof inspect $target --json "$runDir\inspect.json"
repoproof plan $target --json "$runDir\plan.json"
repoproof approve $target --contract "$runDir\repoproof.yaml" --statement "I reviewed the plan" --output "$runDir\approval.json"
repoproof verify $target --contract "$runDir\repoproof.yaml" --approve-file "$runDir\approval.json" --json "$runDir\proof.json" --html "$runDir\proof.html"
```

Keep contracts, approval records and generated reports outside the inspected
repository. They are part of the approval fingerprint by design.

Generated approvals expire after 24 hours. A hand-written approval must carry
a future RFC3339 `expires_at` field; missing or expired approvals are rejected.

`VERIFIED` means that the exact contract assertion was observed with sealed
evidence in the recorded environment. A successful install, exit code, or
build alone is never proof.

## Scope and limits

The v1 execution scope is Python and Node CLI projects. Python portable
runtime and exact pinned wheels can be staged offline inside the sandbox.
Node 22 and HTTP verification are currently reported as `UNSUPPORTED` on the
native zero-capability backend. GitHub URLs must be public HTTPS repositories;
submodules, private credentials, LFS and arbitrary dependency ranges are
refused explicitly.

On builds without an independent native security receipt the UI and CLI stay
in `inspect-only` mode and return `BLOCKED_SECURITY` for execution requests.
RepoProof does not certify a repository as safe or universally working.

See `docs/USER_GUIDE_EN.md`, `SECURITY.md` and `docs/STATUS.md` for the
reproducible workflow, threat model and current release gate.
