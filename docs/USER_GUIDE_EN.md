# RepoProof User Guide (English)

Local-first verification of a GitHub project's first-user path, with evidence.
No account, no cloud, no Docker required. Tested on Windows 11 x64;
Windows 10 compatibility remains unverified.

## Install (portable)

1. Unzip `repoproof-*-windows-amd64.zip` (CLI) anywhere.
2. Unzip `repoproof-desktop-*-windows-amd64.zip` (GUI) anywhere.
3. Verify checksums against the `.sha256` files. For example, compare the output of:

   ```powershell
   Get-FileHash .\repoproof-desktop-0.1.0-dev39-windows-amd64.zip -Algorithm SHA256
   Get-Content .\repoproof-desktop-0.1.0-dev39-windows-amd64.zip.sha256
   ```

   The 64-character hash and filename must match before you extract the archive.
4. An installer is optional; no admin rights or background services are required.

The ZIP also contains `install-portable.ps1`. From PowerShell, run
`./install-portable.ps1 -PackagePath .\repoproof-...zip` to verify the
embedded executable checksum and install it under
`%LOCALAPPDATA%\Programs\RepoProof\CLI` or `...\Desktop` without elevation.
Pass `-InstallRoot` to choose another directory. The script keeps a previous
installation beside the new one if replacement is needed.

If double-clicking appears to do nothing, make sure the ZIP was extracted
first: launch the one desktop `.exe` inside the extracted folder, or run the
portable script and start the installed executable at
`%LOCALAPPDATA%\Programs\RepoProof\Desktop`. The ZIP file itself is not
the executable.

You need: Git (only if you verify GitHub URLs), nothing else. Python/Node
runtimes are provisioned automatically as pinned portable copies on first
use (cached under `%LOCALAPPDATA%\repoproof\runtimes`, delete the folder
to clear).

## The workflow (CLI)

```powershell
# 1. Static inspection. Never executes anything.
repoproof inspect <folder-or-GitHub-URL> [--json inspect.json] [--html inspect.html]

# 2. Candidate plan (review it).
repoproof plan <folder-or-URL> [--json plan.json]

# 3. Write your proof contract (what must be true after the run).
#    See specs/repoproof.example.yaml. Keep it next to your approval files,
#    OUTSIDE the inspected project (otherwise the fingerprint changes).

# 4. Draft the approval. Read every PENDING reason; re-run with --ack-all
#    only for risks you accept, or edit the file by hand.
repoproof approve <folder-or-URL> --contract contract.yaml --statement "..." [--ack-all] --output approval.json

# 5. Run the sandboxed verification.
repoproof verify <folder-or-URL> --contract contract.yaml --approve-file approval.json [--json proof.json] [--html proof.html] [--evidence-dir ./evidence] [--no-provision]
```

## Automatic check (no oracle, capped at PARTIAL)

```powershell
# Prints the candidate plan first, then runs it only with explicit confirmation.
repoproof check <folder-or-URL> [--json proof.json] [--html proof.html] [--evidence-dir ./evidence] [--no-provision] --confirm-run
```

- Without `--confirm-run` nothing runs: exit `11` (inconclusive) after the plan is shown for review.
- The contract is machine-built from the plan phases; it carries **no oracle**, so the verdict is capped at `PARTIAL` by construction — `VERIFIED` is unreachable in this mode, and the summary says so.
- Unsupported stacks exit `12` without running; plans with no runnable steps exit `11` without running.
- Python dependencies are staged the same way as `verify` (pinned wheels, offline `pip --no-index`), unless `--no-provision` is passed.

Exit codes: `0` VERIFIED; `10` check failed (behavior/launch/install/docs);
`11` partial/inconclusive (incl. denied approval); `12` unsupported stack;
`13` blocked (no usable sandbox); `14` blocked (no container engine, legacy
Docker path); `20` internal/usage error; `130` cancelled (Ctrl+C works and
always cleans up).

Generated approval records contain an `expires_at` timestamp and are valid for
24 hours. Hand-written approval records must include a future RFC3339
`expires_at`; missing or expired approvals are rejected before execution.

## The workflow (GUI)

Open the app: **1. Inspect** a folder or pasted GitHub URL → **2. Review**
the plan, write the contract path and statement, draft approval →
**3. Confirm & Verify**, watch progress, **Cancel & Cleanup** anytime →
save the proof JSON. The sandbox status badge must read `ready`; otherwise
only inspection is available.

Shortcut: after **1. Inspect**, tick `I reviewed the plan above (auto mode,
verdict capped at PARTIAL)` and press **Auto-check**. It runs the same
automatic chain as `repoproof check --confirm-run` (no contract or approval
files needed, verdict capped at `PARTIAL`); progress, cancel and saving the
proof work exactly as for Verify.

## Verdicts, honestly

- `VERIFIED` means: the exact asserted behavior was observed, in the stated
  environment, with sealed evidence. Nothing more.
- `PARTIAL` means setup/launch worked but no behavioral oracle existed.
- `INCONCLUSIVE` means the run was denied, cancelled-by-policy, or missing
  prerequisites. `UNSUPPORTED` means the stack is out of scope.
- Approval, contract and output files must live OUTSIDE the inspected
  project, or the fingerprint check fails the run (by design).

## Hard limitations (not bugs)

- Node.js does not start in the sandbox (structural, exit 134): Node projects
  report UNSUPPORTED. Python works, including offline pip installs from
  digest-pinned wheels.
- HTTP service verification is UNSUPPORTED (loopback is unavailable inside
  the sandbox); no firewall exemptions are ever applied.
- Only exact `name==version` pins install; ranges and URLs in
  `requirements.txt` are refused.
- Secret redaction is an allowlist, not DLP. Disk quota is a declared
  budget, not a hard enforcement.
- Private repositories, SSH URLs, non-GitHub hosts, submodules and LFS
  are out of scope and refused with explicit errors.

## Troubleshooting

- `verify` → `INCONCLUSIVE` + "stale or foreign approval": something changed
  inside the project after approval (often the approval file itself was
  saved there). Regenerate approval outside the project.
- `verify` → `INCONCLUSIVE` + "approval has expired" or "approval expiry is
  required": generate a fresh approval or add a future RFC3339 `expires_at`.
- `verify` → `BLOCKED_SECURITY`: no usable sandbox on this machine.
- Leftover `repoproof-*` profiles or temp dirs after a crash: run any
  `verify` once — startup recovery reaps owned resources only.
