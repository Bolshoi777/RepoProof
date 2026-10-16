# RepoProof 0.1.0-dev38

Windows inspect-only development snapshot.

## Included behavior

- Read-only inspection of local folders and public HTTPS GitHub repositories.
- Browser-copied GitHub URLs normalize to one pinned repository snapshot.
- GUI shows elapsed clone progress and supports `Cancel inspect`.
- Reports escape untrusted text and redact recognized secret shapes.

## Security status

Execution remains fail-closed. `Verify` and `Auto-check` stay disabled until an independent native-worker attestation and the required security-lab receipts are available. This prerelease does not claim that a repository is safe or universally working.

## Assets

- `repoproof-0.1.0-dev38-windows-amd64.zip` — CLI portable package.
- `repoproof-desktop-0.1.0-dev38-windows-amd64.zip` — Windows GUI portable package.
- `.sha256` sidecars and SPDX SBOM are included in the release assets.

The source tree intentionally excludes local agent instructions, private development evidence, temporary logs, and generated build directories.
