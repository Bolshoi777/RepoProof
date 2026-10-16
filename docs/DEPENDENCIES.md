# Third-party dependencies (G0 license gate, first entry)

| Module | Version | License | Purpose | Added |
|---|---|---|---|---|
| gopkg.in/yaml.v3 | v3.0.1 | MIT + Apache (dual, LICENSE in module cache) | strict proof-contract parsing (`internal/contract`, KnownFields) | G3-contracts |
| github.com/wailsapp/wails/v2 | v2.16.0 | MIT | desktop GUI shell (`desktop/`, bindings over `internal/app`) | G4-skeleton |

Notes: wails pulled the `go` directive to 1.25.0 (toolchain auto-resolves on
modern Go; recorded, not hidden). The wails CLI binary itself landed in
`D:\Program\` due to a pre-existing broken machine GOBIN env var — not
touched; builds use the absolute path. Transitive deps inherit their
upstream licenses (all permissive OSI); full list in `go.sum`.

Rules: stdlib first; new dependency only with license check recorded here;
`go mod tidy` clean; `go.sum` committed.
