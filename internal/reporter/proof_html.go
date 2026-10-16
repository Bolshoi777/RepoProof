package reporter

import (
	"encoding/json"
	"fmt"
	ht "html/template"
	"io"
	"strings"

	"github.com/repoproof/repoproof/internal/redact"
)

// WriteProofHTML renders validated proof JSON as a self-contained page:
// no external resources, no <script> elements, every untrusted string
// escaped by html/template plus redaction of secret shapes. Hashes and
// SHAs pass through byte-identical (never redacted).
func WriteProofHTML(reportJSON []byte, w io.Writer) error {
	if err := ValidateProofReport(reportJSON); err != nil {
		return fmt.Errorf("proof html: invalid report: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(reportJSON, &m); err != nil {
		return err
	}
	str := func(mp map[string]any, k string) string {
		s, _ := mp[k].(string)
		return redact.RedactText(s)
	}
	strs := func(v any) []string {
		arr, _ := v.([]any)
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			if s, ok := e.(string); ok {
				out = append(out, redact.RedactText(s))
			}
		}
		return out
	}
	snap, _ := m["snapshot"].(map[string]any)
	env, _ := m["environment"].(map[string]any)
	lv, _ := m["levels"].(map[string]any)
	type checkView struct {
		ID, Type, Expected, Observed, Result, EvidenceRef string
	}
	var checks []checkView
	if arr, ok := m["checks"].([]any); ok {
		for _, cv := range arr {
			cm, _ := cv.(map[string]any)
			if cm == nil {
				continue
			}
			checks = append(checks, checkView{
				ID: str(cm, "id"), Type: str(cm, "type"),
				Expected: str(cm, "expected"), Observed: str(cm, "observed"),
				Result: str(cm, "result"), EvidenceRef: str(cm, "evidence_ref"),
			})
		}
	}
	type evView struct{ Ref, SHA256 string }
	var evs []evView
	if arr, ok := m["evidence"].([]any); ok {
		for _, ev := range arr {
			em, _ := ev.(map[string]any)
			if em == nil {
				continue
			}
			evs = append(evs, evView{Ref: str(em, "ref"), SHA256: str(em, "sha256")})
		}
	}
	type stepView struct {
		ID, Phase, PhaseClass, Command string
		ExitCode                       int
	}
	var steps []stepView
	if arr, ok := m["steps"].([]any); ok {
		for _, sv := range arr {
			sm, _ := sv.(map[string]any)
			if sm == nil {
				continue
			}
			code := 0
			if n, ok := sm["exit_code"].(float64); ok {
				code = int(n)
			}
			steps = append(steps, stepView{
				ID: str(sm, "id"), Phase: str(sm, "phase"),
				PhaseClass: proofPhaseClass(str(sm, "phase")),
				Command:    str(sm, "command"), ExitCode: code,
			})
		}
	}
	v := struct {
		Status, RunID, Source, Commit, Fingerprint        string
		WorkerKind, ImageDigest, PolicyDigest, AppVersion string
		Attested                                          bool
		Network                                           string
		Install, Launch, Behavior                         string
		Steps                                             []stepView
		Checks                                            []checkView
		Limitations                                       []string
		Evidence                                          []evView
	}{
		Status: str(m, "status"), RunID: str(m, "run_id"),
		Source: str(snap, "source"), Fingerprint: str(snap, "source_fingerprint"),
		WorkerKind: str(env, "worker_kind"), ImageDigest: str(env, "image_digest"),
		PolicyDigest: str(env, "policy_digest"), AppVersion: str(env, "app_version"),
		Network: str(env, "network_mode"),
		Install: str(lv, "install"), Launch: str(lv, "launch"), Behavior: str(lv, "behavior"),
		Steps: steps, Checks: checks, Limitations: strs(m["limitations"]), Evidence: evs,
	}
	if c, ok := snap["commit"].(string); ok {
		v.Commit = c
	} else {
		v.Commit = "(none)"
	}
	if at, ok := env["attested"].(bool); ok {
		v.Attested = at
	}
	tpl, err := ht.New("proof").Parse(proofHTMLTemplate)
	if err != nil {
		return err
	}
	return tpl.Execute(w, v)
}

func proofPhaseClass(phase string) string {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "install", "setup":
		return "install"
	case "launch", "start":
		return "launch"
	case "verify", "behavior", "oracle":
		return "verify"
	default:
		return "system"
	}
}

const proofHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RepoProof proof report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:72em;margin:2em auto;padding:0 1em;color:#111}
table{border-collapse:collapse;width:100%;margin:1em 0}
th,td{border:1px solid #999;padding:.3em .6em;text-align:left;vertical-align:top}
th{background:#eee}
code{font-family:Consolas,monospace;word-break:break-all}
.verdict{font-size:1.4em;font-weight:bold;padding:.4em .8em;border:2px solid #111;display:inline-block}
.mode{background:#fff8dc;border:1px solid #cc9;padding:.6em}
.filters{display:flex;flex-wrap:wrap;gap:.45em;margin:.8em 0}
.filters label{border:1px solid #999;border-radius:999px;padding:.25em .7em;cursor:pointer}
.filter-input{position:absolute;opacity:0;pointer-events:none}
.filter-input:focus-visible+label{outline:2px solid #06c;outline-offset:2px}
#show-install:checked~.report .phase-launch,#show-install:checked~.report .phase-verify,#show-install:checked~.report .phase-system{display:none}
#show-launch:checked~.report .phase-install,#show-launch:checked~.report .phase-verify,#show-launch:checked~.report .phase-system{display:none}
#show-verify:checked~.report .phase-install,#show-verify:checked~.report .phase-launch,#show-verify:checked~.report .phase-system{display:none}
#show-system:checked~.report .phase-install,#show-system:checked~.report .phase-launch,#show-system:checked~.report .phase-verify{display:none}
</style>
</head>
<body>
<input class="filter-input" type="radio" name="phase" id="show-all" checked>
<input class="filter-input" type="radio" name="phase" id="show-install">
<input class="filter-input" type="radio" name="phase" id="show-launch">
<input class="filter-input" type="radio" name="phase" id="show-verify">
<input class="filter-input" type="radio" name="phase" id="show-system">
<div class="report">
<h1>RepoProof proof report</h1>
<p><span class="verdict">{{.Status}}</span></p>
<p class="mode">Run {{.RunID}}. This verdict covers the exact behavior checked below, in the attested environment — nothing more.</p>
<h2>Timeline</h2>
<div class="filters" role="group" aria-label="Filter timeline by phase">
<label for="show-all">All</label><label for="show-install">Install</label><label for="show-launch">Launch</label><label for="show-verify">Verify</label><label for="show-system">System</label>
</div>
<h2>Snapshot</h2>
<table>
<tr><th>field</th><th>value</th></tr>
<tr><td>source</td><td><code>{{.Source}}</code></td></tr>
<tr><td>commit</td><td><code>{{.Commit}}</code></td></tr>
<tr><td>fingerprint</td><td><code>{{.Fingerprint}}</code></td></tr>
</table>
<h2>Environment</h2>
<table>
<tr><th>field</th><th>value</th></tr>
<tr><td>worker</td><td>{{.WorkerKind}}</td></tr>
<tr><td>image</td><td><code>{{.ImageDigest}}</code></td></tr>
<tr><td>attested</td><td>{{.Attested}}</td></tr>
<tr><td>network</td><td>{{.Network}}</td></tr>
<tr><td>policy</td><td><code>{{.PolicyDigest}}</code></td></tr>
<tr><td>app</td><td>{{.AppVersion}}</td></tr>
</table>
<h2>Levels</h2>
<table>
<tr><th>install</th><th>launch</th><th>behavior</th></tr>
<tr><td>{{.Install}}</td><td>{{.Launch}}</td><td>{{.Behavior}}</td></tr>
</table>
<h2>Steps (executed commands, evidence in store)</h2>
<table>
<tr><th>id</th><th>phase</th><th>command</th><th>exit</th></tr>
{{range .Steps}}<tr class="phase-{{.PhaseClass}}"><td>{{.ID}}</td><td>{{.Phase}}</td><td><code>{{.Command}}</code></td><td>{{.ExitCode}}</td></tr>{{else}}<tr><td colspan="4">(no steps ran)</td></tr>{{end}}
</table>
<h2>Checks</h2>
<table>
<tr><th>id</th><th>type</th><th>expected</th><th>observed</th><th>result</th><th>evidence</th></tr>
{{range .Checks}}<tr><td>{{.ID}}</td><td>{{.Type}}</td><td><code>{{.Expected}}</code></td><td><code>{{.Observed}}</code></td><td>{{.Result}}</td><td><code>{{.EvidenceRef}}</code></td></tr>{{else}}<tr><td colspan="6">(no checks — verdict cannot be VERIFIED)</td></tr>{{end}}
</table>
<h2>Limitations</h2>
<ul>{{range .Limitations}}<li>{{.}}</li>{{else}}<li>(none recorded)</li>{{end}}</ul>
<h2>Evidence</h2>
<table>
<tr><th>ref</th><th>sha256</th></tr>
{{range .Evidence}}<tr><td><code>{{.Ref}}</code></td><td><code>{{.SHA256}}</code></td></tr>{{else}}<tr><td colspan="2">(none)</td></tr>{{end}}
</table>
</div>
</body>
</html>
`
