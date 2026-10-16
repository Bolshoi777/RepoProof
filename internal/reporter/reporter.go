// Package reporter validates inspect JSON against the versioned schema
// contract and renders self-contained static HTML (G1-06, RP-015).
//
// HTML rules: no remote resources, no <script> tags at all, every
// untrusted string through html/template auto-escaping. Secret
// redaction beyond escaping belongs to G2-04 (RP-014), not here.
package reporter

import (
	"encoding/json"
	"fmt"
	ht "html/template"
	"io"
	"regexp"
	"sort"

	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/redact"
)

// MaxHTMLFiles caps rendered manifest rows; the JSON stays complete.
const MaxHTMLFiles = 500

// RequiredTopLevel mirrors specs/inspect.schema.json required[].
var RequiredTopLevel = []string{
	"version", "source", "commit", "source_fingerprint", "readme",
	"indicators", "stack", "support", "file_count", "files",
	"readme_steps", "limitations",
}

// RequiredStep mirrors the schema's readmeStep required[].
var RequiredStep = []string{
	"id", "source_file", "line_start", "line_end", "fence_start",
	"fence_end", "language", "heading", "phase", "command", "unclosed",
}

// StackEnum and SupportEnum mirror the schema enums.
var StackEnum = []string{
	"node", "python", "rust", "go", "java", "ruby",
	"php", "dotnet", "cpp", "multiple", "unknown",
}

var SupportEnum = []string{"supported", "unsupported", "undetermined"}

var (
	hex40 = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	hex64 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

func inSet(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func strField(m map[string]any, name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", fmt.Errorf("missing field %q", name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("field %q must be a string", name)
	}
	return s, nil
}

// ValidateInspectReport checks marshalled inspect JSON against the
// contract declared in specs/inspect.schema.json, stdlib only.
func ValidateInspectReport(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	for _, f := range RequiredTopLevel {
		if _, ok := m[f]; !ok {
			return fmt.Errorf("missing field %q", f)
		}
	}
	if v, err := strField(m, "version"); err != nil || v != "1" {
		return fmt.Errorf("version must be \"1\"")
	}
	if s, err := strField(m, "source"); err != nil || s == "" {
		return fmt.Errorf("source must be a non-empty string")
	}
	if c := m["commit"]; c != nil {
		s, ok := c.(string)
		if !ok || !hex40.MatchString(s) {
			return fmt.Errorf("commit must be null or 40-hex")
		}
	}
	fp, err := strField(m, "source_fingerprint")
	if err != nil || !hex64.MatchString(fp) {
		return fmt.Errorf("source_fingerprint must be 64-hex")
	}
	if r := m["readme"]; r != nil {
		if _, ok := r.(string); !ok {
			return fmt.Errorf("readme must be null or string")
		}
	}
	inds, ok := m["indicators"].([]any)
	if !ok {
		return fmt.Errorf("indicators must be an array")
	}
	for _, v := range inds {
		if _, ok := v.(string); !ok {
			return fmt.Errorf("indicators must be strings")
		}
	}
	st, err := strField(m, "stack")
	if err != nil || !inSet(StackEnum, st) {
		return fmt.Errorf("stack %q not in enum", st)
	}
	su, err := strField(m, "support")
	if err != nil || !inSet(SupportEnum, su) {
		return fmt.Errorf("support %q not in enum", su)
	}
	fc, ok := m["file_count"].(float64)
	if !ok || fc < 0 || fc != float64(int(fc)) {
		return fmt.Errorf("file_count must be a non-negative integer")
	}
	files, ok := m["files"].([]any)
	if !ok {
		return fmt.Errorf("files must be an array")
	}
	for i, fv := range files {
		em, ok := fv.(map[string]any)
		if !ok {
			return fmt.Errorf("files[%d] must be an object", i)
		}
		for _, f := range []string{"path", "kind", "size"} {
			if _, ok := em[f]; !ok {
				return fmt.Errorf("files[%d] missing %q", i, f)
			}
		}
		if _, err := strField(em, "path"); err != nil {
			return fmt.Errorf("files[%d]: %v", i, err)
		}
		kind, err := strField(em, "kind")
		if err != nil || (kind != "file" && kind != "symlink") {
			return fmt.Errorf("files[%d] bad kind", i)
		}
		if sz, ok := em["size"].(float64); !ok {
			return fmt.Errorf("files[%d] size must be a number", i)
		} else {
			_ = sz
		}
		for _, f := range []string{"sha256", "note"} {
			if v, ok := em[f]; ok {
				if _, ok := v.(string); !ok {
					return fmt.Errorf("files[%d].%s must be a string", i, f)
				}
			}
		}
	}
	if rs := m["readme_steps"]; rs != nil {
		steps, ok := rs.([]any)
		if !ok {
			return fmt.Errorf("readme_steps must be null or an array")
		}
		for i, sv := range steps {
			sm, ok := sv.(map[string]any)
			if !ok {
				return fmt.Errorf("readme_steps[%d] must be an object", i)
			}
			for _, f := range RequiredStep {
				if _, ok := sm[f]; !ok {
					return fmt.Errorf("readme_steps[%d] missing %q", i, f)
				}
			}
			for _, f := range []string{"id", "source_file", "language", "heading", "phase", "command"} {
				if _, err := strField(sm, f); err != nil {
					return fmt.Errorf("readme_steps[%d]: %v", i, err)
				}
			}
			for _, f := range []string{"line_start", "line_end", "fence_start", "fence_end"} {
				n, ok := sm[f].(float64)
				if !ok || n < 1 || n != float64(int(n)) {
					return fmt.Errorf("readme_steps[%d].%s must be an integer >= 1", i, f)
				}
			}
			if _, ok := sm["unclosed"].(bool); !ok {
				return fmt.Errorf("readme_steps[%d].unclosed must be a boolean", i)
			}
		}
	}
	lims, ok := m["limitations"].([]any)
	if !ok {
		return fmt.Errorf("limitations must be an array")
	}
	for _, v := range lims {
		if _, ok := v.(string); !ok {
			return fmt.Errorf("limitations must be strings")
		}
	}
	return nil
}

// MarshalAndValidate marshals an inspect report and validates the bytes,
// so every --json artefact is schema-checked by construction.
func MarshalAndValidate(rep *inspector.Report) ([]byte, error) {
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := ValidateInspectReport(raw); err != nil {
		return nil, fmt.Errorf("report violates schema contract: %w", err)
	}
	return append(raw, '\n'), nil
}

type fileView struct {
	Path  string
	Kind  string
	Size  int64
	Hash  string // full hex or note
	Short string // display form
}

type stepView struct {
	ID       string
	Phase    string
	Span     string
	Command  string
	Heading  string
	Unclosed bool
}

type htmlView struct {
	Source      string
	Commit      string
	Fingerprint string
	Stack       string
	Support     string
	Readme      string
	FileCount   int
	Indicators  []string
	Steps       []stepView
	Files       []fileView
	FilesShown  int
	FilesTotal  int
	Truncated   bool
	PlanSteps   []planner.PlanStep
	NeedsReview bool
	Reasons     []string
	Limitations []string
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RepoProof inspect report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:72em;margin:2em auto;padding:0 1em;color:#111}
table{border-collapse:collapse;width:100%;margin:1em 0}
th,td{border:1px solid #999;padding:.3em .6em;text-align:left;vertical-align:top}
th{background:#eee}
code{font-family:Consolas,monospace;word-break:break-all}
.mode{background:#fff8dc;border:1px solid #cc9;padding:.6em}
</style>
</head>
<body>
<h1>RepoProof inspect report</h1>
<p class="mode">inspect-only: nothing was executed. No verdict is claimed by this report.</p>
<h2>Snapshot</h2>
<table>
<tr><th>field</th><th>value</th></tr>
<tr><td>source</td><td><code>{{.Source}}</code></td></tr>
<tr><td>commit</td><td><code>{{.Commit}}</code></td></tr>
<tr><td>fingerprint</td><td><code>{{.Fingerprint}}</code></td></tr>
<tr><td>stack</td><td>{{.Stack}}</td></tr>
<tr><td>support</td><td>{{.Support}}</td></tr>
<tr><td>readme</td><td>{{.Readme}}</td></tr>
<tr><td>files</td><td>{{.FileCount}}</td></tr>
</table>
<h2>Indicators</h2>
<ul>{{range .Indicators}}<li><code>{{.}}</code></li>{{else}}<li>(none)</li>{{end}}</ul>
<h2>Candidate commands (data, not executed)</h2>
<table>
<tr><th>id</th><th>phase</th><th>lines</th><th>command</th><th>heading</th></tr>
{{range .Steps}}<tr><td>{{.ID}}</td><td>{{.Phase}}</td><td>{{.Span}}{{if .Unclosed}} (unclosed){{end}}</td><td><code>{{.Command}}</code></td><td>{{.Heading}}</td></tr>{{else}}<tr><td colspan="5">(none)</td></tr>{{end}}
</table>
<h2>Files (showing {{.FilesShown}} of {{.FilesTotal}})</h2>
{{if .Truncated}}<p>Display truncated; see JSON for the complete manifest.</p>{{end}}
<table>
<tr><th>path</th><th>kind</th><th>size</th><th>sha256 / note</th></tr>
{{range .Files}}<tr><td><code>{{.Path}}</code></td><td>{{.Kind}}</td><td>{{.Size}}</td><td title="{{.Hash}}"><code>{{.Short}}</code></td></tr>{{end}}
</table>
<h2>Candidate plan{{if .NeedsReview}} (needs review){{end}}</h2>
<ul>{{range .Reasons}}<li>{{.}}</li>{{else}}<li>Plan is complete and unambiguous; execution still requires explicit approval.</li>{{end}}</ul>
<table>
<tr><th>id</th><th>phase</th><th>command</th><th>cwd</th><th>timeout</th><th>network</th></tr>
{{range .PlanSteps}}<tr><td>{{.ID}}</td><td>{{.Phase}}</td><td><code>{{.Command}}</code></td><td>{{.CWD}}</td><td>{{.TimeoutSeconds}}s</td><td>{{.Network}}</td></tr>{{else}}<tr><td colspan="6">(no steps)</td></tr>{{end}}
</table>
<h2>Limitations</h2>
<ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>
</body>
</html>
`

// WriteHTML renders the snapshot and its candidate plan as a single
// self-contained page: no external resources, no script elements,
// all values template-escaped. Display strings additionally pass the
// redaction filter (G2-04); hashes and the JSON evidence path keep
// exact bytes so fingerprints stay verifiable.
func WriteHTML(snap *inspector.Snapshot, p *planner.Plan, w io.Writer) error {
	redacted := func(s string) string { return redact.RedactText(s) }
	redactedAll := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, s := range in {
			out = append(out, redacted(s))
		}
		return out
	}
	v := htmlView{
		Source:      redacted(snap.Source),
		Commit:      "(none)",
		Fingerprint: snap.Fingerprint,
		Stack:       string(snap.Stack),
		Support:     string(snap.Support),
		Readme:      "(none)",
		FileCount:   snap.FileCount,
		Indicators:  redactedAll(append([]string{}, snap.Indicators...)),
		NeedsReview: p.NeedsReview,
		Reasons:     redactedAll(append([]string{}, p.ReviewReasons...)),
		Limitations: redactedAll(append([]string{}, snap.Limitations...)),
	}
	for _, s := range p.Steps {
		s.Command = redacted(s.Command)
		v.PlanSteps = append(v.PlanSteps, s)
	}
	sort.Strings(v.Indicators)
	if snap.Commit != nil {
		v.Commit = *snap.Commit
	}
	if snap.Readme != nil {
		v.Readme = *snap.Readme
	}
	for _, s := range snap.ReadmeSteps {
		v.Steps = append(v.Steps, stepView{
			ID: s.ID, Phase: s.Phase,
			Span:    span(s.LineStart, s.LineEnd),
			Command: redacted(s.Command), Heading: redacted(s.Heading), Unclosed: s.Unclosed,
		})
	}
	v.FilesTotal = len(snap.Files)
	shown := snap.Files
	if len(shown) > MaxHTMLFiles {
		shown = shown[:MaxHTMLFiles]
		v.Truncated = true
	}
	v.FilesShown = len(shown)
	for _, e := range shown {
		hash := e.SHA256
		if hash == "" {
			hash = e.Note
		}
		short := hash
		if len(short) > 16 {
			short = short[:16] + "…"
		}
		v.Files = append(v.Files, fileView{
			Path: redacted(e.Path), Kind: e.Kind, Size: e.Size, Hash: hash, Short: short,
		})
	}
	tpl, err := ht.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tpl.Execute(w, v)
}

func span(start, end int) string {
	if start == end {
		return fmt.Sprintf("L%d", start)
	}
	return fmt.Sprintf("L%d-L%d", start, end)
}
