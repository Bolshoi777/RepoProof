package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/readme"
)

func inspectFixture(t *testing.T, name string) *inspector.Report {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	rep, err := inspector.Inspect(filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func schemaDoc(t *testing.T) map[string]any {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "specs", "inspect.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	return doc
}

func strSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

// TestValidatorMatchesSchema ties the stdlib validator to the schema file:
// required sets and enums must be identical in both places.
func TestValidatorMatchesSchema(t *testing.T) {
	doc := schemaDoc(t)
	if got := strSlice(doc["required"]); !sameSet(got, RequiredTopLevel) {
		t.Fatalf("top required mismatch:\n schema=%v\n code=%v", got, RequiredTopLevel)
	}
	props := doc["properties"].(map[string]any)
	stackEnum := strSlice(props["stack"].(map[string]any)["enum"])
	if !sameSet(stackEnum, StackEnum) {
		t.Fatalf("stack enum mismatch: %v vs %v", stackEnum, StackEnum)
	}
	supportEnum := strSlice(props["support"].(map[string]any)["enum"])
	if !sameSet(supportEnum, SupportEnum) {
		t.Fatalf("support enum mismatch: %v vs %v", supportEnum, SupportEnum)
	}
	defs := doc["$defs"].(map[string]any)
	stepReq := strSlice(defs["readmeStep"].(map[string]any)["required"])
	if !sameSet(stepReq, RequiredStep) {
		t.Fatalf("step required mismatch: %v vs %v", stepReq, RequiredStep)
	}
}

func TestMarshalAndValidateRoundTrip(t *testing.T) {
	for _, fix := range []string{"inspect-node", "readme-case", "unsupported-rust", "xss-readme"} {
		rep := inspectFixture(t, fix)
		raw, err := MarshalAndValidate(rep)
		if err != nil {
			t.Fatalf("%s: %v", fix, err)
		}
		if err := ValidateInspectReport(raw); err != nil {
			t.Fatalf("%s revalidate: %v", fix, err)
		}
	}
}

func TestValidateRejectsTampered(t *testing.T) {
	mkStep := func() map[string]any {
		return map[string]any{
			"id": "x", "source_file": "R", "line_start": 0, "line_end": 0,
			"fence_start": 1, "fence_end": 1, "language": "", "heading": "",
			"phase": "u", "command": "c", "unclosed": false,
		}
	}
	cases := []struct {
		name   string
		mutate func(m map[string]any)
	}{
		{"bad fingerprint", func(m map[string]any) { m["source_fingerprint"] = "zzz" }},
		{"bad stack", func(m map[string]any) { m["stack"] = "cobol" }},
		{"bad support", func(m map[string]any) { m["support"] = "maybe" }},
		{"bad commit", func(m map[string]any) { m["commit"] = "123" }},
		{"missing limitations", func(m map[string]any) { delete(m, "limitations") }},
		{"bad line number", func(m map[string]any) { m["readme_steps"] = []any{mkStep()} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := inspectFixture(t, "inspect-node")
			raw, err := MarshalAndValidate(rep)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			tc.mutate(m)
			bad, _ := json.Marshal(m)
			if err := ValidateInspectReport(bad); err == nil {
				t.Fatalf("tampered doc accepted (%s)", tc.name)
			}
		})
	}
}

func TestHTMLXSSNeutralized(t *testing.T) {
	rep := inspectFixture(t, "xss-readme")
	var sb strings.Builder
	if err := WriteHTML(&rep.Snapshot, planner.Build(&rep.Snapshot), &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if strings.Contains(out, "<script") {
		t.Fatal("raw <script present in HTML output")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("escaped payload missing: heading was not rendered as text")
	}
	if strings.Contains(out, "<img src=x") {
		t.Fatal("raw <img present in HTML output")
	}
	if !strings.Contains(out, "&lt;img") {
		t.Fatal("escaped command payload missing")
	}
}

func TestHTMLSelfContained(t *testing.T) {
	rep := inspectFixture(t, "readme-case")
	var sb strings.Builder
	if err := WriteHTML(&rep.Snapshot, planner.Build(&rep.Snapshot), &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, forbidden := range []string{"<script", "src=\"http", "href=\"http", "<link"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("HTML references external/active content: %q", forbidden)
		}
	}
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatal("missing doctype")
	}
	if !strings.Contains(out, "needs review") && !strings.Contains(out, "needs_review") {
		t.Fatal("plan review state not rendered")
	}
}

func TestHTMLRedactsSecretsKeepsJSONExact(t *testing.T) {
	rep := inspectFixture(t, "redaction-readme")
	var sb strings.Builder
	if err := WriteHTML(&rep.Snapshot, planner.Build(&rep.Snapshot), &sb); err != nil {
		t.Fatal(err)
	}
	html := sb.String()
	for _, leaked := range []string{"FAKE_KEY_FOR_REDACTION_TEST", "FAKE_GITHUB_TOKEN_FOR_REDACTION_TEST"} {
		if strings.Contains(html, leaked) {
			t.Fatalf("HTML leaked %q", leaked)
		}
	}
	if !strings.Contains(html, "[redacted") {
		t.Fatal("HTML missing redaction placeholders")
	}
	raw, err := MarshalAndValidate(rep)
	if err != nil {
		t.Fatal(err)
	}
	// JSON evidence keeps exact bytes: hashes stay verifiable.
	for _, kept := range []string{"FAKE_KEY_FOR_REDACTION_TEST", "FAKE_GITHUB_TOKEN_FOR_REDACTION_TEST"} {
		if !strings.Contains(string(raw), kept) {
			t.Fatalf("JSON evidence must keep exact bytes, lost %q", kept)
		}
	}
}

// TestRendererWithMalformedInput is security case 12: corrupt/odd
// bytes must not break the renderer or become executable markup.
func TestRendererWithMalformedInput(t *testing.T) {
	for _, raw := range [][]byte{
		{0xff, 0xfe, 0x00, 0x41},
		[]byte("# T\xe2\x28\xa1 broken utf8\n\n```sh\necho \xff\xfe\n```\n"),
		[]byte("no trailing newline ```sh"),
	} {
		res, err := readme.Parse("README.md", raw)
		if err != nil {
			t.Fatalf("parse must not fail on malformed input: %v", err)
		}
		_ = res
	}
	snap := inspectFixture(t, "xss-readme")
	var sb strings.Builder
	if err := WriteHTML(&snap.Snapshot, planner.Build(&snap.Snapshot), &sb); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sb.String(), "<script") {
		t.Fatal("malformed input produced executable markup")
	}
}

func TestHTMLTruncatesLongManifest(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < MaxHTMLFiles+10; i++ {
		name := filepath.Join(dir, fmt.Sprintf("file-%04d.txt", i))
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := inspector.Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	if err := WriteHTML(&rep.Snapshot, planner.Build(&rep.Snapshot), &sb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "Display truncated") {
		t.Fatal("long manifest must render a truncation note")
	}
	if _, err := MarshalAndValidate(rep); err != nil {
		t.Fatalf("JSON must stay complete: %v", err)
	}
}
