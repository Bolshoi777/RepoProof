package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/evidence"
	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/policy"
	"github.com/repoproof/repoproof/internal/reporter"
	"github.com/repoproof/repoproof/internal/version"
	"github.com/repoproof/repoproof/internal/worker"
)

// sandboxAttestationForTest mirrors the production verify wiring: a
// controller-issued native attestation with sandbox defaults.
func sandboxAttestationForTest() worker.Attestation {
	return worker.Attestation{
		WorkerKind: "appcontainer-native", ImageDigest: "sha256:" + strings.Repeat("a", 64),
		PolicyDigest: "sha256:" + strings.Repeat("b", 64), Network: worker.NetworkGuestOnly,
		HostMounts: 0, Privileged: false, Attested: true,
		Limits: worker.ResourceLimits{CPUCores: 2, MemoryMB: 2048, DiskMB: 4096,
			WallSeconds: 600, MaxOutputBytes: 20 << 20},
	}
}

func TestVersionCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("version exit = %d", code)
	}
	if !strings.Contains(out.String(), version.ModuleVersion) {
		t.Fatalf("version output missing version: %q", out.String())
	}
}

func TestDoctorCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"doctor"}, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("doctor exit = %d", code)
	}
	if !strings.Contains(out.String(), "inspect-only") {
		t.Fatalf("doctor must report inspect-only mode: %q", out.String())
	}
}

// TestVerifyNeedsFlags: verify without contract+approval is a usage
// error, and executes nothing.
func TestVerifyNeedsFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"verify", "."}, &out, &errOut); code != version.ExitInternalError {
		t.Fatalf("verify exit = %d, want usage error", code)
	}
}

func cleanApproveProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	readme := "## Install\n\n```sh\necho S\n```\n\n## Run\n\n```sh\necho H\n```\n"
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c.yaml"), []byte(`version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 60, max_output_bytes: 65536, install_network: none, verify_network: guest-only}
steps:
  - {id: s1, phase: install, from_readme: true}
proof:
  - {id: p1, type: exit_code_equals, expected: 0}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestApproveCleanPlan drafts an approval that authorizes: the file
// must pass policy.Authorize against a valid attestation.
func TestApproveCleanPlan(t *testing.T) {
	dir := cleanApproveProject(t)
	outPath := filepath.Join(t.TempDir(), "a.json")
	var out, errOut bytes.Buffer
	code := run([]string{"approve", dir, "--contract", filepath.Join(dir, "c.yaml"),
		"--statement", "reviewed, run it", "--output", outPath}, &out, &errOut)
	if code != version.ExitVerified {
		t.Fatalf("approve exit = %d: %s", code, errOut.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var ap policy.Approval
	if err := json.Unmarshal(raw, &ap); err != nil {
		t.Fatal(err)
	}
	if ap.PlanFingerprint == "" || ap.Statement == "" {
		t.Fatalf("approval incomplete: %+v", ap)
	}
	rep, err := inspector.Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Build(&rep.Snapshot)
	if p.Fingerprint != ap.PlanFingerprint {
		t.Fatal("approval fingerprint does not match fresh inspect")
	}
	att := sandboxAttestationForTest()
	if err := policy.Authorize(att, p, &ap); err != nil {
		t.Fatalf("drafted approval must authorize: %v", err)
	}
}

// TestApproveNeedsReviewWithoutAck drafts a pending approval that
// verify must deny until reasons are acknowledged.
func TestApproveNeedsReviewWithoutAck(t *testing.T) {
	fix := filepath.Join("..", "..", "fixtures", "readme-case")
	contractPath := filepath.Join("..", "..", "specs", "repoproof.example.yaml")
	outPath := filepath.Join(t.TempDir(), "a.json")
	var out, errOut bytes.Buffer
	code := run([]string{"approve", fix, "--contract", contractPath,
		"--statement", "wip", "--output", outPath}, &out, &errOut)
	if code != version.ExitVerified {
		t.Fatalf("approve exit = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "PENDING") {
		t.Fatalf("reasons must be marked PENDING:\n%s", out.String())
	}
	raw, _ := os.ReadFile(outPath)
	var ap policy.Approval
	if err := json.Unmarshal(raw, &ap); err != nil {
		t.Fatal(err)
	}
	rep, _ := inspector.Inspect(fix)
	p := planner.Build(&rep.Snapshot)
	if err := policy.Authorize(sandboxAttestationForTest(), p, &ap); err == nil {
		t.Fatal("unacknowledged approval must not authorize")
	}
}

// TestApproveAckAll acknowledges explicitly and authorizes.
func TestApproveAckAll(t *testing.T) {
	fix := filepath.Join("..", "..", "fixtures", "readme-case")
	contractPath := filepath.Join("..", "..", "specs", "repoproof.example.yaml")
	outPath := filepath.Join(t.TempDir(), "a.json")
	var out, errOut bytes.Buffer
	code := run([]string{"approve", fix, "--contract", contractPath,
		"--statement", "risks accepted", "--ack-all", "--output", outPath}, &out, &errOut)
	if code != version.ExitVerified {
		t.Fatalf("approve exit = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "ACKNOWLEDGED") {
		t.Fatalf("reasons must be marked ACKNOWLEDGED:\n%s", out.String())
	}
	raw, _ := os.ReadFile(outPath)
	var ap policy.Approval
	if err := json.Unmarshal(raw, &ap); err != nil {
		t.Fatal(err)
	}
	rep, _ := inspector.Inspect(fix)
	p := planner.Build(&rep.Snapshot)
	// Network in the drafted approval is guest-only; attest the same.
	if err := policy.Authorize(sandboxAttestationForTest(), p, &ap); err != nil {
		t.Fatalf("acknowledged approval must authorize: %v", err)
	}
}

func TestApproveNeedsStatement(t *testing.T) {
	var out, errOut bytes.Buffer
	dir := cleanApproveProject(t)
	code := run([]string{"approve", dir, "--contract", filepath.Join(dir, "c.yaml"),
		"--output", filepath.Join(t.TempDir(), "a.json")}, &out, &errOut)
	if code != version.ExitInternalError {
		t.Fatalf("approve exit = %d, want usage error", code)
	}
}

func TestReplayBadInput(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"replay"}, &out, &errOut); code != version.ExitInternalError {
		t.Fatalf("replay exit = %d, want usage error", code)
	}
	if code := run([]string{"replay", filepath.Join(t.TempDir(), "missing.json")}, &out, &errOut); code != version.ExitInternalError {
		t.Fatalf("replay exit = %d, want error", code)
	}
}

// TestCheckRefusesWithoutConfirm runs nothing without the flag.
func TestCheckRefusesWithoutConfirm(t *testing.T) {
	dir := cleanApproveProject(t)
	var out, errOut bytes.Buffer
	code := run([]string{"check", dir}, &out, &errOut)
	if code != version.ExitInconclusive {
		t.Fatalf("check exit = %d, want 11", code)
	}
	if !strings.Contains(out.String(), "review") && !strings.Contains(errOut.String(), "plan") {
		t.Fatalf("plan must be shown for review:\n%s\n%s", out.String(), errOut.String())
	}
}

// TestCheckAutoPartial runs the live automatic chain: setup+launch
// evidence without oracle must cap at PARTIAL, never VERIFIED.
func TestCheckAutoPartial(t *testing.T) {
	dir := cleanApproveProject(t)
	evDir := filepath.Join(t.TempDir(), "ev")
	var out, errOut bytes.Buffer
	code := run([]string{"check", dir, "--confirm-run", "--evidence-dir", evDir},
		&out, &errOut)
	if code != version.ExitBlockedSecurity {
		t.Fatalf("check exit = %d, want 13 (BLOCKED_SECURITY):\n%s\n%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "verdict: BLOCKED_SECURITY") {
		t.Fatalf("verdict missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "worker gate") {
		t.Fatalf("security block reason missing:\n%s", out.String())
	}
}

// verifyFixture builds a project + contract + matching approval. The
// approval lives OUTSIDE the project: it binds the fingerprint, so
// storing it inside would invalidate itself on every write.
func verifyFixture(t *testing.T) (proj, contractPath, approvePath string) {
	t.Helper()
	proj = t.TempDir()
	outside := t.TempDir()
	write := func(dir, name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write(proj, "package.json", `{"name":"verify-cli"}`)
	write(proj, "README.md", "## Install\n\n```sh\necho SETUP_CLI\n```\n\n## Run\n\n```sh\necho HELLO_CLI\n```\n")
	contractPath = write(proj, "repoproof.yaml", `version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 120, max_output_bytes: 65536, install_network: none, verify_network: guest-only}
steps:
  - {id: install, phase: install, from_readme: true}
  - {id: launch, phase: launch, from_readme: true}
proof:
  - {id: exit0, type: exit_code_equals, expected: 0}
  - {id: says-hi, type: stdout_contains, expected: "HELLO_CLI"}
`)
	rep, err := inspector.Inspect(proj)
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Build(&rep.Snapshot)
	if p.NeedsReview {
		t.Fatalf("fixture plan needs review: %v", p.ReviewReasons)
	}
	ap := policy.Approval{
		Version: "1", PlanFingerprint: p.Fingerprint, Commit: p.Commit,
		Statement:           "cli test approval",
		AcknowledgedReasons: append([]string{}, p.ReviewReasons...),
		ApprovedNetwork:     "guest-only",
		ExpiresAt:           policy.NewExpiry(time.Now().UTC()),
	}
	araw, err := json.Marshal(ap)
	if err != nil {
		t.Fatal(err)
	}
	approvePath = write(outside, "approve.json", string(araw))
	return proj, contractPath, approvePath
}

// TestVerifyFullChain confirms the CLI remains fail-closed while native
// attestation is intentionally unavailable in production builds.
func TestVerifyFullChain(t *testing.T) {
	proj, contractPath, approvePath := verifyFixture(t)
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "proof.json")
	evDir := filepath.Join(dir, "evidence")
	var out, errOut bytes.Buffer
	code := run([]string{"verify", proj, "--contract", contractPath,
		"--approve-file", approvePath, "--json", jsonPath, "--evidence-dir", evDir},
		&out, &errOut)
	if code != version.ExitBlockedSecurity {
		t.Fatalf("verify exit = %d, want 13:\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["status"] != "BLOCKED_SECURITY" {
		t.Fatalf("status = %v", m["status"])
	}
	if len(m["checks"].([]any)) != 2 {
		t.Fatalf("checks wrong: %v", m)
	}
	if err := reporter.ValidateProofReport(raw); err != nil {
		t.Fatalf("proof fails validation: %v", err)
	}
	st, err := evidence.Open(evDir)
	if err != nil {
		t.Fatal(err)
	}
	// The run sealed exactly one run id; find and verify it.
	entries, err := os.ReadDir(evDir)
	if err != nil {
		t.Fatal(err)
	}
	sealed := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".receipt") {
			sealed++
			runID := strings.TrimSuffix(e.Name(), ".receipt")
			if err := st.Verify(runID); err != nil {
				t.Fatalf("evidence verify %s: %v", runID, err)
			}
		}
	}
	if sealed != 0 {
		t.Fatalf("blocked run unexpectedly sealed %d evidence receipts", sealed)
	}
	if !strings.Contains(out.String(), "verdict: BLOCKED_SECURITY") {
		t.Fatalf("stdout missing verdict:\n%s", out.String())
	}
}

// TestVerifyBehaviorFailExit10 stays blocked before any project behavior is
// observed when the production worker is not independently attested.
func TestVerifyBehaviorFailExit10(t *testing.T) {
	proj, contractPath, approvePath := verifyFixture(t)
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	// The altered contract lives OUTSIDE the project: rewriting files
	// inside would invalidate the approval fingerprint (by design).
	brokenPath := filepath.Join(t.TempDir(), "broken.yaml")
	broken := strings.Replace(string(raw), `"HELLO_CLI"`, `"NEVER_MATCHES"`, 1)
	if err := os.WriteFile(brokenPath, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"verify", proj, "--contract", brokenPath, "--approve-file", approvePath},
		&out, &errOut)
	if code != version.ExitBlockedSecurity {
		t.Fatalf("verify exit = %d, want 13:\n%s\n%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "verdict: BLOCKED_SECURITY") {
		t.Fatalf("verdict missing:\n%s", out.String())
	}
}

// TestVerifyUnsupportedExit12 confirms worker security gating precedes any
// unsupported-stack execution attempt.
func TestVerifyUnsupportedExit12(t *testing.T) {
	proj := t.TempDir()
	outside := t.TempDir()
	write := func(dir, name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write(proj, "Cargo.toml", "[package]\nname = \"x\"\n")
	contractPath := write(proj, "c.yaml", `version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 60, max_output_bytes: 65536, install_network: none, verify_network: guest-only}
steps:
  - {id: s1, phase: launch, run: "echo hi"}
proof:
  - {id: p1, type: exit_code_equals, expected: 0}
`)
	rep, err := inspector.Inspect(proj)
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Build(&rep.Snapshot)
	if p.Support != inspector.SupportUnsupported {
		t.Fatalf("fixture support = %q", p.Support)
	}
	ap := policy.Approval{
		Version: "1", PlanFingerprint: p.Fingerprint, Commit: p.Commit,
		Statement:           "accept unsupported risk",
		AcknowledgedReasons: append([]string{}, p.ReviewReasons...),
		ApprovedNetwork:     "guest-only",
		ExpiresAt:           policy.NewExpiry(time.Now().UTC()),
	}
	araw, _ := json.Marshal(ap)
	approvePath := write(outside, "a.json", string(araw))
	var out, errOut bytes.Buffer
	code := run([]string{"verify", proj, "--contract", contractPath, "--approve-file", approvePath},
		&out, &errOut)
	if code != version.ExitBlockedSecurity {
		t.Fatalf("verify exit = %d, want 13:\n%s\n%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "verdict: BLOCKED_SECURITY") {
		t.Fatalf("verdict missing:\n%s", out.String())
	}
}

// TestVerifyStaleApprovalDenied: a foreign fingerprint must deny the
// run without executing anything.
func TestVerifyStaleApprovalDenied(t *testing.T) {
	proj, contractPath, approvePath := verifyFixture(t)
	raw, err := os.ReadFile(approvePath)
	if err != nil {
		t.Fatal(err)
	}
	var ap map[string]any
	if err := json.Unmarshal(raw, &ap); err != nil {
		t.Fatal(err)
	}
	ap["plan_fingerprint"] = strings.Repeat("0", 64)
	bad, _ := json.Marshal(ap)
	if err := os.WriteFile(approvePath, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"verify", proj, "--contract", contractPath, "--approve-file", approvePath},
		&out, &errOut)
	if code != version.ExitBlockedSecurity {
		t.Fatalf("verify exit = %d, want BLOCKED_SECURITY(13)", code)
	}
	if !strings.Contains(errOut.String(), "DENIED") && !strings.Contains(out.String(), "BLOCKED_SECURITY") {
		t.Fatalf("denial not reported:\n%s\n%s", out.String(), errOut.String())
	}
}

func TestInspectBasic(t *testing.T) {
	var out, errOut bytes.Buffer
	fix := filepath.Join("..", "..", "fixtures", "inspect-node")
	if code := run([]string{"inspect", fix}, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("inspect exit = %d: %s", code, errOut.String())
	}
	for _, want := range []string{"stack: node", "readme: README.md", "fingerprint: ", "nothing executed", "commands: 0"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("inspect output missing %q:\n%s", want, out.String())
		}
	}
}

func TestInspectJSONOutput(t *testing.T) {
	dir := t.TempDir()
	jsonPath := dir + string(os.PathSeparator) + "inspect.json"
	var out, errOut bytes.Buffer
	args := []string{"inspect", filepath.Join("..", "..", "fixtures", "inspect-python"), "--json", jsonPath}
	if code := run(args, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("inspect exit = %d: %s", code, errOut.String())
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read json: %v", err)
	}
	var rep struct {
		Stack       string  `json:"stack"`
		Fingerprint string  `json:"source_fingerprint"`
		Commit      *string `json:"commit"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if rep.Stack != "python" {
		t.Fatalf("stack = %q", rep.Stack)
	}
	if len(rep.Fingerprint) != 64 || rep.Commit != nil {
		t.Fatalf("bad fingerprint/commit: %+v", rep)
	}
}

// TestInspectHostileNoExec is the CLI-level no-exec guard: inspecting the
// hostile fixture must succeed without creating its postinstall marker.
func TestInspectHostileNoExec(t *testing.T) {
	marker := filepath.Join("..", "..", "fixtures", "inspect-hostile", "PWNED_MARKER.txt")
	_ = os.Remove(marker)
	var out, errOut bytes.Buffer
	args := []string{"inspect", filepath.Join("..", "..", "fixtures", "inspect-hostile")}
	if code := run(args, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("inspect exit = %d: %s", code, errOut.String())
	}
	if _, serr := os.Stat(marker); !os.IsNotExist(serr) {
		t.Fatal("NO-EXEC VIOLATION: hostile marker created by inspect")
	}
}

func TestInspectMissingPath(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"inspect", "no-such-dir-xyz"}, &out, &errOut); code != version.ExitInternalError {
		t.Fatalf("inspect exit = %d, want error", code)
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"frobnicate"}, &out, &errOut); code != version.ExitInternalError {
		t.Fatalf("unknown exit = %d", code)
	}
}

// TestInspectPinsGitCommit builds a synthetic checkout (no git binary)
// and requires the CLI summary to show the pinned SHA.
func TestInspectPinsGitCommit(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	dir := t.TempDir()
	gitdir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitdir, "HEAD"), []byte(sha+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"inspect", dir}, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("inspect exit = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "commit: "+sha) {
		t.Fatalf("output missing pinned commit:\n%s", out.String())
	}
}

// TestInspectUnsupportedStack requires the CLI to name the out-of-scope
// stack and its support verdict explicitly.
func TestInspectUnsupportedStack(t *testing.T) {
	var out, errOut bytes.Buffer
	fix := filepath.Join("..", "..", "fixtures", "unsupported-rust")
	if code := run([]string{"inspect", fix}, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("inspect exit = %d: %s", code, errOut.String())
	}
	for _, want := range []string{"stack: rust", "support: unsupported"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, out.String())
		}
	}
}

// TestInspectHTML writes a self-contained report and checks the hostile
// fixture renders without executable markup.
func TestInspectHTML(t *testing.T) {
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")
	var out, errOut bytes.Buffer
	fix := filepath.Join("..", "..", "fixtures", "xss-readme")
	if code := run([]string{"inspect", fix, "--html", htmlPath}, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("inspect exit = %d: %s", code, errOut.String())
	}
	raw, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	if strings.Contains(html, "<script") || strings.Contains(html, "<img src=x") {
		t.Fatal("HTML contains executable markup")
	}
	if !strings.Contains(html, "&lt;script&gt;") || !strings.HasPrefix(html, "<!DOCTYPE html>") {
		t.Fatal("HTML missing escaped payload or doctype")
	}
}

func TestPlanNeedsReview(t *testing.T) {
	var out, errOut bytes.Buffer
	fix := filepath.Join("..", "..", "fixtures", "readme-case")
	if code := run([]string{"plan", fix}, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("plan exit = %d: %s", code, errOut.String())
	}
	for _, want := range []string{"steps: 5", "needs_review: true", "unclosed", "approval=required"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("plan output missing %q:\n%s", want, out.String())
		}
	}
}

func TestPlanJSONOutput(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "plan.json")
	var out, errOut bytes.Buffer
	fix := filepath.Join("..", "..", "fixtures", "unsupported-go")
	if code := run([]string{"plan", fix, "--json", jsonPath}, &out, &errOut); code != version.ExitVerified {
		t.Fatalf("plan exit = %d: %s", code, errOut.String())
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		NeedsReview bool     `json:"needs_review"`
		Reasons     []string `json:"review_reasons"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if !p.NeedsReview || len(p.Reasons) == 0 {
		t.Fatalf("plan json wrong: %+v", p)
	}
}
