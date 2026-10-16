package inspector

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	p := filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures", name)
	if st, err := os.Stat(p); err != nil || !st.IsDir() {
		t.Fatalf("fixture missing: %s", p)
	}
	return p
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestInspectNodeFixture(t *testing.T) {
	rep, err := Inspect(fixturePath(t, "inspect-node"))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rep.Stack != StackNode {
		t.Fatalf("stack = %q, want node", rep.Stack)
	}
	if rep.Readme == nil || *rep.Readme != "README.md" {
		t.Fatalf("readme = %v, want README.md", rep.Readme)
	}
	if rep.Commit != nil {
		t.Fatal("commit must be nil until G1-02")
	}
	if !hex64.MatchString(rep.Fingerprint) {
		t.Fatalf("bad fingerprint %q", rep.Fingerprint)
	}
	if rep.FileCount != 3 {
		t.Fatalf("fileCount = %d, want 3", rep.FileCount)
	}
	found := false
	for _, ind := range rep.Indicators {
		if ind == "package.json" {
			found = true
		}
	}
	if !found {
		t.Fatalf("indicators missing package.json: %v", rep.Indicators)
	}
}

// TestFingerprintDeterministic inspects twice and requires byte-identical
// fingerprints (run-to-run stability on unchanged content).
func TestFingerprintDeterministic(t *testing.T) {
	a, err := Inspect(fixturePath(t, "inspect-node"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Inspect(fixturePath(t, "inspect-node"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("fingerprint unstable: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
}

func TestInspectPythonFixture(t *testing.T) {
	rep, err := Inspect(fixturePath(t, "inspect-python"))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rep.Stack != StackPython {
		t.Fatalf("stack = %q, want python", rep.Stack)
	}
}

func TestInspectUnknownStack(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Inspect(dir)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rep.Stack != StackUnknown {
		t.Fatalf("stack = %q, want unknown", rep.Stack)
	}
	if rep.Support != SupportUndetermined {
		t.Fatalf("support = %q, want undetermined", rep.Support)
	}
	if rep.Readme != nil {
		t.Fatalf("readme = %v, want nil", *rep.Readme)
	}
}

// TestHostileFixtureNeverExecutes is the G1-01 no-exec guard: a package.json
// with a postinstall hook that would create PWNED_MARKER.txt must be only
// read, never run.
func TestHostileFixtureNeverExecutes(t *testing.T) {
	fix := fixturePath(t, "inspect-hostile")
	marker := filepath.Join(fix, "PWNED_MARKER.txt")
	_ = os.Remove(marker) // start clean in case of a prior broken run

	rep, err := Inspect(fix)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rep.Stack != StackNode {
		t.Fatalf("stack = %q, want node (hostile package.json is still a signal)", rep.Stack)
	}
	if _, serr := os.Stat(marker); !os.IsNotExist(serr) {
		t.Fatalf("NO-EXEC VIOLATION: %s exists after inspect", marker)
	}
}

func TestMissingPathErrors(t *testing.T) {
	if _, err := Inspect(filepath.Join(t.TempDir(), "no-such-dir")); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestFilePathErrors(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(f); err == nil {
		t.Fatal("expected error for non-directory path")
	}
}

// TestSymlinkNotFollowed proves the inspector records a link to outside
// content without reading the target.
func TestSymlinkNotFollowed(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("outside-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "evil-link")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Inspect(dir)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rep.FileCount != 1 {
		t.Fatalf("fileCount = %d, want 1 (symlink is not a file)", rep.FileCount)
	}
	if len(rep.Files) != 2 {
		t.Fatalf("entries = %d, want 2 (file + symlink)", len(rep.Files))
	}
	var linkEntry *Entry
	for i := range rep.Files {
		if rep.Files[i].Path == "evil-link" {
			linkEntry = &rep.Files[i]
		}
		if rep.Files[i].Path == "secret.txt" {
			t.Fatal("outside target leaked into manifest")
		}
	}
	if linkEntry == nil {
		t.Fatal("symlink entry missing from manifest")
	}
	if linkEntry.Kind != "symlink" || linkEntry.SHA256 != "" {
		t.Fatalf("symlink entry must have no hash: %+v", linkEntry)
	}
}

// TestOversizeFileSkipped checks the hash cap path with a tiny limit.
func TestOversizeFileSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), []byte("0123456789abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := inspectWithCap(dir, 8)
	if err != nil {
		t.Fatalf("inspectWithCap: %v", err)
	}
	if len(rep.Files) != 1 {
		t.Fatalf("entries = %d, want 1", len(rep.Files))
	}
	if rep.Files[0].Note != "skipped:too-large" || rep.Files[0].SHA256 != "" {
		t.Fatalf("oversize entry wrong: %+v", rep.Files[0])
	}
}

// TestGitDirSkipped ensures VCS metadata does not pollute the fingerprint.
func TestGitDirSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rep.Files {
		if e.Path == ".git/HEAD" {
			t.Fatal(".git content leaked into manifest")
		}
	}
}

// TestInspectURLClonesPinnedCommit is the URL-slice integration proof:
// a GitHub URL inspects with a pinned 40-hex commit, and no clone
// litter remains afterwards. Requires git + github.com access.
func TestInspectURLClonesPinnedCommit(t *testing.T) {
	// Each package runs in a separate process under `go test ./...`.
	// Scanning the global Temp incorrectly counts another package's live
	// materialization as leaked. Keep the real Inspect/cleanup path, but
	// give this process a private temp root for ownership-aware assertions.
	root := t.TempDir()
	t.Setenv("TMP", root)
	t.Setenv("TEMP", root)
	t.Setenv("TMPDIR", root)
	before, err := cloneLitter()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Inspect("https://github.com/octocat/Hello-World")
	if err != nil {
		t.Fatalf("inspect URL: %v", err)
	}
	if rep.Commit == nil || !sha40.MatchString(*rep.Commit) {
		t.Fatalf("commit not pinned: %v", strOrNil(rep.Commit))
	}
	after, err := cloneLitter()
	if err != nil {
		t.Fatal(err)
	}
	// No NEW litter: set difference must be empty (pre-existing temp
	// dirs from other runs are not this test's business).
	seen := map[string]bool{}
	for _, n := range before {
		seen[n] = true
	}
	for _, n := range after {
		if !seen[n] {
			t.Fatalf("clone litter left behind: %v (before %v)", n, before)
		}
	}
}

func cloneLitter() ([]string, error) {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "repoproof-clone-") {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func strOrNil(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// TestInspectParsesReadmeSteps wires the G1-03 parser into inspect:
// candidate commands appear in the report as data with line spans.
func TestInspectParsesReadmeSteps(t *testing.T) {
	rep, err := Inspect(fixturePath(t, "readme-case"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ReadmeSteps) != 5 {
		t.Fatalf("readme steps = %d, want 5", len(rep.ReadmeSteps))
	}
	s := rep.ReadmeSteps[0]
	if s.Command != "npm install" || s.LineStart != 7 || s.SourceFile != "README.md" {
		t.Fatalf("first step wrong: %+v", s)
	}
}

// TestHostileReadmeStaysData proves hostile README content is extracted
// as inert data (with spans) and never executed.
func TestHostileReadmeStaysData(t *testing.T) {
	fix := fixturePath(t, "inspect-hostile")
	rep, err := Inspect(fix)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ReadmeSteps) != 1 {
		t.Fatalf("hostile steps = %+v", rep.ReadmeSteps)
	}
	if rep.ReadmeSteps[0].LineStart != 4 {
		t.Fatalf("hostile step span wrong: %+v", rep.ReadmeSteps[0])
	}
	if _, serr := os.Stat(filepath.Join(fix, "PWNED_MARKER.txt")); !os.IsNotExist(serr) {
		t.Fatal("NO-EXEC VIOLATION after readme parsing")
	}
}

// TestStackSupportMatrix is the G1-04 classification matrix: each fixture
// must map to an exact (stack, support) pair, with unsupported stacks
// named explicitly instead of collapsing into unknown.
func TestStackSupportMatrix(t *testing.T) {
	cases := []struct {
		fixture string
		stack   Stack
		support Support
	}{
		{"inspect-node", StackNode, SupportSupported},
		{"inspect-python", StackPython, SupportSupported},
		{"inspect-hostile", StackNode, SupportSupported},
		{"readme-case", StackUnknown, SupportUndetermined},
		{"unsupported-rust", StackRust, SupportUnsupported},
		{"unsupported-go", StackGo, SupportUnsupported},
		{"mixed-stack", StackMultiple, SupportUndetermined},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			rep, err := Inspect(fixturePath(t, tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Stack != tc.stack || rep.Support != tc.support {
				t.Fatalf("got (%q, %q), want (%q, %q)",
					rep.Stack, rep.Support, tc.stack, tc.support)
			}
		})
	}
}

// TestClassifyUnit pins the pure function on every branch, including
// multi-unsupported and supported-mixed families with no fixture on disk.
func TestClassifyUnit(t *testing.T) {
	single := func(st Stack) map[Stack]bool { return map[Stack]bool{st: true} }
	cases := []struct {
		name    string
		in      map[Stack]bool
		stack   Stack
		support Support
	}{
		{"empty", map[Stack]bool{}, StackUnknown, SupportUndetermined},
		{"node", single(StackNode), StackNode, SupportSupported},
		{"python", single(StackPython), StackPython, SupportSupported},
		{"rust", single(StackRust), StackRust, SupportUnsupported},
		{"dotnet", single(StackDotnet), StackDotnet, SupportUnsupported},
		{"node+python", map[Stack]bool{StackNode: true, StackPython: true}, StackMultiple, SupportSupported},
		{"rust+go", map[Stack]bool{StackRust: true, StackGo: true}, StackMultiple, SupportUnsupported},
		{"node+rust", map[Stack]bool{StackNode: true, StackRust: true}, StackMultiple, SupportUndetermined},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stack, support := classify(tc.in)
			if stack != tc.stack || support != tc.support {
				t.Fatalf("got (%q, %q), want (%q, %q)", stack, support, tc.stack, tc.support)
			}
		})
	}
}

// TestDotnetSuffixMatch covers variable-name project files (*.csproj).
func TestDotnetSuffixMatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.csproj"), []byte("<Project/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Stack != StackDotnet || rep.Support != SupportUnsupported {
		t.Fatalf("got (%q, %q), want (dotnet, unsupported)", rep.Stack, rep.Support)
	}
}
