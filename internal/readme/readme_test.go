package readme

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures", "readme-case", "README.md"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func TestFixtureCase(t *testing.T) {
	res, err := Parse("README.md", fixtureBytes(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Blocks != 5 {
		t.Fatalf("blocks = %d, want 5", res.Blocks)
	}
	if res.SkippedBlocks != 1 {
		t.Fatalf("skipped = %d, want 1 (python)", res.SkippedBlocks)
	}
	want := []CandidateStep{
		{ID: "readme-1", LineStart: 7, LineEnd: 7, FenceStart: 5, FenceEnd: 10, Language: "sh", Heading: "Install", Phase: PhaseInstall, Command: "npm install"},
		{ID: "readme-2", LineStart: 8, LineEnd: 9, FenceStart: 5, FenceEnd: 10, Language: "sh", Heading: "Install", Phase: PhaseInstall, Command: "npm run build --release"},
		{ID: "readme-3", LineStart: 15, LineEnd: 15, FenceStart: 14, FenceEnd: 16, Language: "console", Heading: "Run", Phase: PhaseLaunch, Command: "npm start"},
		{ID: "readme-4", LineStart: 26, LineEnd: 26, FenceStart: 24, FenceEnd: 28, Language: "", Heading: "Notes", Phase: PhaseUnknown, Command: "echo inner-is-content"},
		{ID: "readme-5", LineStart: 33, LineEnd: 33, FenceStart: 32, FenceEnd: 33, Language: "sh", Heading: "Tail", Phase: PhaseUnknown, Command: "echo unclosed runs to EOF", Unclosed: true},
	}
	if len(res.Steps) != len(want) {
		t.Fatalf("steps = %d, want %d: %+v", len(res.Steps), len(want), res.Steps)
	}
	for i, w := range want {
		w.SourceFile = "README.md"
		got := res.Steps[i]
		if got != w {
			t.Fatalf("step %d:\n got %+v\nwant %+v", i, got, w)
		}
	}
}

func TestCRLFLineNumbers(t *testing.T) {
	raw := "# T\r\n\r\n```sh\r\nnpm test\r\n```\r\n"
	res, err := Parse("README.md", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 {
		t.Fatalf("steps = %+v", res.Steps)
	}
	s := res.Steps[0]
	if s.LineStart != 4 || s.LineEnd != 4 || s.FenceStart != 3 || s.FenceEnd != 5 {
		t.Fatalf("CRLF spans wrong: %+v", s)
	}
	if strings.Contains(s.Command, "\r") {
		t.Fatalf("CR leaked into command: %q", s.Command)
	}
}

func TestTildeFence(t *testing.T) {
	raw := "~~~\nnpm run dev\n~~~\n"
	res, err := Parse("README.md", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 || res.Steps[0].Command != "npm run dev" {
		t.Fatalf("tilde fence: %+v", res.Steps)
	}
}

func TestShortCloseDoesNotEndLongFence(t *testing.T) {
	raw := "````\n```\nmake all\n````\n"
	res, err := Parse("README.md", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.Blocks != 1 {
		t.Fatalf("blocks = %d, want 1", res.Blocks)
	}
	if len(res.Steps) != 1 || res.Steps[0].Command != "make all" {
		t.Fatalf("steps = %+v", res.Steps)
	}
}

func TestMalformedAndTricky(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		steps int
	}{
		{"empty", "", 0},
		{"no fences", "# Hello\n\nJust text.\n", 0},
		{"unclosed fence only", "```sh\necho hi\n", 1},
		{"info with backtick ignored", "```sh `x`\nfoo\n```\n", 0},
		{"indented code block", "    ```sh\n    foo\n    ```\n", 1},
		{"hash tag not heading", "#tag\n\n```sh\nfoo\n```\n", 1},
		{"comment and blanks skipped", "```sh\n# c\n\nfoo\n\n# d\n```\n", 1},
		{"escaped backslash no continuation", "```sh\nfoo\\\\\nbar\n```\n", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Parse("README.md", []byte(tc.raw))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(res.Steps) != tc.steps {
				t.Fatalf("steps = %d, want %d: %+v", len(res.Steps), tc.steps, res.Steps)
			}
		})
	}
}

func TestIndentedQuotedAndSetextMarkdown(t *testing.T) {
	raw := "Install\n-------\n\n    python -m pip install -r requirements.txt\n    python app.py\n\n> ## Usage\n> ```sh\n> python app.py\n> ```\n"
	res, err := Parse("README.md", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.Blocks != 2 || len(res.Steps) != 3 {
		t.Fatalf("blocks=%d steps=%d: %+v", res.Blocks, len(res.Steps), res.Steps)
	}
	if got := res.Steps[0]; got.Heading != "Install" || got.Phase != PhaseInstall || got.LineStart != 4 || got.Command != "python -m pip install -r requirements.txt" {
		t.Fatalf("indented block mismatch: %+v", got)
	}
	if got := res.Steps[2]; got.Heading != "Usage" || got.Phase != PhaseLaunch || got.LineStart != 9 || got.Command != "python app.py" {
		t.Fatalf("quoted fence mismatch: %+v", got)
	}
}

func TestFencePreservesLiteralBlockquoteMarker(t *testing.T) {
	res, err := Parse("README.md", []byte("```sh\n> echo literal-marker\n```\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 || res.Steps[0].Command != "> echo literal-marker" {
		t.Fatalf("literal marker changed: %+v", res.Steps)
	}
}

func TestPhaseGuesses(t *testing.T) {
	for heading, want := range map[string]string{
		"Installation":  PhaseInstall,
		"Prerequisites": PhaseInstall,
		"Quick Start":   PhaseLaunch,
		"Usage":         PhaseLaunch,
		"Running tests": PhaseVerify,
		"Verification":  PhaseVerify,
		"Misc notes":    PhaseUnknown,
		"":              PhaseUnknown,
	} {
		if got := guessPhase(heading); got != want {
			t.Fatalf("guessPhase(%q) = %q, want %q", heading, got, want)
		}
	}
}

func TestOversizeRejected(t *testing.T) {
	big := make([]byte, MaxReadmeBytes+1)
	if _, err := Parse("README.md", big); err == nil {
		t.Fatal("expected error for oversize input")
	}
}

func TestIDsStableAndUnique(t *testing.T) {
	a, err := Parse("README.md", fixtureBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse("README.md", fixtureBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := range a.Steps {
		if a.Steps[i].ID != b.Steps[i].ID {
			t.Fatal("IDs unstable across runs")
		}
		if seen[a.Steps[i].ID] {
			t.Fatalf("duplicate ID %q", a.Steps[i].ID)
		}
		seen[a.Steps[i].ID] = true
	}
}
