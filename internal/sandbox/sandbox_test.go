package sandbox

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestValidProfileName(t *testing.T) {
	for _, ok := range []string{"repoproof-n1-123", "a.b-c", "X"} {
		if err := ValidProfileName(ok); err != nil {
			t.Fatalf("valid name rejected %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a/b", `a\b`, "a b", "a*b", "../x", "a:b", strings.Repeat("a", 65)} {
		if err := ValidProfileName(bad); err == nil {
			t.Fatalf("dangerous name accepted %q", bad)
		}
	}
}

func TestIcaclsGrantArgs(t *testing.T) {
	args, err := IcaclsGrantArgs(`C:\tmp\ws`, "S-1-15-2-123")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, `"*S-1-15-2-123:(OI)(CI)F"`) && !strings.Contains(joined, `*S-1-15-2-123:(OI)(CI)F`) {
		t.Fatalf("grant shape wrong: %v", args)
	}
	if _, err := IcaclsGrantArgs("", "S-1-1"); err == nil {
		t.Fatal("empty workspace must fail")
	}
	if _, err := IcaclsGrantArgs(`C:\tmp`, "not-a-sid"); err == nil {
		t.Fatal("non-SID must fail")
	}
}

func TestProbeSupportSmoke(t *testing.T) {
	rep := ProbeSupport()
	t.Logf("native support: supported=%v reason=%q", rep.Supported, rep.Reason)
}

func TestSanitizeEnv(t *testing.T) {
	ws := `C:\sbox\run1`
	env := SanitizeEnv(ws, []string{`C:\tools\go\bin`}, map[string]string{"lang": "en"})
	joined := "\x00" + strings.Join(env, "\x00")
	if !strings.Contains(joined, "\x00PATH=") {
		t.Fatal("PATH missing")
	}
	// Parent environment must not leak: only our base + extras.
	for _, kv := range env {
		if strings.HasPrefix(kv, "USERPROFILE=") && kv != "USERPROFILE="+ws {
			t.Fatalf("USERPROFILE leaks host: %q", kv)
		}
		if strings.HasPrefix(kv, "APPDATA=") && !strings.HasPrefix(kv, "APPDATA="+ws) {
			t.Fatalf("APPDATA leaks host: %q", kv)
		}
	}
	need := map[string]string{
		"SystemRoot": `C:\Windows`,
		"TEMP":       ws + `\tmp`,
		"PATH":       `C:\Windows\System32;C:\tools\go\bin`,
		"LANG":       "en",
	}
	got := map[string]string{}
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		got[parts[0]] = parts[1]
	}
	for k, v := range need {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q", k, got[k], v)
		}
	}
	if !sort.StringsAreSorted(env) {
		t.Fatal("env must be sorted for determinism")
	}
}

func TestOwnershipRules(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "r1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnership(base, "r1", "repoproof-r1", filepath.Join(base, "r1")); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	bad := []struct {
		name    string
		run     string
		profile string
		ws      string
	}{
		{"foreign profile", "r1", "someone-else", filepath.Join(base, "r1")},
		{"mismatch profile", "r1", "repoproof-r2", filepath.Join(base, "r1")},
		{"escape workspace", "r1", "repoproof-r1", filepath.Join(base, "..", "evil")},
		{"absolute outside", "r1", "repoproof-r1", `C:\Windows\Temp\x`},
		{"empty run", "", "repoproof-", filepath.Join(base, "")},
		{"bad chars", "r1", "repoproof-../r1", filepath.Join(base, "r1")},
	}
	for _, tc := range bad {
		if err := verifyOwnership(base, tc.run, tc.profile, tc.ws); err == nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	if containedPath(base, filepath.Join(base, "..", "evil")) {
		t.Fatal("traversal accepted by containedPath")
	}
	if !containedPath(base, filepath.Join(base, "r1", "deep")) {
		t.Fatal("legit subpath rejected")
	}
}
