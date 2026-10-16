package inspector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	shaA = "0123456789abcdef0123456789abcdef01234567"
	shaB = "fedcba9876543210fedcba9876543210fedcba98"
)

// mkRepo creates a synthetic git metadata layout without running git.
func mkRepo(t *testing.T, head string, refs map[string]string, packed string) string {
	t.Helper()
	dir := t.TempDir()
	gitdir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(filepath.Join(gitdir, "refs", "heads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitdir, "HEAD"), []byte(head+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for ref, sha := range refs {
		p := filepath.Join(gitdir, filepath.FromSlash(ref))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(sha+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if packed != "" {
		if err := os.WriteFile(filepath.Join(gitdir, "packed-refs"), []byte(packed), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestResolveDetachedHEAD(t *testing.T) {
	dir := mkRepo(t, shaA, nil, "")
	sha, note := resolveGitCommit(dir)
	if note != "" || sha == nil || *sha != shaA {
		t.Fatalf("sha=%v note=%q", sha, note)
	}
}

func TestResolveBranchLooseRef(t *testing.T) {
	dir := mkRepo(t, "ref: refs/heads/main", map[string]string{"refs/heads/main": shaA}, "")
	sha, note := resolveGitCommit(dir)
	if note != "" || sha == nil || *sha != shaA {
		t.Fatalf("sha=%v note=%q", sha, note)
	}
}

func TestResolveBranchPackedRef(t *testing.T) {
	packed := "# pack-refs with: peeled fully-peeled sorted\n" + shaB + " refs/heads/main\n"
	dir := mkRepo(t, "ref: refs/heads/main", nil, packed)
	sha, note := resolveGitCommit(dir)
	if note != "" || sha == nil || *sha != shaB {
		t.Fatalf("sha=%v note=%q", sha, note)
	}
}

func TestUnbornHEADHasNoCommit(t *testing.T) {
	dir := mkRepo(t, "ref: refs/heads/main", nil, "")
	sha, note := resolveGitCommit(dir)
	if sha != nil || !strings.Contains(note, "unborn") {
		t.Fatalf("sha=%v note=%q, want unborn note", sha, note)
	}
}

func TestMalformedHEADHasNoCommit(t *testing.T) {
	for _, head := range []string{"garbage", "ref: ", "ref: ../evil", "ref: /abs/path"} {
		dir := mkRepo(t, head, nil, "")
		sha, note := resolveGitCommit(dir)
		if sha != nil || !strings.Contains(note, "malformed") {
			t.Fatalf("head=%q: sha=%v note=%q, want malformed note", head, sha, note)
		}
	}
}

func TestNonCheckoutHasNoCommitNoNote(t *testing.T) {
	sha, note := resolveGitCommit(t.TempDir())
	if sha != nil || note != "" {
		t.Fatalf("sha=%v note=%q, want both empty", sha, note)
	}
}

func TestWorktreePointerOutsideRootIsRejected(t *testing.T) {
	dir := t.TempDir()
	realgit := filepath.Join(dir, "real.git", "worktrees", "wt1")
	if err := os.MkdirAll(filepath.Join(realgit, "refs", "heads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realgit, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realgit, "refs", "heads", "main"), []byte(shaA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wt := filepath.Join(dir, "wt")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: ../real.git/worktrees/wt1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sha, note := resolveGitCommit(wt)
	if sha != nil || note != "" {
		t.Fatalf("external gitdir pointer must not disclose metadata: sha=%v note=%q", sha, note)
	}
}

// TestRefSwitchPinsCurrent proves the snapshot pins the HEAD observed at
// inspection time instead of a stale cached value.
func TestRefSwitchPinsCurrent(t *testing.T) {
	dir := mkRepo(t, "ref: refs/heads/main", map[string]string{"refs/heads/main": shaA}, "")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.Commit == nil || *first.Commit != shaA {
		t.Fatalf("first commit = %v, want %s", first.Commit, shaA)
	}
	// Simulate ref switch (fetch/checkout moving the branch).
	if err := os.WriteFile(filepath.Join(dir, ".git", "refs", "heads", "main"), []byte(shaB+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second.Commit == nil || *second.Commit != shaB {
		t.Fatalf("second commit = %v, want %s (stale pin)", second.Commit, shaB)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatal("content fingerprint must not change on ref-only switch")
	}
}

// TestInspectGitLimitations checks the honest limitation strings.
func TestInspectGitLimitations(t *testing.T) {
	dir := mkRepo(t, "ref: refs/heads/main", map[string]string{"refs/heads/main": shaA}, "")
	rep, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Commit == nil {
		t.Fatal("commit must be pinned")
	}
	joined := strings.Join(rep.Limitations, ";")
	if !strings.Contains(joined, "pinned") {
		t.Fatalf("limitations missing pin note: %v", rep.Limitations)
	}

	plain, err := Inspect(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if plain.Commit != nil {
		t.Fatal("non-checkout must keep commit null")
	}
	if !strings.Contains(strings.Join(plain.Limitations, ";"), "not a git checkout") {
		t.Fatalf("limitations missing non-git note: %v", plain.Limitations)
	}
}
