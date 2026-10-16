package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateURL(t *testing.T) {
	ok := []struct {
		in, canonical string
	}{
		{"https://github.com/octocat/Hello-World", "https://github.com/octocat/Hello-World"},
		{"https://github.com/octocat/Hello-World/", "https://github.com/octocat/Hello-World"},
		{"https://github.com/octocat/Hello-World.git", "https://github.com/octocat/Hello-World"},
		{"https://github.com/octocat/Hello-World/tree/main?tab=readme#readme", "https://github.com/octocat/Hello-World"},
		{"https://github.com/octocat/Hello-World/issues", "https://github.com/octocat/Hello-World"},
		{"https://github.com/octocat/Hello-World/blob/main/README.md", "https://github.com/octocat/Hello-World"},
		{"  https://github.com/o/r  ", "https://github.com/o/r"},
	}
	for _, tc := range ok {
		got, err := ValidateURL(tc.in)
		if err != nil || got != tc.canonical {
			t.Fatalf("ValidateURL(%q) = %q, %v", tc.in, got, err)
		}
	}
	bad := []string{
		"", "not a url", "http://github.com/o/r", "git@github.com:o/r.git",
		"https://user:token@github.com/o/r", "https://gitlab.com/o/r",
		"https://github.com/o",
		"https://github.com/o/r/not-a-github-route", "https://github.com/../x",
		"javascript:alert(1)", "file:///etc/passwd",
	}
	for _, in := range bad {
		if _, err := ValidateURL(in); err == nil {
			t.Fatalf("ValidateURL(%q) accepted", in)
		}
	}
}

func TestGitEnvIsMinimalAndDisablesConfig(t *testing.T) {
	env := strings.Join(gitEnv(), "\x00")
	for _, forbidden := range []string{"GIT_SSH_COMMAND=", "GIT_ASKPASS=", "SSH_AUTH_SOCK=", "AWS_SECRET_ACCESS_KEY="} {
		if strings.Contains(env, forbidden) {
			t.Fatalf("unsafe inherited variable: %s", forbidden)
		}
	}
	for _, required := range []string{"GIT_CONFIG_GLOBAL=NUL", "GIT_CONFIG_SYSTEM=NUL", "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0"} {
		if !strings.Contains(env, required) {
			t.Fatalf("missing git hardening: %s", required)
		}
	}
}

// TestCloneHelloWorld is the live URL slice proof: resolve pins HEAD,
// materialize checks out exactly that commit, and no credentials or
// submodules are involved. Requires git + github.com access.
func TestCloneHelloWorld(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), CloneTimeout)
	defer cancel()
	const remote = "https://github.com/octocat/Hello-World"
	sha, err := ResolveCommit(ctx, remote)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(sha) != 40 {
		t.Fatalf("sha = %q", sha)
	}
	dir, got, cleanup, err := Materialize(ctx, remote, "")
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	defer cleanup()
	if got != sha {
		t.Fatalf("checkout %q != resolved %q", got, sha)
	}
	out, err := runGit(ctx, filepath.Join(dir, "repo"), "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != sha {
		t.Fatalf("HEAD %q != pinned %q", out, sha)
	}
}

// TestRemoveAllRetryLocked proves cleanup survives transient Windows
// locks: a held file handle fails the first attempts, releasing it
// lets a later attempt succeed.
func TestRemoveAllRetryLocked(t *testing.T) {
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked.txt")
	f, err := os.Create(locked)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- removeAllRetry(dir, 10*time.Second)
	}()
	select {
	case err := <-done:
		t.Fatalf("removal should have waited for the lock, got %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("removal failed after unlock: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("removal did not finish after unlock")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("dir survived cleanup")
	}
}

func TestBoundedTreeBytesRefusesOversizeFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "payload.bin"), make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedTreeBytes(dir, 512); err == nil {
		t.Fatal("oversize materialized tree was accepted")
	}
}

func TestTreeObjectBytesRejectsLimit(t *testing.T) {
	old := runGit
	_ = old // treeObjectBytes is exercised through the live clone below.
	// Keep this test focused on the parser contract through a tiny local git
	// repository so no untrusted repository code is executed.
	dir := t.TempDir()
	if _, err := runGit(context.Background(), dir, "init"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload.bin"), make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(context.Background(), dir, "add", "payload.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(context.Background(), dir, "-c", "user.name=RepoProof", "-c", "user.email=test@repoproof.invalid", "commit", "-m", "fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := treeObjectBytes(context.Background(), dir, "HEAD", 512); err == nil {
		t.Fatal("oversize git tree was accepted")
	}
}
