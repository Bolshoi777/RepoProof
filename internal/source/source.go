// Package source materializes remote GitHub repositories for
// inspection (URL-clone slice): strict URL validation, commit pinning
// via ls-remote, and a detached checkout of exactly that commit.
//
// The git binary is trusted vendor tooling (like icacls before it),
// invoked with fixed argument shapes; repository CONTENT is never
// executed, and hooks never run (clone/checkout run no hooks).
// Submodules are never initialized. Private repos, credentials in
// URLs, non-GitHub hosts and oversized repos are refused or limited
// (see limitations below, not silent behavior).
package source

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Timeouts for network operations.
const (
	ResolveTimeout = 60 * time.Second
	CloneTimeout   = 10 * time.Minute
	// MaxMaterializedBytes bounds the checked-out tree before inspection.
	// It is a post-clone guard, not a filesystem quota; the report must keep
	// that distinction explicit.
	MaxMaterializedBytes = int64(512 << 20)
)

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

var githubRepositoryRoutes = map[string]bool{
	"actions": true, "archive": true, "blob": true, "branches": true,
	"commits": true, "compare": true, "community": true, "discussions": true,
	"graphs": true, "issues": true, "network": true, "projects": true,
	"pull": true, "pulls": true, "raw": true, "releases": true,
	"security": true, "settings": true, "tags": true, "tree": true,
	"wiki": true,
}

// ValidateURL accepts only public GitHub HTTPS repository URLs:
// https://github.com/<owner>/<repo>[.git][/]. Anything else
// (credentials, other hosts/schemes, deep paths) is refused.
func ValidateURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" {
		return "", fmt.Errorf("source: only https GitHub URLs accepted")
	}
	if u.Host != "github.com" {
		return "", fmt.Errorf("source: only github.com accepted, got %q", u.Host)
	}
	if u.User != nil {
		return "", fmt.Errorf("source: credentials in URL refused")
	}
	// Browser-copied GitHub links often carry a harmless tab/query or a
	// fragment. They do not change the repository identity, so discard them
	// after validating the host and credentials instead of making users edit
	// a URL manually.
	p := strings.Trim(u.Path, "/")
	parts := strings.Split(p, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("source: want https://github.com/<owner>/<repo>, got %q", raw)
	}
	for _, part := range parts[:2] {
		if strings.ContainsAny(part, " \t\n?#%") || part == "." || part == ".." {
			return "", fmt.Errorf("source: bad path component %q", part)
		}
	}
	repo := strings.TrimSuffix(parts[1], ".git")
	if repo == "" {
		return "", fmt.Errorf("source: repository name is empty")
	}
	if len(parts) > 2 && !githubRepositoryRoutes[strings.ToLower(parts[2])] {
		return "", fmt.Errorf("source: unsupported GitHub path %q; paste the repository URL", strings.Join(parts[2:], "/"))
	}
	return "https://github.com/" + parts[0] + "/" + repo, nil
}

func gitEnv() []string {
	// Start from a minimal trusted block. Inheriting the operator's
	// environment lets Git load credential helpers, smudge filters or
	// SSH commands configured outside this repository.
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"TEMP=" + os.TempDir(),
		"TMP=" + os.TempDir(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=NUL",
		"GIT_CONFIG_GLOBAL=NUL",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_OPTIONAL_LOCKS=0",
	}
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("git %s: %w (output: %s)", args[0], ctx.Err(), oneLine(string(out)))
	}
	if err != nil {
		return "", fmt.Errorf("git %s failed: %v: %s", args[0], err, oneLine(string(out)))
	}
	return string(out), nil
}

// removeAllRetry tolerates transient Windows locks on fresh trees
// (indexer/antivirus holds handles briefly after clone). Last error
// is returned for callers that can report it.
func removeAllRetry(dir string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var err error
	for {
		if err = os.RemoveAll(dir); err == nil {
			_, statErr := os.Lstat(dir)
			if os.IsNotExist(statErr) {
				return nil
			}
			if statErr != nil {
				err = statErr
			} else {
				err = fmt.Errorf("clone directory still exists after RemoveAll")
			}
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func oneLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	if s == "" {
		return "(no output)"
	}
	return s
}

// ResolveCommit pins the remote HEAD to a commit SHA without cloning.
func ResolveCommit(ctx context.Context, remote string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, ResolveTimeout)
	defer cancel()
	out, err := runGit(ctx, "", "ls-remote", remote, "HEAD")
	if err != nil {
		return "", fmt.Errorf("source: resolve: %w", err)
	}
	fields := strings.Fields(out)
	if len(fields) < 2 || !sha40.MatchString(strings.ToLower(fields[0])) {
		return "", fmt.Errorf("source: resolve: unexpected ls-remote output")
	}
	return strings.ToLower(fields[0]), nil
}

// Materialize validates, pins and clones the repository, checking out
// exactly the pinned commit detached. The caller owns dir and must
// remove it (cleanup func). No hooks run, no submodules initialize.
func Materialize(ctx context.Context, rawURL, parentDir string) (dir, sha string, cleanup func(), err error) {
	remote, err := ValidateURL(rawURL)
	if err != nil {
		return "", "", nil, err
	}
	sha, err = ResolveCommit(ctx, remote)
	if err != nil {
		return "", "", nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, CloneTimeout)
	defer cancel()
	dir, err = os.MkdirTemp(parentDir, "repoproof-clone-")
	if err != nil {
		return "", "", nil, err
	}
	// Best-effort removal with retries: on Windows a fresh clone can
	// stay briefly locked (indexer/antivirus), and a silent RemoveAll
	// failure would litter temp dirs. Same lesson as profile teardown.
	cleanup = func() { _ = removeAllRetry(dir, 5*time.Second) }
	fail := func(format string, args ...any) (string, string, func(), error) {
		cleanup()
		return "", "", nil, fmt.Errorf(format, args...)
	}
	target := filepath.Join(dir, "repo")
	if _, err := runGit(ctx, "", "clone", "--no-checkout", "--no-tags", "--depth=1", "--filter=blob:none", "--no-recurse-submodules", remote, target); err != nil {
		return fail("source: clone: %v", err)
	}
	if size, err := treeObjectBytes(ctx, target, sha, MaxMaterializedBytes); err != nil {
		return fail("source: repository tree exceeds materialized limit (%d bytes): %v", MaxMaterializedBytes, err)
	} else if size > MaxMaterializedBytes {
		return fail("source: repository tree exceeds materialized limit (%d bytes): %d", MaxMaterializedBytes, size)
	}
	if _, err := runGit(ctx, target, "checkout", "--detach", sha); err != nil {
		return fail("source: checkout %s: %v", sha, err)
	}
	if size, err := boundedTreeBytes(target, MaxMaterializedBytes); err != nil {
		return fail("source: checkout exceeds materialized tree limit (%d bytes): %v", MaxMaterializedBytes, err)
	} else if size > MaxMaterializedBytes {
		return fail("source: checkout exceeds materialized tree limit (%d bytes): %d", MaxMaterializedBytes, size)
	}
	// Return the parent: the repo lives at dir/repo, and cleanup
	// removes the whole tree. Returning repo-root here once caused
	// orphaned empty parents (cleanup/root mismatch).
	return dir, sha, cleanup, nil
}

// treeObjectBytes reads Git's object-size metadata without checking out blob
// contents. It is a preflight guard for partial clones; the filesystem walk
// after checkout remains the final defense for generated working-tree files.
func treeObjectBytes(ctx context.Context, dir, rev string, limit int64) (int64, error) {
	out, err := runGit(ctx, dir, "ls-tree", "--full-tree", "-r", "-l", rev)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "blob" || fields[3] == "-" {
			continue
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || size < 0 {
			return 0, fmt.Errorf("invalid tree blob size %q", fields[3])
		}
		if size > limit-total {
			return total, fmt.Errorf("tree byte limit exceeded")
		}
		total += size
	}
	return total, nil
}

func boundedTreeBytes(root string, limit int64) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Size() < 0 || info.Size() > limit-total {
			return fmt.Errorf("byte limit exceeded")
		}
		total += info.Size()
		return nil
	})
	return total, err
}
