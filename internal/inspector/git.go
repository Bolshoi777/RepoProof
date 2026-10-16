// Git HEAD resolution for inspect snapshots (G1-02, RP-002).
//
// The inspector never executes the `git` binary: it only reads `.git`
// metadata files. This keeps inspection process-free and immune to
// aliases, hooks, or PATH games. A nested subfolder of a checkout is NOT
// treated as a checkout — only root's own `.git` counts.
package inspector

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var sha40 = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// findGitDir locates the git metadata dir for root: root/.git (dir),
// a worktree pointer file (root/.git containing "gitdir: <path>"),
// or a bare-repo layout (root/HEAD + root/refs).
func findGitDir(root string) (string, bool) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", false
	}
	dotgit := filepath.Join(root, ".git")
	if fi, err := os.Lstat(dotgit); err == nil {
		if fi.IsDir() {
			gitReal, rerr := filepath.EvalSymlinks(dotgit)
			if rerr != nil || !pathWithin(rootReal, gitReal) {
				return "", false
			}
			return gitReal, true
		}
		if raw, err := os.ReadFile(dotgit); err == nil {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(string(raw)), "gitdir: "); ok && rest != "" {
				if !filepath.IsAbs(rest) {
					rest = filepath.Join(rootAbs, rest)
				}
				gitReal, rerr := filepath.EvalSymlinks(rest)
				if rerr != nil || !pathWithin(rootReal, gitReal) {
					return "", false
				}
				return gitReal, true
			}
		}
		return "", false
	}
	if _, err := os.Stat(filepath.Join(root, "HEAD")); err == nil {
		if _, err := os.Stat(filepath.Join(root, "refs")); err == nil {
			return root, true
		}
	}
	return "", false
}

func pathWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// resolveGitCommit pins HEAD to a commit SHA. It returns (nil, "") when
// root is not a git checkout, (sha, "") on success, or (nil, note) with
// an explanatory note that the caller records as a limitation.
func resolveGitCommit(root string) (sha *string, note string) {
	gitdir, ok := findGitDir(root)
	if !ok {
		return nil, ""
	}
	raw, err := os.ReadFile(filepath.Join(gitdir, "HEAD"))
	if err != nil {
		return nil, "git HEAD unreadable: inspection continues without commit pin"
	}
	head := strings.TrimSpace(string(raw))
	if sha40.MatchString(head) {
		s := strings.ToLower(head)
		return &s, ""
	}
	ref, ok := strings.CutPrefix(head, "ref: ")
	if !ok || ref == "" || strings.Contains(ref, "..") || strings.HasPrefix(ref, "/") || filepath.IsAbs(ref) {
		return nil, "git HEAD malformed: inspection continues without commit pin"
	}
	// Loose ref.
	if rraw, err := os.ReadFile(filepath.Join(gitdir, filepath.FromSlash(ref))); err == nil {
		if s := strings.ToLower(strings.TrimSpace(string(rraw))); sha40.MatchString(s) {
			return &s, ""
		}
	}
	// Packed refs.
	if praw, err := os.ReadFile(filepath.Join(gitdir, "packed-refs")); err == nil {
		for _, line := range strings.Split(string(praw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
				continue
			}
			f := strings.Fields(line)
			if len(f) == 2 && f[1] == ref && sha40.MatchString(f[0]) {
				s := strings.ToLower(f[0])
				return &s, ""
			}
		}
	}
	return nil, "unborn HEAD (" + ref + "): no commit to pin"
}
