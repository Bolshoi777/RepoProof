package inspector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxStageEntries = 1_000_000
	maxStageBytes   = int64(512 << 20)
)

// StageSnapshot copies exactly the hashed regular files from an inspected
// source tree into a fresh project directory. It never falls back to the
// operator's source tree. Every source byte is rehashed while being copied;
// a changed or unhashed entry aborts the whole staging operation.
func StageSnapshot(s Snapshot, sourceRoot, workspace string) error {
	if sourceRoot == "" || workspace == "" {
		return fmt.Errorf("stage: source and workspace are required")
	}
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return fmt.Errorf("stage: source path: %w", err)
	}
	ws, err := filepath.Abs(workspace)
	if err != nil {
		return fmt.Errorf("stage: workspace path: %w", err)
	}
	if err := plainDirectory(ws); err != nil {
		return fmt.Errorf("stage: workspace: %w", err)
	}
	if err := plainDirectory(root); err != nil {
		return fmt.Errorf("stage: source: %w", err)
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return fmt.Errorf("stage: source canonical path: %w", err)
	}
	project := filepath.Join(ws, "project")
	if !containedPath(ws, project) {
		return fmt.Errorf("stage: project path escapes workspace")
	}
	if err := os.Mkdir(project, 0o755); err != nil {
		return fmt.Errorf("stage: project must be fresh: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = os.RemoveAll(project)
		}
	}()

	byPath := make(map[string]Entry, len(s.Files))
	seenFolded := make(map[string]string, len(s.Files))
	if len(s.Files) > maxStageEntries {
		return fmt.Errorf("stage: manifest entry limit exceeded")
	}
	var total int64
	for _, e := range s.Files {
		norm, err := stageRelativePath(e.Path)
		if err != nil {
			return err
		}
		key := strings.ToLower(norm)
		if old, ok := seenFolded[key]; ok && old != norm {
			return fmt.Errorf("stage: case-insensitive path collision: %q and %q", old, norm)
		}
		seenFolded[key] = norm
		if e.Kind != "file" || e.SHA256 == "" || e.Size < 0 {
			return fmt.Errorf("stage: entry %q is not a hashed regular file", norm)
		}
		if e.Size > maxStageBytes-total {
			return fmt.Errorf("stage: byte limit exceeded")
		}
		total += e.Size
		byPath[norm] = e
	}

	// Fail closed on any source item that the snapshot did not hash. This
	// catches symlinks, junctions, devices, and files created after inspect.
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		norm := filepath.ToSlash(rel)
		if norm == ".git" || strings.HasPrefix(norm, ".git/") {
			if d.Type()&fs.ModeSymlink != 0 {
				return fmt.Errorf("stage: .git symlink refused: %s", norm)
			}
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 || stageReparse(info) {
			return fmt.Errorf("stage: symlink/reparse entry refused: %s", norm)
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		if !sameCanonical(root, resolved) {
			return fmt.Errorf("stage: entry escapes source root: %s", norm)
		}
		if d.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("stage: special entry refused: %s", norm)
		}
		if _, ok := byPath[norm]; !ok {
			return fmt.Errorf("stage: source changed or entry was not inspected: %s", norm)
		}
		return nil
	})
	if walkErr != nil {
		return walkErr
	}

	for norm, e := range byPath {
		src := filepath.Join(root, filepath.FromSlash(norm))
		dst := filepath.Join(project, filepath.FromSlash(norm))
		if !containedPath(root, src) || !containedPath(project, dst) {
			return fmt.Errorf("stage: path escapes root: %s", norm)
		}
		if err := makeFreshParents(project, filepath.Dir(filepath.FromSlash(norm))); err != nil {
			return err
		}
		if err := copyVerifiedFile(src, dst, e); err != nil {
			return fmt.Errorf("stage %s: %w", norm, err)
		}
	}
	rollback = false
	return nil
}

// ReadVerifiedFile returns bytes for one manifest entry only after checking
// its size and digest. Callers that prepare dependencies use this instead of
// rereading an unbound path from the source tree.
func ReadVerifiedFile(s Snapshot, sourceRoot, rel string) ([]byte, error) {
	norm, err := stageRelativePath(rel)
	if err != nil {
		return nil, err
	}
	var want *Entry
	for i := range s.Files {
		if s.Files[i].Path == norm {
			want = &s.Files[i]
			break
		}
	}
	if want == nil || want.Kind != "file" || want.SHA256 == "" || want.Size < 0 {
		return nil, fmt.Errorf("stage: %q is not a hashed manifest file", norm)
	}
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return nil, err
	}
	if err := plainDirectory(root); err != nil {
		return nil, err
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return nil, err
	}
	path := filepath.Join(root, filepath.FromSlash(norm))
	if !containedPath(root, path) {
		return nil, fmt.Errorf("stage: path escapes source root")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || stageReparse(info) || info.Size() != want.Size {
		return nil, fmt.Errorf("stage: source changed before dependency read")
	}
	f, err := openStageSource(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxStageBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != want.Size {
		return nil, fmt.Errorf("stage: source changed during dependency read")
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != strings.ToLower(want.SHA256) {
		return nil, fmt.Errorf("stage: source digest mismatch")
	}
	return raw, nil
}

func stageRelativePath(raw string) (string, error) {
	if raw == "" || strings.Contains(raw, "\\") || strings.Contains(raw, ":") {
		return "", fmt.Errorf("stage: unsafe relative path %q", raw)
	}
	parts := strings.Split(raw, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.HasSuffix(p, ".") || strings.HasSuffix(p, " ") {
			return "", fmt.Errorf("stage: unsafe relative path %q", raw)
		}
		if stageReservedComponent(p) {
			return "", fmt.Errorf("stage: reserved device name in path %q", raw)
		}
		if strings.EqualFold(p, ".git") {
			return "", fmt.Errorf("stage: .git entry refused: %q", raw)
		}
	}
	return strings.Join(parts, "/"), nil
}

func copyVerifiedFile(src, dst string, want Entry) error {
	info, err := os.Lstat(src)
	if err != nil || !info.Mode().IsRegular() || info.Size() != want.Size {
		return fmt.Errorf("source changed before copy")
	}
	in, err := openStageSource(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, maxStageBytes+1))
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if info, err := os.Lstat(src); err != nil || info.Size() != want.Size {
		return fmt.Errorf("source changed during copy")
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != strings.ToLower(want.SHA256) {
		return fmt.Errorf("source digest mismatch")
	}
	return nil
}

func makeFreshParents(root, rel string) error {
	if rel == "." || rel == "" {
		return nil
	}
	cur := root
	for _, p := range strings.Split(filepath.ToSlash(rel), "/") {
		cur = filepath.Join(cur, p)
		if info, err := os.Lstat(cur); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stageReparse(info) {
				return fmt.Errorf("stage: destination parent is not a directory: %s", cur)
			}
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.Mkdir(cur, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func plainDirectory(path string) error {
	cur := filepath.Clean(path)
	for {
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stageReparse(info) {
			return fmt.Errorf("not a plain directory: %s", cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return nil
}

func containedPath(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func sameCanonical(root, target string) bool {
	if !containedPath(root, target) {
		return false
	}
	return true
}
