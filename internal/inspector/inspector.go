// Package inspector implements read-only static inspection of a local
// project folder (G1-01, RP-001).
//
// Hard invariants:
//   - never executes, spawns, or evaluates anything found in the folder
//     (no shells, no hooks, no scripts, no binaries);
//   - never follows symlinks (a link is recorded, its target is never read);
//   - never leaves the inspected root;
//   - skips VCS metadata (.git).
//
// Fingerprint: SHA-256 over a canonical manifest of
// "kind<TAB>relpath<TAB>size<TAB>payload" lines sorted by relpath, where
// payload is the file SHA-256 hex, "link:<target>" for symlinks, or
// "skipped:too-large" for files above the hash cap. This matches the
// source_fingerprint semantics of docs/10_PROTOCOL_AND_LIMITS.md
// (commit == null until G1-02 adds git SHA support).
package inspector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/repoproof/repoproof/internal/readme"
	"github.com/repoproof/repoproof/internal/source"
)

// DefaultMaxHashBytes caps how much of a single file is hashed. Larger
// files are recorded with their size and a skipped marker instead of a
// hash, so inspection stays bounded without reading gigabytes.
const DefaultMaxHashBytes = 32 << 20 // 32 MiB

// Stack is the detected runtime family. "multiple" and "unknown" are
// honest non-results: they must never be presented as supported.
type Stack string

const (
	StackNode     Stack = "node"
	StackPython   Stack = "python"
	StackRust     Stack = "rust"
	StackGo       Stack = "go"
	StackJava     Stack = "java"
	StackRuby     Stack = "ruby"
	StackPHP      Stack = "php"
	StackDotnet   Stack = "dotnet"
	StackCpp      Stack = "cpp"
	StackMultiple Stack = "multiple"
	StackUnknown  Stack = "unknown"
)

// Support states whether the detected stack is in v1 scope. Only node
// and python are supported; everything else detected is explicitly
// unsupported, and undetected is undetermined (never implied support).
type Support string

const (
	SupportSupported    Support = "supported"
	SupportUnsupported  Support = "unsupported"
	SupportUndetermined Support = "undetermined"
)

// Entry is one manifest record.
type Entry struct {
	Path   string `json:"path"`             // rel path, forward slashes
	Kind   string `json:"kind"`             // "file" or "symlink"
	Size   int64  `json:"size"`             // -1 when unknown
	SHA256 string `json:"sha256,omitempty"` // hex, files within cap only
	Note   string `json:"note,omitempty"`   // "link:<target>" | "skipped:too-large"
}

// Snapshot is the deterministic inspection result for a local folder.
type Snapshot struct {
	Source      string   `json:"source"`             // absolute path as given
	Commit      *string  `json:"commit"`             // pinned git HEAD or null
	Fingerprint string   `json:"source_fingerprint"` // 64 lowercase hex
	Readme      *string  `json:"readme"`             // root README rel path or nil
	Indicators  []string `json:"indicators"`         // known config files found
	Stack       Stack    `json:"stack"`
	Support     Support  `json:"support"` // v1 scope verdict for Stack
	FileCount   int      `json:"file_count"`
	Files       []Entry  `json:"files"`
	// ReadmeSteps holds candidate commands parsed from the root README
	// (G1-03). Data only, never executed. Null when no README found.
	ReadmeSteps []readme.CandidateStep `json:"readme_steps"`
	Limitations []string               `json:"limitations"`
}

// Report is the JSON-serializable inspect output (inspect level, v1).
type Report struct {
	Version string `json:"version"`
	Snapshot
}

// readmeCandidates are matched case-insensitively at root depth only.
var readmeCandidates = []string{
	"readme.md", "readme.markdown", "readme.txt", "readme",
}

// indicatorStacks maps a root-level file name (lowercase) to the stack
// it indicates. Presence is a signal, never a support guarantee.
// Only node and python are v1-supported (RP-004); the rest marks the
// project explicitly UNSUPPORTED instead of silently unknown.
var indicatorStacks = map[string]Stack{
	"package.json":      StackNode,
	"package-lock.json": StackNode,
	"pyproject.toml":    StackPython,
	"setup.py":          StackPython,
	"setup.cfg":         StackPython,
	"pipfile":           StackPython,
	"poetry.lock":       StackPython,
	"uv.lock":           StackPython,
	"cargo.toml":        StackRust,
	"cargo.lock":        StackRust,
	"go.mod":            StackGo,
	"go.sum":            StackGo,
	"pom.xml":           StackJava,
	"build.gradle":      StackJava,
	"build.gradle.kts":  StackJava,
	"gemfile":           StackRuby,
	"gemfile.lock":      StackRuby,
	"composer.json":     StackPHP,
	"composer.lock":     StackPHP,
	"cmakelists.txt":    StackCpp,
}

// indicatorSuffixes matches root files by suffix (project files whose
// base name varies, e.g. MyApp.csproj).
var indicatorSuffixes = map[string]Stack{
	".csproj": StackDotnet,
	".sln":    StackDotnet,
}

// supportedStacks is the v1 execution scope. Everything else detected
// is explicitly unsupported until a later gate implements it.
var supportedStacks = map[Stack]bool{
	StackNode:   true,
	StackPython: true,
}

const requirementsPrefix = "requirements"

// Inspect performs a read-only inspection of a local folder or, when
// given an https://github.com URL, of a pinned-commit clone made into
// a temp dir and removed afterwards (each inspect re-clones; a shared
// cache is future work). Repository content is never executed.
func Inspect(path string) (*Report, error) {
	if strings.HasPrefix(strings.TrimSpace(path), "https://") {
		dir, _, cleanup, err := source.Materialize(context.Background(), path, "")
		if err != nil {
			return nil, err
		}
		defer cleanup()
		return inspectWithCap(filepath.Join(dir, "repo"), DefaultMaxHashBytes)
	}
	return inspectWithCap(path, DefaultMaxHashBytes)
}

func inspectWithCap(path string, maxHashBytes int64) (*Report, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect: lstat source: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("inspect: not a directory: %s", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("inspect: resolve path: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("inspect: resolve canonical root: %w", err)
	}

	entries := []Entry{}
	rootFiles := map[string]bool{} // lowercase base name -> present (depth 1)

	walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(abs, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		// A regular directory may be a Windows junction/reparse point even
		// when DirEntry.Type does not expose ModeSymlink. Resolve canonical
		// targets before hashing or descending so inspect cannot read a host
		// tree outside the selected root.
		if d.Type()&fs.ModeSymlink == 0 {
			resolved, rerr := filepath.EvalSymlinks(p)
			if rerr != nil {
				return rerr
			}
			if !pathWithin(realRoot, resolved) {
				return fmt.Errorf("inspect: reparse point escapes root: %s", rel)
			}
		}

		// Never descend into VCS metadata.
		if d.IsDir() {
			if rel == ".git" || strings.HasPrefix(rel, ".git/") {
				return filepath.SkipDir
			}
			return nil
		}

		// Record depth-1 names for README/indicator detection.
		if !strings.Contains(rel, "/") {
			rootFiles[strings.ToLower(rel)] = true
		}

		// Never follow symlinks: record the link itself.
		if d.Type()&fs.ModeSymlink != 0 {
			target, terr := os.Readlink(p)
			if terr != nil {
				target = "unreadable"
			}
			entries = append(entries, Entry{
				Path: rel, Kind: "symlink", Size: -1, Note: "link:" + target,
			})
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // sockets, pipes, devices: ignored, never touched
		}

		fi, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		size := fi.Size()
		e := Entry{Path: rel, Kind: "file", Size: size}
		if size > maxHashBytes {
			e.Note = "skipped:too-large"
		} else if h, herr := hashFile(p); herr != nil {
			return herr
		} else {
			e.SHA256 = h
		}
		entries = append(entries, e)
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("inspect: walk: %w", walkErr)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	h := sha256.New()
	for _, e := range entries {
		payload := e.SHA256
		if e.Kind == "symlink" || e.Note != "" {
			payload = e.Note
		}
		fmt.Fprintf(h, "%s\t%s\t%d\t%s\n", e.Kind, e.Path, e.Size, payload)
	}
	fingerprint := hex.EncodeToString(h.Sum(nil))

	// README detection (root only, case-insensitive).
	var readmeName *string
	for _, cand := range readmeCandidates {
		for name := range rootFiles {
			if name == cand {
				r := rootActualName(abs, name)
				readmeName = &r
				break
			}
		}
		if readmeName != nil {
			break
		}
	}

	// Indicator detection: exact names plus suffix matches (.csproj/.sln).
	indicators := []string{}
	stacks := map[Stack]bool{}
	for name := range rootFiles {
		if st, ok := indicatorStacks[name]; ok {
			indicators = append(indicators, rootActualName(abs, name))
			stacks[st] = true
		}
		for suffix, st := range indicatorSuffixes {
			if strings.HasSuffix(name, suffix) {
				indicators = append(indicators, rootActualName(abs, name))
				stacks[st] = true
			}
		}
		if strings.HasPrefix(name, requirementsPrefix) && strings.HasSuffix(name, ".txt") {
			indicators = append(indicators, rootActualName(abs, name))
			stacks[StackPython] = true
		}
	}
	sort.Strings(indicators)

	stack, support := classify(stacks)

	fileCount := 0
	for _, e := range entries {
		if e.Kind == "file" {
			fileCount++
		}
	}

	commit, gitNote := resolveGitCommit(abs)
	limitations := []string{}
	if commit != nil {
		limitations = append(limitations, "commit pinned to git HEAD at inspection time; re-run to confirm stability")
	} else if gitNote != "" {
		limitations = append(limitations, gitNote)
	} else {
		limitations = append(limitations, "not a git checkout: commit is null, content fingerprint only")
	}
	limitations = append(limitations, "inspect-only: nothing was executed")

	var steps []readme.CandidateStep
	if readmeName != nil {
		parsed, perr := parseReadmeCapped(abs, *readmeName)
		if perr != nil {
			limitations = append(limitations, perr.Error())
		} else {
			steps = parsed.Steps
		}
	}

	return &Report{
		Version: "1",
		Snapshot: Snapshot{
			Source:      abs,
			Commit:      commit,
			Fingerprint: fingerprint,
			Readme:      readmeName,
			Indicators:  indicators,
			Stack:       stack,
			Support:     support,
			FileCount:   fileCount,
			Files:       entries,
			ReadmeSteps: steps,
			Limitations: limitations,
		},
	}, nil
}

// classify maps detected runtime families to (stack, support).
// A single family names itself; any mix is "multiple". Support is
// granted only when every detected family is v1-supported; a mix of
// supported and out-of-scope families is undetermined, never implied.
func classify(stacks map[Stack]bool) (Stack, Support) {
	supported := []Stack{}
	unsupported := []Stack{}
	for st := range stacks {
		if supportedStacks[st] {
			supported = append(supported, st)
		} else {
			unsupported = append(unsupported, st)
		}
	}
	switch {
	case len(supported) == 0 && len(unsupported) == 0:
		return StackUnknown, SupportUndetermined
	case len(supported) == 1 && len(unsupported) == 0:
		return supported[0], SupportSupported
	case len(supported) > 1 && len(unsupported) == 0:
		return StackMultiple, SupportSupported
	case len(supported) == 0 && len(unsupported) == 1:
		return unsupported[0], SupportUnsupported
	case len(supported) == 0:
		return StackMultiple, SupportUnsupported
	default:
		return StackMultiple, SupportUndetermined
	}
}

// parseReadmeCapped parses the root README with a size cap so a giant
// file cannot exhaust memory. Content is data, never executed.
func parseReadmeCapped(root, name string) (*readme.ParseResult, error) {
	f, err := os.Open(filepath.Join(root, name))
	if err != nil {
		return nil, fmt.Errorf("readme %s unreadable: %v", name, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, readme.MaxReadmeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("readme %s unreadable: %v", name, err)
	}
	if len(raw) > readme.MaxReadmeBytes {
		return nil, fmt.Errorf("readme %s exceeds parse limit: commands not extracted", name)
	}
	return readme.Parse(name, raw)
}

// rootActualName returns the on-disk base name for a lowercase root name.
func rootActualName(root, lower string) string {
	names, err := os.ReadDir(root)
	if err != nil {
		return lower
	}
	for _, n := range names {
		if strings.ToLower(n.Name()) == lower {
			return n.Name()
		}
	}
	return lower
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
