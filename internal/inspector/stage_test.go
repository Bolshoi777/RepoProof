package inspector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func stageEntry(path string, raw []byte) Entry {
	h := sha256.Sum256(raw)
	return Entry{Path: path, Kind: "file", Size: int64(len(raw)), SHA256: hex.EncodeToString(h[:])}
}

func TestStageSnapshotCopiesOnlyVerifiedBytes(t *testing.T) {
	source := t.TempDir()
	workspace := t.TempDir()
	raw := []byte("print('fixture')\n")
	if err := os.WriteFile(filepath.Join(source, "main.py"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Source: source, Files: []Entry{stageEntry("main.py", raw)}}
	if err := StageSnapshot(s, source, workspace); err != nil {
		t.Fatalf("stage failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(workspace, "project", "main.py"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("staged bytes changed: %q", got)
	}
}

func TestStageSnapshotRefusesChangedSourceAndRollsBack(t *testing.T) {
	source := t.TempDir()
	workspace := t.TempDir()
	original := []byte("original\n")
	path := filepath.Join(source, "main.py")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Source: source, Files: []Entry{stageEntry("main.py", original)}}
	if err := os.WriteFile(path, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := StageSnapshot(s, source, workspace); err == nil {
		t.Fatal("changed source was staged")
	}
	if _, err := os.Stat(filepath.Join(workspace, "project")); !os.IsNotExist(err) {
		t.Fatalf("failed staging left project behind: %v", err)
	}
}

func TestStageSnapshotRefusesSymlink(t *testing.T) {
	source := t.TempDir()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "real.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.txt", filepath.Join(source, "link.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	entry := stageEntry("real.txt", []byte("x"))
	entryLink := Entry{Path: "link.txt", Kind: "symlink", Size: -1, Note: "link:real.txt"}
	if err := StageSnapshot(Snapshot{Source: source, Files: []Entry{entry, entryLink}}, source, workspace); err == nil {
		t.Fatal("symlink was accepted")
	}
}
