package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r1, err := s.Put("run-1", "install", "stdout", []byte("npm ok\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Put("run-1", "verify", "stdout", []byte("HELLO\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Ref == r2.Ref {
		t.Fatal("distinct payloads share a ref")
	}
	// Idempotent re-put of identical bytes.
	r1b, err := s.Put("run-1", "install", "stdout", []byte("npm ok\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if r1b.Ref != r1.Ref {
		t.Fatal("identical bytes must share a ref")
	}
	man, err := s.Manifest("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(man) != 3 {
		t.Fatalf("manifest has %d records", len(man))
	}
	receipt, err := s.Seal("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt) != 64 {
		t.Fatalf("bad receipt %q", receipt)
	}
	if err := s.Verify("run-1"); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if _, err := s.Put("run-1", "late", "stdout", []byte("x"), false); err == nil {
		t.Fatal("sealed run must refuse puts")
	}
}

func tamperStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("run-9", "s1", "stdout", []byte("original\n"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal("run-9"); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("run-9"); err != nil {
		t.Fatalf("baseline corrupt: %v", err)
	}
	return s, dir
}

func TestTamperedObjectFails(t *testing.T) {
	s, dir := tamperStore(t)
	man, _ := s.Manifest("run-9")
	obj := filepath.Join(dir, "objects", man[0].Ref)
	if err := os.WriteFile(obj, []byte("forged\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("run-9"); err == nil || !strings.Contains(err.Error(), "modified") {
		t.Fatalf("modified object accepted: %v", err)
	}
}

func TestDeletedObjectFails(t *testing.T) {
	s, dir := tamperStore(t)
	man, _ := s.Manifest("run-9")
	if err := os.Remove(filepath.Join(dir, "objects", man[0].Ref)); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("run-9"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("deleted object accepted: %v", err)
	}
}

func TestTamperedManifestFails(t *testing.T) {
	s, dir := tamperStore(t)
	// Append a forged record: receipt covers the manifest, so the
	// chain must break even though the object itself is intact.
	f, err := os.OpenFile(filepath.Join(dir, "run-9.manifest.json"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	forged := `{"ref":"` + strings.Repeat("0", 64) + `","run_id":"run-9","step_id":"evil","kind":"stdout","size":1,"sha256":"` + strings.Repeat("0", 64) + `","sanitized":false,"utc":"2026-01-01T00:00:00Z"}` + "\n"
	if _, err := f.WriteString(forged); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := s.Verify("run-9"); err == nil || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("forged manifest accepted: %v", err)
	}
}

func TestUnsealedVerifyFails(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("r", "s", "stdout", []byte("x"), false); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("r"); err == nil || !strings.Contains(err.Error(), "not sealed") {
		t.Fatalf("unsealed verify accepted: %v", err)
	}
}

func TestRejectsBadInput(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		run, step string
		payload   []byte
	}{
		{"bad run", "../evil", "s", []byte("x")},
		{"bad step", "r", "../../x", []byte("x")},
		{"empty kind", "r", "s", nil},
		{"oversize", "r", "s", make([]byte, MaxPayloadBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind := "stdout"
			if tc.name == "empty kind" {
				kind = ""
			}
			if _, err := s.Put(tc.run, tc.step, kind, tc.payload, false); err == nil {
				t.Fatal("expected refusal")
			}
		})
	}
	if _, err := s.Manifest("nope"); err == nil {
		t.Fatal("missing manifest must fail")
	}
}
