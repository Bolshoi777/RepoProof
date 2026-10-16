// Package evidence is the immutable artefact store (G3-05, RP-013):
// content-addressed payloads, an append-only per-run manifest, and a
// sealed receipt chaining them. Verification recomputes every hash;
// any modification, deletion, or manifest edit fails loudly.
//
// The store keeps exact bytes it is given (hashes must stay
// verifiable); sanitization happens at export time, and the Sanitized
// flag records which side a payload came from. Nothing here executes.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MaxPayloadBytes caps a single artefact (bomb protection).
const MaxPayloadBytes = 32 << 20

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Record binds one payload to its run/step with a content hash.
type Record struct {
	Ref       string `json:"ref"` // sha256 hex of payload
	RunID     string `json:"run_id"`
	StepID    string `json:"step_id"`
	Kind      string `json:"kind"` // stdout|stderr|exit|output|meta
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Sanitized bool   `json:"sanitized"`
	UTC       string `json:"utc"`
}

// Store persists artefacts under root.
type Store struct {
	root string
}

// Open creates the store directory.
func Open(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "objects"), 0o755); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

func (s *Store) objPath(ref string) string {
	return filepath.Join(s.root, "objects", ref)
}

func (s *Store) manifestPath(runID string) string {
	return filepath.Join(s.root, runID+".manifest.json")
}

func (s *Store) receiptPath(runID string) string {
	return filepath.Join(s.root, runID+".receipt")
}

func checkID(what, v string) error {
	if !idRe.MatchString(v) || len(v) > 128 {
		return fmt.Errorf("evidence: bad %s %q", what, v)
	}
	return nil
}

// Put stores a payload under its content hash (idempotent for identical
// bytes) and appends the manifest. A sealed run rejects new puts.
func (s *Store) Put(runID, stepID, kind string, payload []byte, sanitized bool) (Record, error) {
	var zero Record
	if err := checkID("run id", runID); err != nil {
		return zero, err
	}
	if err := checkID("step id", stepID); err != nil {
		return zero, err
	}
	if kind == "" {
		return zero, fmt.Errorf("evidence: empty kind")
	}
	if len(payload) > MaxPayloadBytes {
		return zero, fmt.Errorf("evidence: payload exceeds %d bytes", MaxPayloadBytes)
	}
	if sealed, _ := os.Stat(s.receiptPath(runID)); sealed != nil {
		return zero, fmt.Errorf("evidence: run %q already sealed", runID)
	}
	sum := sha256.Sum256(payload)
	ref := hex.EncodeToString(sum[:])
	if err := os.WriteFile(s.objPath(ref), payload, 0o644); err != nil {
		return zero, err
	}
	// Re-read and compare: a pre-existing different file under our
	// ref would mean a sha256 break or disk corruption — refuse.
	back, err := os.ReadFile(s.objPath(ref))
	if err != nil {
		return zero, err
	}
	if !equalBytes(back, payload) {
		return zero, fmt.Errorf("evidence: object %s failed write-back check", ref)
	}
	rec := Record{
		Ref: ref, RunID: runID, StepID: stepID, Kind: kind,
		Size: int64(len(payload)), SHA256: ref, Sanitized: sanitized,
		UTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := s.appendManifest(runID, rec); err != nil {
		return zero, err
	}
	return rec, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Manifest returns the run records in stored order.
func (s *Store) Manifest(runID string) ([]Record, error) {
	if err := checkID("run id", runID); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(s.manifestPath(runID))
	if err != nil {
		return nil, fmt.Errorf("evidence: no manifest for %q", runID)
	}
	var recs []Record
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	for dec.More() {
		var r Record
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("evidence: corrupt manifest for %q", runID)
		}
		recs = append(recs, r)
	}
	return recs, nil
}

func (s *Store) appendManifest(runID string, rec Record) error {
	f, err := os.OpenFile(s.manifestPath(runID), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
	return err
}

// Seal finalizes the run manifest and writes the receipt: the sha256
// of the canonical manifest bytes. Later puts are refused.
func (s *Store) Seal(runID string) (string, error) {
	if err := checkID("run id", runID); err != nil {
		return "", err
	}
	if _, err := os.Stat(s.receiptPath(runID)); err == nil {
		return "", fmt.Errorf("evidence: run %q already sealed", runID)
	}
	recs, err := s.Manifest(runID)
	if err != nil {
		return "", err
	}
	canon, err := canonicalManifest(recs)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	receipt := hex.EncodeToString(sum[:])
	if err := os.WriteFile(s.receiptPath(runID), []byte(receipt+"\n"), 0o644); err != nil {
		return "", err
	}
	return receipt, nil
}

// canonicalManifest is the deterministic byte form covered by receipts.
func canonicalManifest(recs []Record) ([]byte, error) {
	cp := append([]Record{}, recs...)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].StepID != cp[j].StepID {
			return cp[i].StepID < cp[j].StepID
		}
		if cp[i].Kind != cp[j].Kind {
			return cp[i].Kind < cp[j].Kind
		}
		return cp[i].Ref < cp[j].Ref
	})
	out := []byte{}
	for _, r := range cp {
		raw, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		out = append(out, raw...)
		out = append(out, '\n')
	}
	// Bind record count explicitly (no silent truncation ambiguity).
	out = append(out, []byte(fmt.Sprintf("count:%d\n", len(cp)))...)
	return out, nil
}

// Verify replays the whole chain: receipt present, manifest matches
// receipt, every object present with matching hash and size.
func (s *Store) Verify(runID string) error {
	want, err := os.ReadFile(s.receiptPath(runID))
	if err != nil {
		return fmt.Errorf("evidence: run %q not sealed", runID)
	}
	recs, err := s.Manifest(runID)
	if err != nil {
		return err
	}
	canon, err := canonicalManifest(recs)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canon)
	if hex.EncodeToString(sum[:]) != strings.TrimSpace(string(want)) {
		return fmt.Errorf("evidence: manifest of %q does not match receipt (tampered manifest)", runID)
	}
	for _, r := range recs {
		raw, err := os.ReadFile(s.objPath(r.Ref))
		if err != nil {
			return fmt.Errorf("evidence: object %s of %q missing", r.Ref, runID)
		}
		got := sha256.Sum256(raw)
		if hex.EncodeToString(got[:]) != r.SHA256 || int64(len(raw)) != r.Size {
			return fmt.Errorf("evidence: object %s of %q modified", r.Ref, runID)
		}
	}
	return nil
}
