package acceptance

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestFixtureMatrixIntegrity keeps the planned acceptance matrix honest. It
// does not turn a unit test into an E2E claim: an implemented row must point
// to a unique real test function, while an unimplemented row must remain
// NOT_RUN. Current backend capability rows are also pinned to UNSUPPORTED so
// a synthetic test cannot accidentally advertise Node/HTTP support.
func TestFixtureMatrixIntegrity(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	f, err := os.Open(filepath.Join(root, "examples", "fixture_matrix.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = 7
	head, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantHead := []string{"id", "fixture_name", "expected_verdict", "category", "implemented", "test_result", "evidence_path"}
	if strings.Join(head, "\x00") != strings.Join(wantHead, "\x00") {
		t.Fatalf("header = %v, want %v", head, wantHead)
	}

	validVerdicts := map[string]bool{
		"VERIFIED": true, "BEHAVIOR_FAIL": true, "INSTALL_FAIL": true,
		"DOCS_FAIL": true, "LAUNCH_FAIL": true, "PARTIAL": true,
		"INCONCLUSIVE": true, "UNSUPPORTED": true, "BLOCKED_SECURITY": true,
		"ERROR_INTERNAL": true, "CANCELLED": true,
	}
	seen := map[string]bool{}
	evidenceSeen := map[string]string{}
	currentUnsupported := map[string]bool{
		"F02": true, "F03": true, "F04": true, "F05": true,
		"F07": true, "F09": true, "F12": true, "F16": true, "F32": true,
	}
	rows := 0
	for {
		row, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("row %d: %v", rows+2, err)
		}
		rows++
		id, name, verdict, _, implemented, result, evidence := row[0], row[1], row[2], row[3], row[4], row[5], row[6]
		if id == "" || name == "" {
			t.Fatalf("row %d: id and fixture_name are required", rows+1)
		}
		if seen[id] {
			t.Fatalf("row %d: duplicate fixture id %q", rows+1, id)
		}
		seen[id] = true
		if !validVerdicts[verdict] {
			t.Fatalf("row %d (%s): unknown expected verdict %q", rows+1, id, verdict)
		}
		if currentUnsupported[id] && verdict != "UNSUPPORTED" {
			t.Fatalf("row %d (%s): current backend capability must stay UNSUPPORTED, got %q", rows+1, id, verdict)
		}
		switch implemented {
		case "YES":
			if result != "PASS" {
				t.Fatalf("row %d (%s): implemented row must be PASS, got %q", rows+1, id, result)
			}
			checkEvidence(t, root, id, evidence)
			if prior := evidenceSeen[evidence]; prior != "" {
				t.Fatalf("row %d (%s): evidence %q is already claimed by %s; use a row-specific test", rows+1, id, evidence, prior)
			}
			evidenceSeen[evidence] = id
		case "NO":
			if result != "NOT_RUN" || evidence != "" {
				t.Fatalf("row %d (%s): unimplemented row must be NOT_RUN with empty evidence, got result=%q evidence=%q", rows+1, id, result, evidence)
			}
		default:
			t.Fatalf("row %d (%s): implemented must be YES or NO, got %q", rows+1, id, implemented)
		}
	}
	if rows != 36 {
		t.Fatalf("fixture matrix rows = %d, want 36", rows)
	}
}

func checkEvidence(t *testing.T, root, id, evidence string) {
	t.Helper()
	if evidence == "" {
		t.Fatalf("fixture %s: implemented row has no evidence", id)
	}
	sep := strings.LastIndexByte(evidence, ':')
	if sep <= 0 || sep == len(evidence)-1 {
		t.Fatalf("fixture %s: evidence must be path:TestName, got %q", id, evidence)
	}
	path, testName := evidence[:sep], evidence[sep+1:]
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("fixture %s: evidence file %q: %v", id, path, err)
	}
	baseName := testName
	if i := strings.IndexByte(baseName, '('); i >= 0 {
		baseName = baseName[:i]
	}
	needle := fmt.Sprintf("func %s(", baseName)
	if !strings.Contains(string(raw), needle) {
		t.Fatalf("fixture %s: evidence test %q not found in %s", id, testName, path)
	}
}
