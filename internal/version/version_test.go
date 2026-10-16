package version

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVersionNonEmpty(t *testing.T) {
	if ModuleVersion == "" {
		t.Fatal("ModuleVersion must not be empty")
	}
	if Mode != "inspect-only" {
		t.Fatalf("G0/G1 Mode must be inspect-only, got %q", Mode)
	}
}

func TestExitCodesDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, code := range map[string]int{
		"ExitVerified":           ExitVerified,
		"ExitCheckFailed":        ExitCheckFailed,
		"ExitInconclusive":       ExitInconclusive,
		"ExitUnsupported":        ExitUnsupported,
		"ExitBlockedSecurity":    ExitBlockedSecurity,
		"ExitBlockedEnvironment": ExitBlockedEnvironment,
		"ExitInternalError":      ExitInternalError,
		"ExitCancelled":          ExitCancelled,
	} {
		if prev, dup := seen[code]; dup {
			t.Fatalf("exit code %d shared by %s and %s", code, prev, name)
		}
		seen[code] = name
	}
	if ExitVerified != 0 {
		t.Fatalf("ExitVerified must be 0, got %d", ExitVerified)
	}
	if ExitBlockedSecurity != 13 {
		t.Fatalf("ExitBlockedSecurity must be 13, got %d", ExitBlockedSecurity)
	}
	if ExitBlockedEnvironment != 14 {
		t.Fatalf("ExitBlockedEnvironment must be 14, got %d", ExitBlockedEnvironment)
	}
}

// TestReportSchemaVersionMatchesSpec guards the contract between code and
// specs/report.schema.json using stdlib JSON only (no new dependencies).
func TestReportSchemaVersionMatchesSpec(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	schemaPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "specs", "report.schema.json")
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Properties struct {
			SchemaVersion struct {
				Const string `json:"const"`
			} `json:"schema_version"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	if schema.Properties.SchemaVersion.Const != ReportSchemaVersion {
		t.Fatalf("schema const %q != code %q",
			schema.Properties.SchemaVersion.Const, ReportSchemaVersion)
	}
	for _, field := range []string{"schema_version", "run_id", "status", "snapshot", "environment"} {
		found := false
		for _, req := range schema.Required {
			if req == field {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("schema required missing %q", field)
		}
	}
}
