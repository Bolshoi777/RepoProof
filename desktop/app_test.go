package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/app"
)

// TestBindingsMatchCLI is the G4 parity gate: UI-bound methods return
// the same Core output as the CLI path, byte for byte.
func TestBindingsMatchCLI(t *testing.T) {
	ui := NewApp()
	got, err := ui.Inspect(filepath.Join("..", "fixtures", "readme-case"))
	if err != nil {
		t.Fatalf("ui inspect: %v", err)
	}
	want, err := app.Inspect(filepath.Join("..", "fixtures", "readme-case"))
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatal("UI inspect JSON differs from service output")
	}

	planGot, err := ui.Plan(filepath.Join("..", "fixtures", "readme-case"))
	if err != nil {
		t.Fatalf("ui plan: %v", err)
	}
	planWant, err := app.BuildPlan(filepath.Join("..", "fixtures", "readme-case"))
	if err != nil {
		t.Fatal(err)
	}
	if planGot != string(planWant) {
		t.Fatal("UI plan JSON differs from service output")
	}
}

// TestInspectAndPlanBinding covers the single-pass desktop path and keeps
// cancellation exposed as an explicit, fail-closed binding when idle.
func TestInspectAndPlanBinding(t *testing.T) {
	ui := NewApp()
	raw, err := ui.InspectAndPlan(filepath.Join("..", "fixtures", "readme-case"))
	if err != nil {
		t.Fatalf("inspect and plan: %v", err)
	}
	var payload struct {
		Inspect map[string]any `json:"inspect"`
		Plan    map[string]any `json:"plan"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Inspect) == 0 || len(payload.Plan) == 0 {
		t.Fatalf("single-pass response missing report or plan: %s", raw)
	}
	if _, err := ui.CancelInspect(); err == nil {
		t.Fatal("idle inspect cancellation must fail closed")
	}
}

// TestDraftApprovalBinding runs the approval draft through the UI
// binding against a temp project (outside the repo fixtures).
func TestDraftApprovalBinding(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("## Run\n\n```sh\necho H\n```\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	contractPath := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(contractPath, []byte(`version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 60, max_output_bytes: 65536, install_network: none, verify_network: guest-only}
steps:
  - {id: s1, phase: launch, from_readme: true}
proof:
  - {id: p1, type: exit_code_equals, expected: 0}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	ui := NewApp()
	raw, err := ui.DraftApproval(dir, contractPath, "ui test", true)
	if err != nil {
		t.Fatalf("ui approve: %v", err)
	}
	var d map[string]string
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}
	if d["path"] == "" || d["summary"] == "" {
		t.Fatalf("binding returned incomplete: %v", d)
	}
	if _, err := os.Stat(d["path"]); err != nil {
		t.Fatalf("approval file missing: %v", err)
	}
	approvalRaw, err := os.ReadFile(d["path"])
	if err != nil {
		t.Fatal(err)
	}
	var approval map[string]any
	if err := json.Unmarshal(approvalRaw, &approval); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"contract_fingerprint", "dependency_fingerprint"} {
		if value, ok := approval[field].(string); !ok || value == "" {
			t.Fatalf("approval missing %s: %v", field, approval)
		}
	}
}

// TestStartCheckBinding runs the automatic chain through the UI
// binding and polls for the PARTIAL verdict.
func TestStartCheckBinding(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("## Run\n\n```sh\necho H\n```\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ui := NewApp()
	if _, err := ui.StartCheck("", true); err == nil {
		t.Fatal("empty path must fail")
	}
	if _, err := ui.StartCheck(dir, false); err == nil {
		t.Fatal("unconfirmed check must fail")
	}
	runID, err := ui.StartCheck(dir, true)
	if err != nil {
		t.Fatalf("start check: %v", err)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		raw, err := ui.VerifyResult(runID)
		if err != nil {
			t.Fatal(err)
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatal(err)
		}
		if done, _ := r["done"].(bool); done {
			if exit, _ := r["exit"].(float64); exit != 13 {
				t.Fatalf("exit = %v, want 13 (BLOCKED_SECURITY)", exit)
			}
			if !strings.Contains(r["summary"].(string), "BLOCKED_SECURITY") {
				t.Fatalf("summary missing BLOCKED_SECURITY: %v", r["summary"])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("check run did not finish")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestSupportStatusBinding checks the status-bar probe shape.
func TestSupportStatusBinding(t *testing.T) {
	ui := NewApp()
	raw, err := ui.SupportStatus()
	if err != nil {
		t.Fatalf("ui support: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["supported"]; !ok {
		t.Fatalf("status shape wrong: %v", m)
	}
}
