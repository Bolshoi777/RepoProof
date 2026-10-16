// Proof reports (W2): schema-validated verdict documents per
// specs/report.schema.json. Built only from recorded outcomes —
// never from live execution — and validated by construction before
// any --json artefact is written.
package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/redact"
	"github.com/repoproof/repoproof/internal/verifier"
	"github.com/repoproof/repoproof/internal/version"
	"github.com/repoproof/repoproof/internal/worker"
)

// ProofStatusEnum mirrors the report schema status enum, including
// BLOCKED_ENVIRONMENT (DEBT-014 closes here).
var ProofStatusEnum = []string{
	"VERIFIED", "BEHAVIOR_FAIL", "LAUNCH_FAIL", "INSTALL_FAIL",
	"DOCS_FAIL", "PARTIAL", "INCONCLUSIVE", "UNSUPPORTED",
	"BLOCKED_SECURITY", "BLOCKED_ENVIRONMENT", "ERROR_INTERNAL", "CANCELLED",
}

// ProofLevelEnum mirrors the schema level enum.
var ProofLevelEnum = []string{"PASS", "FAIL", "NOT_RUN", "UNKNOWN"}

// ProofStep is one executed step with its evidence reference.
type ProofStep struct {
	ID          string
	Phase       string
	Command     string
	ExitCode    int
	Output      string
	Error       string
	EvidenceRef string
}

// ProofInput is everything a proof report needs, all previously recorded.
type ProofInput struct {
	RunID       string
	Verdict     verifier.Status
	Setup       verifier.Phase
	Launch      verifier.Phase
	Oracle      verifier.Oracle
	Steps       []ProofStep
	Assertions  []verifier.Assertion
	Limitations []string
}

type proofSnap struct {
	Source      string  `json:"source"`
	Commit      *string `json:"commit"`
	Fingerprint string  `json:"source_fingerprint"`
}

type proofEnv struct {
	WorkerKind   string                `json:"worker_kind"`
	ImageDigest  string                `json:"image_digest"`
	Attested     bool                  `json:"attested"`
	NetworkMode  string                `json:"network_mode"`
	PolicyDigest string                `json:"policy_digest"`
	AppVersion   string                `json:"app_version"`
	Limits       worker.ResourceLimits `json:"limits"`
}

type proofLevels struct {
	Install  string `json:"install"`
	Launch   string `json:"launch"`
	Behavior string `json:"behavior"`
}

type proofStepOut struct {
	ID       string `json:"id"`
	Phase    string `json:"phase"`
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
}

type proofCheck struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Expected    string `json:"expected"`
	Observed    string `json:"observed"`
	Result      string `json:"result"`
	EvidenceRef string `json:"evidence_ref"`
}

type proofEvidence struct {
	Ref       string `json:"ref"`
	SHA256    string `json:"sha256"`
	Sanitized bool   `json:"sanitized"`
}

type proofReport struct {
	SchemaVersion string          `json:"schema_version"`
	RunID         string          `json:"run_id"`
	Status        string          `json:"status"`
	Snapshot      proofSnap       `json:"snapshot"`
	Environment   proofEnv        `json:"environment"`
	Levels        proofLevels     `json:"levels"`
	Steps         []proofStepOut  `json:"steps"`
	Checks        []proofCheck    `json:"checks"`
	Limitations   []string        `json:"limitations"`
	Evidence      []proofEvidence `json:"evidence"`
}

func phaseLevel(p verifier.Phase) string {
	switch p {
	case verifier.PhasePass:
		return "PASS"
	case verifier.PhaseFail:
		return "FAIL"
	default:
		return "NOT_RUN"
	}
}

func oracleLevel(o verifier.Oracle) string {
	switch o {
	case verifier.OraclePass:
		return "PASS"
	case verifier.OracleFail:
		return "FAIL"
	case verifier.OracleAbsent, verifier.OracleNotRun:
		return "NOT_RUN"
	default:
		return "UNKNOWN"
	}
}

// lastLaunch returns the most recent launch step (the observed side of
// every check) or nil.
func lastLaunch(steps []ProofStep) *ProofStep {
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].Phase == "launch" {
			return &steps[i]
		}
	}
	return nil
}

// BuildProofReport assembles and validates the verdict document.
func BuildProofReport(snap *inspector.Snapshot, att worker.Attestation, in ProofInput) ([]byte, error) {
	rep := proofReport{
		SchemaVersion: "1.0",
		RunID:         in.RunID,
		Status:        string(in.Verdict),
		Snapshot: proofSnap{
			Source: snap.Source, Commit: snap.Commit, Fingerprint: snap.Fingerprint,
		},
		Environment: proofEnv{
			WorkerKind: att.WorkerKind, ImageDigest: att.ImageDigest,
			Attested: att.Attested, NetworkMode: string(att.Network),
			PolicyDigest: att.PolicyDigest, AppVersion: version.ModuleVersion,
			Limits: att.Limits,
		},
		Levels: proofLevels{
			Install: phaseLevel(in.Setup), Launch: phaseLevel(in.Launch),
			Behavior: oracleLevel(in.Oracle),
		},
		Checks:      []proofCheck{},
		Steps:       []proofStepOut{},
		Limitations: append([]string{}, append(snap.Limitations, in.Limitations...)...),
		Evidence:    []proofEvidence{},
	}
	for _, s := range in.Steps {
		rep.Steps = append(rep.Steps, proofStepOut{
			ID: s.ID, Phase: s.Phase, Command: s.Command, ExitCode: s.ExitCode,
		})
	}
	last := lastLaunch(in.Steps)
	for _, a := range in.Assertions {
		obs := verifier.Observation{}
		if last != nil {
			obs = verifier.Observation{ExitCode: last.ExitCode, Stdout: last.Output}
		}
		ok, _ := verifier.Evaluate([]verifier.Assertion{a}, obs)
		result := "FAIL"
		if ok {
			result = "PASS"
		}
		observed, ref := "", ""
		if last != nil {
			ref = last.EvidenceRef
			switch a.Type {
			case verifier.AssertExitCodeEquals:
				observed = fmt.Sprint(last.ExitCode)
			default:
				// Exported proof JSON is shareable. Keep exact bytes in the
				// evidence store referenced by ref, but redact display text
				// before it enters the report itself.
				observed = redact.RedactText(last.Output)
				if len(observed) > 4096 {
					observed = observed[:4096]
				}
			}
		}
		rep.Checks = append(rep.Checks, proofCheck{
			ID: a.ID, Type: a.Type, Expected: a.Expected,
			Observed: observed, Result: result, EvidenceRef: ref,
		})
	}
	seen := map[string]bool{}
	for _, s := range in.Steps {
		if s.EvidenceRef == "" || seen[s.EvidenceRef] {
			continue
		}
		seen[s.EvidenceRef] = true
		rep.Evidence = append(rep.Evidence, proofEvidence{Ref: s.EvidenceRef, SHA256: s.EvidenceRef})
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := ValidateProofReport(raw); err != nil {
		return nil, fmt.Errorf("proof report violates schema contract: %w", err)
	}
	return append(raw, '\n'), nil
}

// ValidateProofReport checks a proof document against the contract in
// specs/report.schema.json (stdlib only).
func ValidateProofReport(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	for _, f := range []string{"schema_version", "run_id", "status", "snapshot",
		"environment", "levels", "checks", "limitations", "evidence"} {
		if _, ok := m[f]; !ok {
			return fmt.Errorf("missing field %q", f)
		}
	}
	if v, _ := m["schema_version"].(string); v != "1.0" {
		return fmt.Errorf("schema_version must be \"1.0\"")
	}
	st, _ := m["status"].(string)
	if !inProofSet(ProofStatusEnum, st) {
		return fmt.Errorf("status %q not in enum", st)
	}
	snap, ok := m["snapshot"].(map[string]any)
	if !ok {
		return fmt.Errorf("snapshot must be an object")
	}
	for _, f := range []string{"source", "commit", "source_fingerprint"} {
		if _, ok := snap[f]; !ok {
			return fmt.Errorf("snapshot missing %q", f)
		}
	}
	if c := snap["commit"]; c != nil {
		if _, ok := c.(string); !ok {
			return fmt.Errorf("commit must be null or string")
		}
	}
	fp, _ := snap["source_fingerprint"].(string)
	if !hex64.MatchString(fp) {
		return fmt.Errorf("source_fingerprint must be 64-hex")
	}
	env, ok := m["environment"].(map[string]any)
	if !ok {
		return fmt.Errorf("environment must be an object")
	}
	for _, f := range []string{"worker_kind", "image_digest", "attested", "network_mode", "policy_digest"} {
		if _, ok := env[f]; !ok {
			return fmt.Errorf("environment missing %q", f)
		}
	}
	if _, ok := env["attested"].(bool); !ok {
		return fmt.Errorf("attested must be a boolean")
	}
	if v, ok := env["app_version"]; ok {
		if _, ok := v.(string); !ok {
			return fmt.Errorf("app_version must be a string")
		}
	}
	if lim, ok := env["limits"]; ok {
		lm, ok := lim.(map[string]any)
		if !ok {
			return fmt.Errorf("limits must be an object")
		}
		for _, f := range []string{"cpu_cores", "memory_mb", "disk_mb", "wall_seconds", "max_output_bytes"} {
			n, ok := lm[f].(float64)
			if !ok || n < 0 || n != float64(int(n)) {
				return fmt.Errorf("limits.%s must be a non-negative integer", f)
			}
		}
	}
	lv, ok := m["levels"].(map[string]any)
	if !ok {
		return fmt.Errorf("levels must be an object")
	}
	for _, f := range []string{"install", "launch", "behavior"} {
		v, _ := lv[f].(string)
		if !inProofSet(ProofLevelEnum, v) {
			return fmt.Errorf("levels.%s %q not in enum", f, v)
		}
	}
	checks, ok := m["checks"].([]any)
	if !ok {
		return fmt.Errorf("checks must be an array")
	}
	for i, cv := range checks {
		cm, ok := cv.(map[string]any)
		if !ok {
			return fmt.Errorf("checks[%d] must be an object", i)
		}
		for _, f := range []string{"id", "type", "expected", "observed", "result", "evidence_ref"} {
			if _, ok := cm[f]; !ok {
				return fmt.Errorf("checks[%d] missing %q", i, f)
			}
		}
		if r, _ := cm["result"].(string); !inProofSet(ProofLevelEnum, r) {
			return fmt.Errorf("checks[%d].result %q not in enum", i, r)
		}
	}
	if sv, ok := m["steps"]; ok && sv != nil {
		steps, ok := sv.([]any)
		if !ok {
			return fmt.Errorf("steps must be an array")
		}
		for i, sv := range steps {
			sm, ok := sv.(map[string]any)
			if !ok {
				return fmt.Errorf("steps[%d] must be an object", i)
			}
			for _, f := range []string{"id", "phase", "command", "exit_code"} {
				if _, ok := sm[f]; !ok {
					return fmt.Errorf("steps[%d] missing %q", i, f)
				}
			}
		}
	}
	lims, ok := m["limitations"].([]any)
	if !ok {
		return fmt.Errorf("limitations must be an array")
	}
	for _, v := range lims {
		if _, ok := v.(string); !ok {
			return fmt.Errorf("limitations must be strings")
		}
	}
	evs, ok := m["evidence"].([]any)
	if !ok {
		return fmt.Errorf("evidence must be an array")
	}
	for i, ev := range evs {
		em, ok := ev.(map[string]any)
		if !ok {
			return fmt.Errorf("evidence[%d] must be an object", i)
		}
		for _, f := range []string{"ref", "sha256", "sanitized"} {
			if _, ok := em[f]; !ok {
				return fmt.Errorf("evidence[%d] missing %q", i, f)
			}
		}
		if s, _ := em["sha256"].(string); !hex64.MatchString(s) {
			return fmt.Errorf("evidence[%d].sha256 must be 64-hex", i)
		}
		if _, ok := em["sanitized"].(bool); !ok {
			return fmt.Errorf("evidence[%d].sanitized must be a boolean", i)
		}
	}
	return nil
}

func inProofSet(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
