// Package verifier evaluates recorded observations into proof
// verdicts (G3). It never executes anything: all inputs are already
// observed step outcomes, and Decide is a pure function. The central
// invariant (RP-012, ADR-002): VERIFIED requires a passed functional
// oracle plus passed setup and launch; exit 0 alone proves nothing.
package verifier

// Status is the proof verdict. It extends the report schema enum with
// BLOCKED_ENVIRONMENT (RP-SBX-CHANGE-001); the schema file gains the
// value in G3 (DEBT-014).
type Status string

const (
	StatusVerified        Status = "VERIFIED"
	StatusBehaviorFail    Status = "BEHAVIOR_FAIL"
	StatusLaunchFail      Status = "LAUNCH_FAIL"
	StatusInstallFail     Status = "INSTALL_FAIL"
	StatusDocsFail        Status = "DOCS_FAIL"
	StatusPartial         Status = "PARTIAL"
	StatusInconclusive    Status = "INCONCLUSIVE"
	StatusUnsupported     Status = "UNSUPPORTED"
	StatusBlockedSecurity Status = "BLOCKED_SECURITY"
	StatusBlockedEnv      Status = "BLOCKED_ENVIRONMENT"
	StatusErrorInternal   Status = "ERROR_INTERNAL"
	StatusCancelled       Status = "CANCELLED"
)

// Phase is a setup/launch outcome.
type Phase string

const (
	PhasePass   Phase = "pass"
	PhaseFail   Phase = "fail"
	PhaseNotRun Phase = "not_run"
)

// Oracle is the functional oracle outcome. Absent means no oracle was
// defined; unknown means an external dependency left the outcome
// undecidable; broken means RepoProof's own oracle engine failed.
type Oracle string

const (
	OraclePass    Oracle = "pass"
	OracleFail    Oracle = "fail"
	OracleAbsent  Oracle = "absent"
	OracleUnknown Oracle = "unknown_external"
	OracleNotRun  Oracle = "not_run"
	OracleBroken  Oracle = "broken_engine"
)

// Inputs pins every fact Decide may use. No hidden defaults: the
// caller states explicitly what happened, including failures of
// RepoProof itself.
type Inputs struct {
	Setup        Phase
	Launch       Phase
	Oracle       Oracle
	DocsMismatch bool // setup failed on a documented command vs repo mismatch

	EnvironmentBlocked bool // no usable container engine
	WorkerBlocked      bool // attestation/policy denial
	Unsupported        bool // stack out of scope
	Cancelled          bool // operator abort
}

// Decide maps observations to exactly one verdict. Priority is
// fail-closed and fixed: abort and RepoProof-internal failures outrank
// repository failures, and any block outranks phase outcomes, so a
// missing oracle or a dead worker can never read as VERIFIED.
func Decide(in Inputs) Status {
	switch {
	case in.Cancelled:
		return StatusCancelled
	case in.Oracle == OracleBroken:
		return StatusErrorInternal
	case in.EnvironmentBlocked:
		return StatusBlockedEnv
	case in.WorkerBlocked:
		return StatusBlockedSecurity
	case in.Unsupported:
		return StatusUnsupported
	}
	if in.Setup != PhasePass {
		if in.DocsMismatch {
			return StatusDocsFail
		}
		if in.Setup == PhaseFail {
			return StatusInstallFail
		}
		return StatusInconclusive
	}
	if in.Launch != PhasePass {
		if in.Launch == PhaseFail {
			return StatusLaunchFail
		}
		return StatusInconclusive
	}
	switch in.Oracle {
	case OraclePass:
		return StatusVerified
	case OracleFail:
		return StatusBehaviorFail
	case OracleAbsent, OracleNotRun:
		return StatusPartial
	default:
		return StatusInconclusive
	}
}
