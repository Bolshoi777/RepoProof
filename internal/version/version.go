// Package version holds build-time identity constants shared by CLI, GUI
// and report writers. Single source of truth for schema and exit codes
// (provisional codes per docs/02_ARCHITECTURE.md section 9, final
// confirmation in G2-02).
package version

// ModuleVersion is the RepoProof core version. Overridden at release
// build time via -ldflags; defaults to the dev marker below.
var ModuleVersion = "0.0.1-g0"

// ReportSchemaVersion must match specs/report.schema.json
// properties.schema_version.const.
const ReportSchemaVersion = "1.0"

// Provisional CLI exit codes (docs/02_ARCHITECTURE.md section 9 +
// RP-SBX-CHANGE-001: 14 for missing container runtime).
// Final confirmation and tests for all user-facing paths in G2-02.
const (
	ExitVerified           = 0   // VERIFIED
	ExitCheckFailed        = 10  // CHECK_FAILED (BEHAVIOR/LAUNCH/INSTALL/DOCS_FAIL)
	ExitInconclusive       = 11  // PARTIAL/INCONCLUSIVE
	ExitUnsupported        = 12  // UNSUPPORTED
	ExitBlockedSecurity    = 13  // BLOCKED_SECURITY (fail-closed, no worker)
	ExitBlockedEnvironment = 14  // BLOCKED_ENVIRONMENT (no usable container engine)
	ExitInternalError      = 20  // INTERNAL_ERROR / not-yet-implemented slice
	ExitCancelled          = 130 // CANCELLED
)

// Mode describes the execution capability compiled into this binary.
// Until G2 attests an isolated worker, the only honest value is
// "inspect-only".
const Mode = "inspect-only"
