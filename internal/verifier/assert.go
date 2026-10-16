package verifier

import (
	"fmt"
	"strconv"
	"strings"
)

// Assertion kinds evaluated by this package (v1 subset from
// docs/02_ARCHITECTURE.md section 7). Kinds not listed here fail
// closed when evaluated.
const (
	AssertExitCodeEquals = "exit_code_equals"
	AssertStdoutContains = "stdout_contains"
	AssertHTTPStatus     = "http_status"
	AssertHTTPBody       = "http_body_contains"
)

// Assertion is one check against recorded output.
type Assertion struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Expected string `json:"expected"`
}

// Observation is already-recorded step output. Nothing here executes.
// HTTP holds a recorded probe response; nil means no probe ran.
type Observation struct {
	ExitCode int
	Stdout   string
	HTTP     *HTTPResponse
}

// HTTPResponse is a recorded contained-probe result.
type HTTPResponse struct {
	Status int
	Body   string
}

// Evaluate runs every assertion against the observation, returning
// overall pass plus the IDs that failed. Unknown assertion kinds
// fail the check (never silently pass). HTTP assertions without a
// recorded probe fail (no probe, no proof).
func Evaluate(assertions []Assertion, obs Observation) (bool, []string) {
	failed := []string{}
	for _, a := range assertions {
		switch a.Type {
		case AssertExitCodeEquals:
			want, err := strconv.Atoi(strings.TrimSpace(a.Expected))
			if err != nil || obs.ExitCode != want {
				failed = append(failed, a.ID)
			}
		case AssertStdoutContains:
			if a.Expected == "" || !strings.Contains(obs.Stdout, a.Expected) {
				failed = append(failed, a.ID)
			}
		case AssertHTTPStatus:
			want, err := strconv.Atoi(strings.TrimSpace(a.Expected))
			if err != nil || obs.HTTP == nil || obs.HTTP.Status != want {
				failed = append(failed, a.ID)
			}
		case AssertHTTPBody:
			if a.Expected == "" || obs.HTTP == nil || !strings.Contains(obs.HTTP.Body, a.Expected) {
				failed = append(failed, a.ID)
			}
		default:
			failed = append(failed, a.ID+fmt.Sprintf(" (unknown assertion type %q)", a.Type))
		}
	}
	return len(failed) == 0, failed
}

// OracleFromOutcome maps evaluation to an oracle verdict input:
// all-passed -> pass, anything else -> fail. Absence of assertions
// is NOT handled here (caller maps it to absent/PARTIAL).
func OracleFromOutcome(pass bool) Oracle {
	if pass {
		return OraclePass
	}
	return OracleFail
}
