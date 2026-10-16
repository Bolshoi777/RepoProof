package verifier

import (
	"testing"
)

func TestAcceptanceTable(t *testing.T) {
	// Mirrors docs/04_TEST_AND_ACCEPTANCE.md section 2 (T01..T10).
	cases := []struct {
		id   string
		in   Inputs
		want Status
	}{
		{"T01 verified", Inputs{Setup: PhasePass, Launch: PhasePass, Oracle: OraclePass}, StatusVerified},
		{"T02 behavior fail", Inputs{Setup: PhasePass, Launch: PhasePass, Oracle: OracleFail}, StatusBehaviorFail},
		{"T03 launch fail", Inputs{Setup: PhasePass, Launch: PhaseFail, Oracle: OracleNotRun}, StatusLaunchFail},
		{"T04 install fail", Inputs{Setup: PhaseFail, Oracle: OracleNotRun}, StatusInstallFail},
		{"T05 no oracle", Inputs{Setup: PhasePass, Launch: PhasePass, Oracle: OracleAbsent}, StatusPartial},
		{"T06 external unknown", Inputs{Setup: PhasePass, Launch: PhasePass, Oracle: OracleUnknown}, StatusInconclusive},
		{"T07 worker blocked", Inputs{WorkerBlocked: true}, StatusBlockedSecurity},
		{"T08 unsupported", Inputs{Unsupported: true}, StatusUnsupported},
		{"T09 broken oracle", Inputs{Setup: PhasePass, Launch: PhasePass, Oracle: OracleBroken}, StatusErrorInternal},
		{"T10 cancelled", Inputs{Cancelled: true}, StatusCancelled},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if got := Decide(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPriorityOrder(t *testing.T) {
	cases := []struct {
		name string
		in   Inputs
		want Status
	}{
		{
			"cancel beats everything",
			Inputs{Setup: PhaseFail, Cancelled: true, WorkerBlocked: true, Unsupported: true},
			StatusCancelled,
		},
		{
			"broken oracle beats repo failure",
			Inputs{Setup: PhaseFail, Launch: PhaseFail, Oracle: OracleBroken},
			StatusErrorInternal,
		},
		{
			"no engine beats worker block",
			Inputs{EnvironmentBlocked: true, WorkerBlocked: true},
			StatusBlockedEnv,
		},
		{
			"block beats phase failure",
			Inputs{Setup: PhaseFail, WorkerBlocked: true},
			StatusBlockedSecurity,
		},
		{
			"unsupported beats phase failure",
			Inputs{Setup: PhaseFail, Unsupported: true},
			StatusUnsupported,
		},
		{
			"docs mismatch outranks install fail",
			Inputs{Setup: PhaseFail, DocsMismatch: true},
			StatusDocsFail,
		},
		{
			"setup not run is inconclusive, not verified",
			Inputs{Setup: PhaseNotRun, Launch: PhaseNotRun, Oracle: OraclePass},
			StatusInconclusive,
		},
		{
			"launch not run is inconclusive",
			Inputs{Setup: PhasePass, Launch: PhaseNotRun, Oracle: OraclePass},
			StatusInconclusive,
		},
		{
			"oracle not run is partial",
			Inputs{Setup: PhasePass, Launch: PhasePass, Oracle: OracleNotRun},
			StatusPartial,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decide(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNoFalseVerified exhausts the input space: VERIFIED must imply
// passed setup, passed launch and a passed oracle, with no blocks.
func TestNoFalseVerified(t *testing.T) {
	phases := []Phase{PhasePass, PhaseFail, PhaseNotRun}
	oracles := []Oracle{OraclePass, OracleFail, OracleAbsent, OracleUnknown, OracleNotRun, OracleBroken}
	flags := []bool{false, true}
	n := 0
	for _, s := range phases {
		for _, l := range phases {
			for _, o := range oracles {
				for _, docs := range flags {
					for _, env := range flags {
						for _, wb := range flags {
							for _, un := range flags {
								for _, c := range flags {
									in := Inputs{Setup: s, Launch: l, Oracle: o, DocsMismatch: docs,
										EnvironmentBlocked: env, WorkerBlocked: wb, Unsupported: un, Cancelled: c}
									if Decide(in) == StatusVerified {
										n++
										if s != PhasePass || l != PhasePass || o != OraclePass ||
											env || wb || un || c {
											t.Fatalf("false VERIFIED for %+v", in)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("VERIFIED unreachable: over-constrained")
	}
	t.Logf("verified reachable in %d input combos, all sound", n)
}
