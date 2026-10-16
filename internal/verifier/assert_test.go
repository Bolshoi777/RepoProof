package verifier

import (
	"testing"
)

func TestEvaluate(t *testing.T) {
	obs := Observation{ExitCode: 0, Stdout: "hello repoproof\n"}
	ok, failed := Evaluate([]Assertion{
		{ID: "exit", Type: AssertExitCodeEquals, Expected: "0"},
		{ID: "out", Type: AssertStdoutContains, Expected: "repoproof"},
	}, obs)
	if !ok || len(failed) != 0 {
		t.Fatalf("pass case failed: %v", failed)
	}

	// exit 0 with wrong output must fail: the anti-false-VERIFIED core.
	ok, failed = Evaluate([]Assertion{
		{ID: "exit", Type: AssertExitCodeEquals, Expected: "0"},
		{ID: "out", Type: AssertStdoutContains, Expected: "expected-text"},
	}, obs)
	if ok || len(failed) != 1 || failed[0] != "out" {
		t.Fatalf("wrong-output case: ok=%v failed=%v", ok, failed)
	}

	ok, failed = Evaluate([]Assertion{
		{ID: "x", Type: "http_status", Expected: "200"},
	}, obs)
	if ok {
		t.Fatal("unknown assertion kind must not pass")
	}

	ok, failed = Evaluate([]Assertion{
		{ID: "e", Type: AssertExitCodeEquals, Expected: "not-a-number"},
	}, obs)
	if ok {
		t.Fatal("non-numeric exit expectation must not pass")
	}
}

func TestEvaluateHTTP(t *testing.T) {
	obs := Observation{ExitCode: 0, Stdout: "up",
		HTTP: &HTTPResponse{Status: 200, Body: "ok healthy"}}
	ok, failed := Evaluate([]Assertion{
		{ID: "s", Type: AssertHTTPStatus, Expected: "200"},
		{ID: "b", Type: AssertHTTPBody, Expected: "healthy"},
	}, obs)
	if !ok {
		t.Fatalf("http pass case failed: %v", failed)
	}

	// 200 with the wrong body, and 404 instead of 200, must fail:
	// a live port never implies a verified behavior.
	ok, _ = Evaluate([]Assertion{
		{ID: "b", Type: AssertHTTPBody, Expected: "ready"},
	}, obs)
	if ok {
		t.Fatal("wrong body must fail")
	}
	ok, _ = Evaluate([]Assertion{
		{ID: "s", Type: AssertHTTPStatus, Expected: "200"},
	}, Observation{HTTP: &HTTPResponse{Status: 404, Body: "nope"}})
	if ok {
		t.Fatal("404 must fail a 200 assertion")
	}
	ok, _ = Evaluate([]Assertion{
		{ID: "s", Type: AssertHTTPStatus, Expected: "200"},
	}, Observation{})
	if ok {
		t.Fatal("missing probe must fail http assertions")
	}
}

func TestOracleFromOutcome(t *testing.T) {
	if OracleFromOutcome(true) != OraclePass || OracleFromOutcome(false) != OracleFail {
		t.Fatal("outcome mapping wrong")
	}
}
