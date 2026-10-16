// Command repoproof is the RepoProof CLI entry point.
//
// The CLI delegates inspection, planning, approval, replay and verification
// to the shared Core. Verification remains fail-closed until the native
// worker has an independent security attestation; there is no host fallback.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/repoproof/repoproof/internal/app"
	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/reporter"
	"github.com/repoproof/repoproof/internal/sandbox"
	"github.com/repoproof/repoproof/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI against explicit writers so unit tests can capture
// output without spawning processes. Returns a provisional exit code
// (see internal/version).
func run(args []string, stdout, stderr io.Writer) int {
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	fs := flag.NewFlagSet("repoproof", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return version.ExitInternalError
	}
	rest := fs.Args()

	if *showVersion || (len(rest) == 1 && rest[0] == "version") {
		fmt.Fprintf(stdout, "repoproof %s (schema %s, mode %s)\n",
			version.ModuleVersion, version.ReportSchemaVersion, version.Mode)
		return version.ExitVerified
	}

	if len(rest) == 0 {
		usage(stderr)
		return version.ExitInternalError
	}

	switch rest[0] {
	case "doctor":
		support := sandbox.ProbeSupport()
		fmt.Fprintf(stdout, "mode: %s\n", version.Mode)
		fmt.Fprintf(stdout, "worker: none (execute disabled until G2 attestation)\n")
		fmt.Fprintf(stdout, "native_sandbox: supported=%t\n", support.Supported)
		if support.Reason != "" {
			fmt.Fprintf(stdout, "native_sandbox_reason: %s\n", support.Reason)
		}
		fmt.Fprintf(stdout, "go: %s\n", runtime.Version())
		fmt.Fprintf(stdout, "report_schema: %s\n", version.ReportSchemaVersion)
		logger.Info("doctor", "mode", version.Mode)
		return version.ExitVerified
	case "inspect":
		return runInspect(rest[1:], stdout, stderr, logger)
	case "plan":
		return runPlan(rest[1:], stdout, stderr, logger)
	case "approve":
		return runApprove(rest[1:], stdout, stderr, logger)
	case "replay":
		return runReplay(rest[1:], stdout, stderr, logger)
	case "check":
		return runCheck(rest[1:], stdout, stderr, logger)
	case "verify":
		return runVerify(rest[1:], stdout, stderr, logger)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", rest[0])
		usage(stderr)
		return version.ExitInternalError
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: repoproof [--version] <version|doctor|inspect|plan|approve|check|verify|replay>")
	fmt.Fprintln(w, "  inspect <path> [--json out.json] [--html out.html]  read-only static inspection, executes nothing")
	fmt.Fprintln(w, "  plan <path> [--json out.json]      candidate execution plan for review (never executes)")
	fmt.Fprintln(w, "  verify <path> --contract c.yaml --approve-file a.json [--json out.json] [--html out.html] [--evidence-dir d] [--no-provision]")
	fmt.Fprintln(w, "      approved sandboxed verification run (never executes on host)")
	fmt.Fprintln(w, "  approve <path> --contract c.yaml --statement \"...\" [--ack-all] --output a.json")
	fmt.Fprintln(w, "      draft the approval record for a reviewed plan (inspect-only, executes nothing)")
	fmt.Fprintln(w, "  replay <proof.json>")
	fmt.Fprintln(w, "      check whether a recorded verdict is reusable in the current environment")
	fmt.Fprintln(w, "  check <path> [--json out.json] [--html out.html] [--evidence-dir d] [--no-provision] --confirm-run")
	fmt.Fprintln(w, "      automatic run without oracle (verdict capped at PARTIAL); prints the plan first")
	fmt.Fprintln(w, "  verify stays blocked until the native worker security gate is attested; inspect/plan remain available.")
}

// runInspect implements `inspect <path> [--json out]`: strictly read-only,
// never executes repository content.
func runInspect(args []string, stdout, stderr io.Writer, logger *slog.Logger) int {
	var jsonOut, htmlOut string
	target := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json" && i+1 < len(args):
			i++
			jsonOut = args[i]
		case len(a) > 7 && a[:7] == "--json=":
			jsonOut = a[7:]
		case a == "--html" && i+1 < len(args):
			i++
			htmlOut = args[i]
		case len(a) > 7 && a[:7] == "--html=":
			htmlOut = a[7:]
		case len(a) > 1 && a[0] == '-':
			fmt.Fprintf(stderr, "inspect: unknown flag %q\n", a)
			return version.ExitInternalError
		case target == "":
			target = a
		default:
			fmt.Fprintf(stderr, "inspect: unexpected argument %q\n", a)
			return version.ExitInternalError
		}
	}
	if target == "" {
		fmt.Fprintln(stderr, "usage: repoproof inspect <path> [--json out.json] [--html out.html]")
		return version.ExitInternalError
	}

	rep, err := inspector.Inspect(target)
	if err != nil {
		fmt.Fprintf(stderr, "inspect: %v\n", err)
		return version.ExitInternalError
	}

	if jsonOut != "" {
		raw, merr := reporter.MarshalAndValidate(rep)
		if merr != nil {
			fmt.Fprintf(stderr, "inspect: %v\n", merr)
			return version.ExitInternalError
		}
		if werr := os.WriteFile(jsonOut, raw, 0o644); werr != nil {
			fmt.Fprintf(stderr, "inspect: write %s: %v\n", jsonOut, werr)
			return version.ExitInternalError
		}
		logger.Info("inspect json written", "path", jsonOut)
	}

	if htmlOut != "" {
		f, herr := os.Create(htmlOut)
		if herr != nil {
			fmt.Fprintf(stderr, "inspect: create %s: %v\n", htmlOut, herr)
			return version.ExitInternalError
		}
		herr = reporter.WriteHTML(&rep.Snapshot, planner.Build(&rep.Snapshot), f)
		cerr := f.Close()
		if herr != nil || cerr != nil {
			fmt.Fprintf(stderr, "inspect: write %s failed\n", htmlOut)
			return version.ExitInternalError
		}
		logger.Info("inspect html written", "path", htmlOut)
	}

	readme := "(none)"
	if rep.Readme != nil {
		readme = *rep.Readme
	}
	commit := "(none)"
	if rep.Commit != nil {
		commit = *rep.Commit
	}
	fmt.Fprintf(stdout, "source: %s\n", rep.Source)
	fmt.Fprintf(stdout, "commit: %s\n", commit)
	fmt.Fprintf(stdout, "fingerprint: %s\n", rep.Fingerprint)
	fmt.Fprintf(stdout, "stack: %s\n", rep.Stack)
	fmt.Fprintf(stdout, "support: %s\n", rep.Support)
	fmt.Fprintf(stdout, "readme: %s\n", readme)
	fmt.Fprintf(stdout, "indicators: %v\n", rep.Indicators)
	fmt.Fprintf(stdout, "files: %d\n", rep.FileCount)
	fmt.Fprintf(stdout, "commands: %d\n", len(rep.ReadmeSteps))
	fmt.Fprintf(stdout, "mode: inspect-only (nothing executed)\n")
	logger.Info("inspect ok", "source", rep.Source, "stack", string(rep.Stack))
	return version.ExitVerified
}

// runPlan implements `plan <path> [--json out]`: builds the candidate
// plan from a fresh read-only inspection. Output is review data;
// nothing is executed and nothing is approved by producing it.
func runPlan(args []string, stdout, stderr io.Writer, logger *slog.Logger) int {
	var jsonOut string
	target := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json" && i+1 < len(args):
			i++
			jsonOut = args[i]
		case len(a) > 7 && a[:7] == "--json=":
			jsonOut = a[7:]
		case len(a) > 1 && a[0] == '-':
			fmt.Fprintf(stderr, "plan: unknown flag %q\n", a)
			return version.ExitInternalError
		case target == "":
			target = a
		default:
			fmt.Fprintf(stderr, "plan: unexpected argument %q\n", a)
			return version.ExitInternalError
		}
	}
	if target == "" {
		fmt.Fprintln(stderr, "usage: repoproof plan <path> [--json out.json]")
		return version.ExitInternalError
	}

	rep, err := inspector.Inspect(target)
	if err != nil {
		fmt.Fprintf(stderr, "plan: %v\n", err)
		return version.ExitInternalError
	}
	p := planner.Build(&rep.Snapshot)

	if jsonOut != "" {
		raw, merr := json.MarshalIndent(p, "", "  ")
		if merr != nil {
			fmt.Fprintf(stderr, "plan: encode: %v\n", merr)
			return version.ExitInternalError
		}
		if werr := os.WriteFile(jsonOut, append(raw, '\n'), 0o644); werr != nil {
			fmt.Fprintf(stderr, "plan: write %s: %v\n", jsonOut, werr)
			return version.ExitInternalError
		}
	}

	fmt.Fprintf(stdout, "source: %s\n", p.Source)
	fmt.Fprintf(stdout, "stack: %s\n", p.Stack)
	fmt.Fprintf(stdout, "steps: %d\n", len(p.Steps))
	for _, s := range p.Steps {
		fmt.Fprintf(stdout, "  - %s [%s] %s (cwd=%s, timeout=%ds, network=%s, approval=required)\n",
			s.ID, s.Phase, s.Command, s.CWD, s.TimeoutSeconds, s.Network)
	}
	if p.NeedsReview {
		fmt.Fprintf(stdout, "needs_review: true\n")
		for _, r := range p.ReviewReasons {
			fmt.Fprintf(stdout, "  reason: %s\n", r)
		}
	} else {
		fmt.Fprintf(stdout, "needs_review: false\n")
	}
	logger.Info("plan ok", "source", p.Source, "steps", len(p.Steps), "needs_review", p.NeedsReview)
	return version.ExitVerified
}

// runApprove drafts the approval record for a reviewed plan. It only
// reads (inspect + plan + contract) and writes one JSON file: no
// execution, no approval granted implicitly. Unacknowledged review
// reasons stay empty unless --ack-all is passed explicitly, in which
// case they are listed on stdout for the record.
func runApprove(args []string, stdout, stderr io.Writer, logger *slog.Logger) int {
	var contractPath, statement, output string
	ackAll := false
	target := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--contract" && i+1 < len(args):
			i++
			contractPath = args[i]
		case len(a) > 11 && a[:11] == "--contract=":
			contractPath = a[11:]
		case a == "--statement" && i+1 < len(args):
			i++
			statement = args[i]
		case len(a) > 12 && a[:12] == "--statement=":
			statement = a[12:]
		case a == "--output" && i+1 < len(args):
			i++
			output = args[i]
		case len(a) > 9 && a[:9] == "--output=":
			output = a[9:]
		case a == "--ack-all":
			ackAll = true
		case len(a) > 1 && a[0] == '-':
			fmt.Fprintf(stderr, "approve: unknown flag %q\n", a)
			return version.ExitInternalError
		case target == "":
			target = a
		default:
			fmt.Fprintf(stderr, "approve: unexpected argument %q\n", a)
			return version.ExitInternalError
		}
	}
	if target == "" || contractPath == "" || output == "" || statement == "" {
		fmt.Fprintln(stderr, "usage: repoproof approve <path> --contract c.yaml --statement \"...\" [--ack-all] --output a.json")
		return version.ExitInternalError
	}

	summary, err := app.DraftApproval(target, contractPath, statement, ackAll, output)
	if err != nil {
		fmt.Fprintf(stderr, "approve: %v\n", err)
		return version.ExitInternalError
	}
	fmt.Fprint(stdout, summary)
	logger.Info("approve drafted", "path", output, "acked", ackAll)
	return version.ExitVerified
}

// runReplay checks one proof report against the current environment
// through the shared service layer. Read-only: no execution.
func runReplay(args []string, stdout, stderr io.Writer, logger *slog.Logger) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "usage: repoproof replay <proof.json>")
		return version.ExitInternalError
	}
	summary, code, err := app.ReplayReport(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "replay: %v\n", err)
		return version.ExitInternalError
	}
	fmt.Fprint(stdout, summary)
	logger.Info("replay checked", "report", args[0], "exit", code)
	return code
}

// runCheck implements the automatic path: prints the plan for review,
// then runs only with explicit --confirm-run. See app.CheckTarget.
func runCheck(args []string, stdout, stderr io.Writer, logger *slog.Logger) int {
	var jsonOut, htmlOut, evidenceDir string
	noProvision, confirmRun := false, false
	target := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json" && i+1 < len(args):
			i++
			jsonOut = args[i]
		case len(a) > 7 && a[:7] == "--json=":
			jsonOut = a[7:]
		case a == "--html" && i+1 < len(args):
			i++
			htmlOut = args[i]
		case len(a) > 7 && a[:7] == "--html=":
			htmlOut = a[7:]
		case a == "--evidence-dir" && i+1 < len(args):
			i++
			evidenceDir = args[i]
		case len(a) > 14 && a[:14] == "--evidence-dir=":
			evidenceDir = a[14:]
		case a == "--no-provision":
			noProvision = true
		case a == "--confirm-run":
			confirmRun = true
		case len(a) > 1 && a[0] == '-':
			fmt.Fprintf(stderr, "check: unknown flag %q\n", a)
			return version.ExitInternalError
		case target == "":
			target = a
		default:
			fmt.Fprintf(stderr, "check: unexpected argument %q\n", a)
			return version.ExitInternalError
		}
	}
	if target == "" {
		fmt.Fprintln(stderr, "usage: repoproof check <path> [--json out.json] [--html out.html] [--evidence-dir d] [--no-provision] --confirm-run")
		return version.ExitInternalError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	out, err := app.CheckTarget(ctx, app.CheckParams{
		Target: target, JSONOut: jsonOut, HTMLOut: htmlOut,
		EvidenceDir: evidenceDir, NoProvision: noProvision, ConfirmRun: confirmRun,
	}, func(msg string) { fmt.Fprintf(stderr, "check: %s\n", msg) })
	if err != nil {
		fmt.Fprintf(stderr, "check: %v\n", err)
		return version.ExitInternalError
	}
	fmt.Fprint(stdout, out.Summary)
	logger.Info("check done", "verdict", string(out.Verdict))
	return out.ExitCode
}

// runVerify implements the approved sandboxed verification run by
// delegating to the shared service layer (internal/app): flag parsing
// and output stay here, the chain lives there exactly once.
func runVerify(args []string, stdout, stderr io.Writer, logger *slog.Logger) int {
	var contractPath, approvePath, jsonOut, htmlOut, evidenceDir string
	noProvision := false
	target := ""
	takeNext := func(i *int, name string) string {
		if *i+1 >= len(args) {
			fmt.Fprintf(stderr, "verify: flag %s needs a value\n", name)
			return ""
		}
		*i++
		return args[*i]
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--contract":
			contractPath = takeNext(&i, a)
		case len(a) > 11 && a[:11] == "--contract=":
			contractPath = a[11:]
		case a == "--approve-file":
			approvePath = takeNext(&i, a)
		case len(a) > 14 && a[:14] == "--approve-file=":
			approvePath = a[14:]
		case a == "--json" && i+1 < len(args):
			i++
			jsonOut = args[i]
		case len(a) > 7 && a[:7] == "--json=":
			jsonOut = a[7:]
		case a == "--evidence-dir" && i+1 < len(args):
			i++
			evidenceDir = args[i]
		case len(a) > 14 && a[:14] == "--evidence-dir=":
			evidenceDir = a[14:]
		case a == "--html" && i+1 < len(args):
			i++
			htmlOut = args[i]
		case len(a) > 7 && a[:7] == "--html=":
			htmlOut = a[7:]
		case a == "--no-provision":
			noProvision = true
		case len(a) > 1 && a[0] == '-':
			fmt.Fprintf(stderr, "verify: unknown flag %q\n", a)
			return version.ExitInternalError
		case target == "":
			target = a
		default:
			fmt.Fprintf(stderr, "verify: unexpected argument %q\n", a)
			return version.ExitInternalError
		}
	}
	if target == "" || contractPath == "" || approvePath == "" {
		fmt.Fprintln(stderr, "usage: repoproof verify <path> --contract c.yaml --approve-file a.json [--json out.json] [--html out.html] [--evidence-dir d] [--no-provision]")
		return version.ExitInternalError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	out, err := app.RunVerify(ctx, app.VerifyParams{
		Target: target, ContractPath: contractPath, ApprovePath: approvePath,
		JSONOut: jsonOut, HTMLOut: htmlOut, EvidenceDir: evidenceDir,
		NoProvision: noProvision,
	}, func(msg string) { fmt.Fprintf(stderr, "verify: %s\n", msg) })
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return version.ExitInternalError
	}
	fmt.Fprint(stdout, out.Summary)
	logger.Info("verify done", "run", out.RunID, "verdict", string(out.Verdict))
	return out.ExitCode
}
