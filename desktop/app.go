// Package main hosts the RepoProof desktop app (G4): a thin Wails
// shell over internal/app. All logic lives in the shared Core; this
// package only binds methods, relays progress events, and saves files
// the user explicitly exports.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/repoproof/repoproof/internal/app"
	"github.com/repoproof/repoproof/internal/reporter"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type guiRun struct {
	done    bool
	exit    int
	summary string
	proof   string
	cancel  context.CancelFunc
}

// App is the bound frontend API. Results stay in memory; exported
// files are written only through explicit user actions.
type App struct {
	ctx           context.Context
	mu            sync.Mutex
	runs          map[string]*guiRun
	seq           int
	inspectCancel context.CancelFunc
}

// NewApp creates the bound API handle.
func NewApp() *App {
	return &App{runs: map[string]*guiRun{}}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func fail(msg string, err error) (string, error) {
	if err == nil {
		return "", fmt.Errorf("%s", msg)
	}
	return "", fmt.Errorf("%s: %w", msg, err)
}

// Inspect returns validated inspect JSON for a local path.
func (a *App) Inspect(path string) (string, error) {
	raw, err := app.Inspect(path)
	if err != nil {
		return fail("inspect", err)
	}
	return string(raw), nil
}

// Plan returns the candidate plan JSON for a local path.
func (a *App) Plan(path string) (string, error) {
	raw, err := app.BuildPlan(path)
	if err != nil {
		return fail("plan", err)
	}
	return string(raw), nil
}

// InspectAndPlan materializes a target once and returns both the validated
// inspection report and candidate plan for the desktop review screen.
func (a *App) InspectAndPlan(path string) (string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.inspectCancel = cancel
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.inspectCancel = nil
		a.mu.Unlock()
	}()
	raw, err := app.InspectAndPlanContext(ctx, path)
	if err != nil {
		return fail("inspect", err)
	}
	return string(raw), nil
}

// CancelInspect aborts a running read-only materialization. No repository
// code has executed at this point; the source package still owns cleanup.
func (a *App) CancelInspect() (string, error) {
	a.mu.Lock()
	cancel := a.inspectCancel
	a.mu.Unlock()
	if cancel == nil {
		return fail("no inspect is running", nil)
	}
	cancel()
	return "cancelling", nil
}

// DraftApproval writes the approval record outside the project and
// returns its path plus the human summary as JSON.
func (a *App) DraftApproval(path, contractPath, statement string, ackAll bool) (string, error) {
	dir, err := os.MkdirTemp("", "repoproof-ui-")
	if err != nil {
		return fail("temp dir", err)
	}
	out := filepath.Join(dir, "approve.json")
	summary, err := app.DraftApproval(path, contractPath, statement, ackAll, out)
	if err != nil {
		return fail("approve", err)
	}
	raw, _ := json.Marshal(map[string]string{"path": out, "summary": summary})
	return string(raw), nil
}

// BrowseFolder opens a directory picker for the project path.
func (a *App) BrowseFolder() (string, error) {
	path, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select project folder",
	})
	if err != nil {
		return fail("browse", err)
	}
	return path, nil
}

// BrowseFile opens a native picker for operator-owned inputs such as the
// proof contract. Keeping this in the Wails binding avoids asking users to
// type fragile Windows paths into the UI.
func (a *App) BrowseFile() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   "Select proof contract",
		Filters: []runtime.FileFilter{{DisplayName: "YAML files", Pattern: "*.yaml;*.yml"}},
	})
	if err != nil {
		return fail("browse file", err)
	}
	return path, nil
}

// SupportStatus reports the native sandbox probe for the status bar.
func (a *App) SupportStatus() (string, error) {
	raw, err := app.SupportStatus()
	if err != nil {
		return fail("support probe", err)
	}
	return string(raw), nil
}

// CancelVerify aborts a running verification (tree dies with the job,
// verdict becomes CANCELLED, cleanup still runs).
func (a *App) CancelVerify(runID string) (string, error) {
	a.mu.Lock()
	r, ok := a.runs[runID]
	a.mu.Unlock()
	if !ok {
		return fail("unknown run", nil)
	}
	if r.cancel != nil {
		r.cancel()
	}
	return "cancelling", nil
}

// emit fires a Wails event only from a real Wails startup context.
// Unit tests construct App via NewApp (ctx is nil): calling
// runtime.EventsEmit there would log.Fatalf (os.Exit). Production
// sets ctx in startup, so events flow normally.
func (a *App) emit(name string, payload any) {
	ctx := a.ctx
	if ctx == nil || ctx.Value("events") == nil {
		return
	}
	runtime.EventsEmit(ctx, name, payload)
}

// StartCheck launches the automatic chain (PARTIAL ceiling) and
// returns a run ID. Same events and polling as StartVerify.
func (a *App) StartCheck(path string, confirmRun bool) (string, error) {
	if path == "" {
		return fail("path is required", nil)
	}
	if !confirmRun {
		return fail("confirmation required: review the plan first", nil)
	}
	a.mu.Lock()
	a.seq++
	runID := fmt.Sprintf("ui-check-%d-%d", time.Now().UnixNano(), a.seq)
	ctx, cancel := context.WithCancel(context.Background())
	a.runs[runID] = &guiRun{cancel: cancel}
	a.mu.Unlock()

	go func() {
		out, err := app.CheckTarget(ctx, app.CheckParams{
			Target: path, ConfirmRun: true,
		}, func(msg string) {
			a.emit("verify:progress", map[string]string{"run": runID, "msg": msg})
		})
		a.mu.Lock()
		r := a.runs[runID]
		if err != nil {
			r.summary = fmt.Sprintf("run failed: %v", err)
			r.exit = 20
		} else {
			r.summary = out.Summary
			r.proof = string(out.Proof)
			r.exit = out.ExitCode
		}
		r.done = true
		a.mu.Unlock()
		a.emit("verify:done", map[string]any{"run": runID, "exit": r.exit})
	}()
	return runID, nil
}

// StartVerify launches the chain asynchronously and returns a run ID.
// Progress streams through verify:progress events; completion through
// verify:done. Nothing runs on the host.
func (a *App) StartVerify(path, contractPath, approvePath string) (string, error) {
	if path == "" || contractPath == "" || approvePath == "" {
		return fail("path, contract and approval are required", nil)
	}
	a.mu.Lock()
	a.seq++
	runID := fmt.Sprintf("ui-run-%d-%d", time.Now().UnixNano(), a.seq)
	ctx, cancel := context.WithCancel(context.Background())
	a.runs[runID] = &guiRun{cancel: cancel}
	a.mu.Unlock()

	go func() {
		out, err := app.RunVerify(ctx, app.VerifyParams{
			Target: path, ContractPath: contractPath, ApprovePath: approvePath,
			RunID: runID,
		}, func(msg string) {
			a.emit("verify:progress", map[string]string{"run": runID, "msg": msg})
		})
		a.mu.Lock()
		r := a.runs[runID]
		if err != nil {
			r.summary = fmt.Sprintf("run failed: %v", err)
			r.exit = 20
		} else {
			r.summary = out.Summary
			r.proof = string(out.Proof)
			r.exit = out.ExitCode
		}
		r.done = true
		a.mu.Unlock()
		a.emit("verify:done", map[string]any{"run": runID, "exit": r.exit})
	}()
	return runID, nil
}

// VerifyResult polls one run: done flag with summary, proof and exit.
func (a *App) VerifyResult(runID string) (string, error) {
	a.mu.Lock()
	r, ok := a.runs[runID]
	if !ok {
		a.mu.Unlock()
		return fail("unknown run", nil)
	}
	done, exit, summary, proof := r.done, r.exit, r.summary, r.proof
	a.mu.Unlock()
	raw, _ := json.Marshal(map[string]any{
		"done": done, "exit": exit, "summary": summary, "proof": proof,
	})
	return string(raw), nil
}

// SaveProof opens a save dialog and writes the run's proof JSON.
func (a *App) SaveProof(runID string) (string, error) {
	a.mu.Lock()
	r, ok := a.runs[runID]
	if !ok {
		a.mu.Unlock()
		return fail("unknown run", nil)
	}
	done, proof := r.done, r.proof
	a.mu.Unlock()
	if !done || proof == "" {
		return fail("no completed proof for run", nil)
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultFilename:      runID + "-proof.json",
		Title:                "Save proof report",
		ShowHiddenFiles:      false,
		CanCreateDirectories: true,
	})
	if err != nil {
		return fail("save dialog", err)
	}
	if path == "" {
		return fail("save cancelled", nil)
	}
	if err := os.WriteFile(path, []byte(proof), 0o644); err != nil {
		return fail("save proof", err)
	}
	return path, nil
}

// SaveProofHTML renders the same validated proof as a self-contained offline
// HTML report. The renderer escapes/redacts untrusted values before writing.
func (a *App) SaveProofHTML(runID string) (string, error) {
	a.mu.Lock()
	r, ok := a.runs[runID]
	if !ok {
		a.mu.Unlock()
		return fail("unknown run", nil)
	}
	done, proof := r.done, r.proof
	a.mu.Unlock()
	if !done || proof == "" {
		return fail("no completed proof for run", nil)
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultFilename: runID + "-proof.html", Title: "Save proof HTML",
		ShowHiddenFiles: false, CanCreateDirectories: true,
	})
	if err != nil {
		return fail("save dialog", err)
	}
	if path == "" {
		return fail("save cancelled", nil)
	}
	f, err := os.Create(path)
	if err != nil {
		return fail("create proof HTML", err)
	}
	if err := reporter.WriteProofHTML([]byte(proof), f); err != nil {
		_ = f.Close()
		return fail("render proof HTML", err)
	}
	if err := f.Close(); err != nil {
		return fail("save proof HTML", err)
	}
	return path, nil
}
