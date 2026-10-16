// Package contract parses deterministic proof contracts
// (repoproof.yaml, G3-contracts): the maintainer-authored binding of
// steps to behavioral assertions. Parsing and validation only — no
// execution. Contracts are strict and hermetic: unknown fields,
// placeholders, remote oracle targets and missing oracles are all
// rejected, because a loose contract would produce looser verdicts.
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/verifier"
	"gopkg.in/yaml.v3"
)

// Fingerprint binds an approval to the exact contract bytes the operator
// reviewed. Formatting changes intentionally produce a new fingerprint;
// approval is conservative and must be redrafted.
func Fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// FingerprintContract gives machine-built contracts the same binding
// property without inventing a second approval format.
func FingerprintContract(c *Contract) string {
	raw, _ := json.Marshal(c)
	return Fingerprint(raw)
}

// First third-party dependency (MIT/Apache, see docs/DEPENDENCIES.md).
// YAML has no stdlib support; the parser is strict (KnownFields) so the
// dependency cannot smuggle unvalidated content past Validate.

// Supported vocabularies (v1, closed sets).
var (
	kindSet    = map[string]bool{"cli": true, "http": true}
	runtimeSet = map[string]bool{"node": true, "python": true}
	phaseSet   = map[string]bool{"install": true, "launch": true}
	netSet     = map[string]bool{"restricted": true, "none": true}
	typeSet    = map[string]bool{
		verifier.AssertExitCodeEquals: true,
		verifier.AssertStdoutContains: true,
		"http_status":                 true,
		"http_body_contains":          true,
	}
	idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

// Resource bounds for contract-declared execution.
const (
	maxWallSeconds = 600
	maxOutputBytes = 64 << 20
)

// Contract is a validated proof contract.
type Contract struct {
	Version   int       `yaml:"version"`
	Project   Project   `yaml:"project"`
	Execution Execution `yaml:"execution"`
	Steps     []Step    `yaml:"steps"`
	Proof     []Proof   `yaml:"proof"`
}

type Project struct {
	Kind    string `yaml:"kind"`
	Runtime string `yaml:"runtime"`
}

type Execution struct {
	MaxWallSeconds int    `yaml:"max_wall_seconds"`
	MaxOutputBytes int64  `yaml:"max_output_bytes"`
	InstallNetwork string `yaml:"install_network"`
	VerifyNetwork  string `yaml:"verify_network"`
}

type Step struct {
	ID    string `yaml:"id"`
	Phase string `yaml:"phase"`
	// Exactly one command source: inline Run, or FromReadme to resolve
	// the command from the approved plan at execute time.
	Run            string `yaml:"run"`
	FromReadme     bool   `yaml:"from_readme"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

type Proof struct {
	ID       string `yaml:"id"`
	Type     string `yaml:"type"`
	Target   string `yaml:"target"`
	Expected any    `yaml:"expected"`
}

// Parse decodes strict YAML and validates every rule.
func Parse(data []byte) (*Contract, error) {
	var c Contract
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("contract: bad yaml: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate enforces the closed vocabularies and hermeticity rules.
func (c *Contract) Validate() error {
	if err := c.validateSteps(); err != nil {
		return err
	}
	return c.validateProof()
}

// validateSteps checks identity, scope and step bindings. Exported
// for machine-built contracts (auto mode), which carry no oracle.
func (c *Contract) validateSteps() error {
	if c.Version != 1 {
		return fmt.Errorf("contract: version must be 1, got %d", c.Version)
	}
	if !kindSet[c.Project.Kind] {
		return fmt.Errorf("contract: project.kind must be cli|http, got %q", c.Project.Kind)
	}
	if !runtimeSet[c.Project.Runtime] {
		return fmt.Errorf("contract: project.runtime must be node|python, got %q", c.Project.Runtime)
	}
	e := c.Execution
	if e.MaxWallSeconds < 1 || e.MaxWallSeconds > maxWallSeconds {
		return fmt.Errorf("contract: max_wall_seconds must be 1..%d", maxWallSeconds)
	}
	if e.MaxOutputBytes < 1 || e.MaxOutputBytes > maxOutputBytes {
		return fmt.Errorf("contract: max_output_bytes must be 1..%d", maxOutputBytes)
	}
	if !netSet[e.InstallNetwork] {
		return fmt.Errorf("contract: install_network must be restricted|none, got %q", e.InstallNetwork)
	}
	// v1 amendment rule: verification is network-off, no exceptions.
	if e.VerifyNetwork != "guest-only" {
		return fmt.Errorf("contract: verify_network must be guest-only in v1, got %q", e.VerifyNetwork)
	}
	if len(c.Steps) == 0 {
		return fmt.Errorf("contract: at least one step required")
	}
	seen := map[string]bool{}
	for i := range c.Steps {
		s := &c.Steps[i]
		if !idRe.MatchString(s.ID) {
			return fmt.Errorf("contract: steps[%d] bad id %q", i, s.ID)
		}
		if seen[s.ID] {
			return fmt.Errorf("contract: duplicate step id %q", s.ID)
		}
		seen[s.ID] = true
		if !phaseSet[s.Phase] {
			return fmt.Errorf("contract: step %q phase must be install|launch, got %q", s.ID, s.Phase)
		}
		hasRun := strings.TrimSpace(s.Run) != "" && !strings.ContainsRune(s.Run, 0)
		switch {
		case s.FromReadme && hasRun:
			return fmt.Errorf("contract: step %q sets both run and from_readme: ambiguous", s.ID)
		case s.FromReadme:
			// Command resolves from the approved plan at execute time.
		case hasRun:
			if hasPlaceholder(s.Run) {
				return fmt.Errorf("contract: step %q has env placeholder: contracts must be hermetic", s.ID)
			}
		default:
			return fmt.Errorf("contract: step %q needs run or from_readme", s.ID)
		}
		if s.TimeoutSeconds < 0 || s.TimeoutSeconds > maxWallSeconds {
			return fmt.Errorf("contract: step %q timeout out of range", s.ID)
		}
	}
	return nil
}

// validateProof checks the oracle block. Human-written contracts must
// carry proof (Parse enforces it); machine-built auto contracts
// deliberately omit it and cap at PARTIAL.
func (c *Contract) validateProof() error {
	if len(c.Proof) == 0 {
		return fmt.Errorf("contract: at least one proof assertion required (no oracle, no VERIFIED)")
	}
	seen := map[string]bool{}
	for i := range c.Proof {
		p := &c.Proof[i]
		if !idRe.MatchString(p.ID) {
			return fmt.Errorf("contract: proof[%d] bad id %q", i, p.ID)
		}
		if seen[p.ID] {
			return fmt.Errorf("contract: duplicate proof id %q", p.ID)
		}
		seen[p.ID] = true
		if !typeSet[p.Type] {
			return fmt.Errorf("contract: proof %q unknown type %q", p.ID, p.Type)
		}
		exp, err := normalizeExpected(p.Expected)
		if err != nil {
			return fmt.Errorf("contract: proof %q: %w", p.ID, err)
		}
		_ = exp
		if strings.HasPrefix(p.Type, "http_") {
			if err := checkLoopbackTarget(p.Target); err != nil {
				return fmt.Errorf("contract: proof %q: %w", p.ID, err)
			}
		} else if p.Target != "" {
			return fmt.Errorf("contract: proof %q: target is meaningless for type %q", p.ID, p.Type)
		}
	}
	return nil
}

// Assertions converts proof entries to verifier assertions in order.
func (c *Contract) Assertions() []verifier.Assertion {
	out := make([]verifier.Assertion, 0, len(c.Proof))
	for _, p := range c.Proof {
		exp, _ := normalizeExpected(p.Expected)
		out = append(out, verifier.Assertion{ID: p.ID, Type: p.Type, Expected: exp})
	}
	return out
}

// AutoFromPlan builds the machine contract for automatic mode: one
// from_readme step per present phase, no oracle, PARTIAL ceiling by
// construction. Only supported stacks qualify; anything else is an
// error so the caller can verdict INCONCLUSIVE/UNSUPPORTED instead
// of running blind. Empty plans (no runnable steps) are refused.
func AutoFromPlan(p *planner.Plan) (*Contract, error) {
	if p.Stack != string(inspector.StackNode) && p.Stack != string(inspector.StackPython) {
		return nil, fmt.Errorf("auto contract: stack %q not auto-runnable", p.Stack)
	}
	has := map[string]bool{}
	for _, s := range p.Steps {
		if s.Phase == "install" || s.Phase == "launch" {
			has[s.Phase] = true
		}
	}
	if len(has) == 0 {
		return nil, fmt.Errorf("auto contract: plan has no runnable steps")
	}
	c := &Contract{
		Version: 1,
		Project: Project{Kind: "cli", Runtime: p.Stack},
		Execution: Execution{
			MaxWallSeconds: 600, MaxOutputBytes: 20 << 20,
			InstallNetwork: "none", VerifyNetwork: "guest-only",
		},
	}
	if has["install"] {
		c.Steps = append(c.Steps, Step{ID: "auto-install", Phase: "install", FromReadme: true})
	}
	if has["launch"] {
		c.Steps = append(c.Steps, Step{ID: "auto-launch", Phase: "launch", FromReadme: true})
	}
	if err := c.validateSteps(); err != nil {
		return nil, err
	}
	return c, nil
}

// StepIDs returns step IDs in declaration order (deterministic).

func (c *Contract) StepIDs() []string {
	out := make([]string, 0, len(c.Steps))
	for _, s := range c.Steps {
		out = append(out, s.ID)
	}
	return out
}

func normalizeExpected(v any) (string, error) {
	switch e := v.(type) {
	case string:
		if strings.TrimSpace(e) == "" {
			return "", fmt.Errorf("expected must not be empty")
		}
		return e, nil
	case int:
		return strconv.Itoa(e), nil
	default:
		return "", fmt.Errorf("expected must be a string or integer, got %T", v)
	}
}

// checkLoopbackTarget enforces contained oracle probes: only http
// URLs on loopback may be asserted. Anything wider is rejected.
func checkLoopbackTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return fmt.Errorf("target must be an http URL, got %q", target)
	}
	host := strings.ToLower(u.Hostname())
	if host != "127.0.0.1" && host != "localhost" {
		return fmt.Errorf("target must be loopback (127.0.0.1|localhost), got %q", target)
	}
	return nil
}

var placeholderRe = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]+%`)

func hasPlaceholder(s string) bool {
	return placeholderRe.MatchString(s)
}
