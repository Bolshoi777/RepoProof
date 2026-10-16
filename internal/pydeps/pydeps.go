// Package pydeps stages Python dependencies for offline container
// installs (online-install slice): strict requirements parsing,
// PyPI metadata lookup, digest-pinned archive fetch, and staging.
// The container later installs with --no-index --find-links, so
// install hooks execute only inside the sandbox, never on the host.
//
// Scope is deliberately narrow: exact pins (name==version), wheels
// preferred, sdists only when no wheel exists for the file set.
// Anything else (ranges, URLs, -r includes, options, env markers)
// is refused with a reason, not guessed.
package pydeps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/repoproof/repoproof/internal/fetch"
)

var pinRe = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-!+]+)$`)

// Pin is one exact dependency.
type Pin struct {
	Name    string
	Version string
}

// ResolvedArtifact is the immutable selection used for both approval
// fingerprinting and download. Re-resolving after approval is forbidden by
// callers; a changed index produces a different fingerprint before staging.
type ResolvedArtifact struct {
	Pin         Pin
	Filename    string
	URL         string
	PackageType string
	SHA256      string
}

func Resolve(ctx context.Context, baseURL string, pins []Pin) ([]ResolvedArtifact, error) {
	if baseURL == "" {
		baseURL = "https://pypi.org"
	}
	out := make([]ResolvedArtifact, 0, len(pins))
	for _, pin := range pins {
		files, err := queryRelease(ctx, baseURL, pin)
		if err != nil {
			return nil, err
		}
		chosen, err := pickWheel(files)
		if err != nil {
			return nil, fmt.Errorf("%s==%s: %w", pin.Name, pin.Version, err)
		}
		out = append(out, ResolvedArtifact{Pin: pin, Filename: chosen.Filename, URL: chosen.URL, PackageType: chosen.PackageType, SHA256: strings.ToLower(chosen.Digests.SHA256)})
	}
	return out, nil
}

func FingerprintResolved(artifacts []ResolvedArtifact) string {
	var material strings.Builder
	for _, chosen := range artifacts {
		for _, value := range []string{strings.ToLower(chosen.Pin.Name), chosen.Pin.Version, chosen.Filename, chosen.URL, chosen.PackageType, strings.ToLower(chosen.SHA256)} {
			material.WriteString(value)
			material.WriteByte(0)
		}
	}
	sum := sha256.Sum256([]byte(material.String()))
	return hex.EncodeToString(sum[:])
}

// ResolvedFingerprint records the exact PyPI artifacts selected by the
// resolver for these pins. It is controller metadata only: the returned
// digest binds approval to the filename, URL, package type and SHA-256 that
// Stage will later fetch and install in the guest.
func ResolvedFingerprint(ctx context.Context, baseURL string, pins []Pin) (string, error) {
	if len(pins) == 0 {
		return "", nil
	}
	resolved, err := Resolve(ctx, baseURL, pins)
	if err != nil {
		return "", err
	}
	return FingerprintResolved(resolved), nil
}

// ParseRequirements accepts only exact pins, one per line; comments
// and blank lines skipped. Anything else is an explicit error.
func ParseRequirements(data []byte) ([]Pin, error) {
	var out []Pin
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := pinRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("pydeps: line %d: only exact pins (name==version) supported: %q", i+1, line)
		}
		out = append(out, Pin{Name: m[1], Version: m[2]})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pydeps: no pins found")
	}
	return out, nil
}

type pypiFile struct {
	Filename    string `json:"filename"`
	URL         string `json:"url"`
	PackageType string `json:"packagetype"`
	Digests     struct {
		SHA256 string `json:"sha256"`
	} `json:"digests"`
}

type pypiRelease struct {
	URLs []pypiFile `json:"urls"`
}

// queryRelease fetches PyPI metadata (bounded, allowlisted) for a pin.
func queryRelease(ctx context.Context, baseURL string, pin Pin) ([]pypiFile, error) {
	meta := fmt.Sprintf("%s/pypi/%s/%s/json", strings.TrimSuffix(baseURL, "/"), pin.Name, pin.Version)
	if err := fetch.CheckURL(meta); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{CheckRedirect: func(next *http.Request, _ []*http.Request) error {
		return fetch.CheckURL(next.URL.String())
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pydeps: metadata for %s==%s: %w", pin.Name, pin.Version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pydeps: metadata for %s==%s: HTTP %s", pin.Name, pin.Version, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var rel pypiRelease
	if err := json.Unmarshal(raw, &rel); err != nil {
		return nil, fmt.Errorf("pydeps: bad metadata for %s==%s", pin.Name, pin.Version)
	}
	if len(rel.URLs) == 0 {
		return nil, fmt.Errorf("pydeps: no files for %s==%s", pin.Name, pin.Version)
	}
	return rel.URLs, nil
}

// pickWheel prefers a wheel usable anywhere (py3-none-any first, then
// any wheel), falling back to sdist only when no wheel exists.
func pickWheel(files []pypiFile) (pypiFile, error) {
	var sdist pypiFile
	hasSdist := false
	for _, f := range files {
		if f.Digests.SHA256 == "" || f.URL == "" {
			continue
		}
		if f.PackageType == "bdist_wheel" {
			if strings.Contains(f.Filename, "py3-none-any") || strings.Contains(f.Filename, "py2.py3-none-any") {
				return f, nil
			}
		}
	}
	for _, f := range files {
		if f.Digests.SHA256 == "" || f.URL == "" {
			continue
		}
		if f.PackageType == "bdist_wheel" {
			return f, nil
		}
		if f.PackageType == "sdist" && !hasSdist {
			sdist, hasSdist = f, true
		}
	}
	if hasSdist {
		return sdist, nil
	}
	return pypiFile{}, fmt.Errorf("pydeps: no digest-pinned wheel or sdist available")
}

// Stage resolves every pin to a digest-pinned archive and fetches it
// into stageDir. baseURL defaults to https://pypi.org (tests inject
// loopback). Returns staged file paths.
func Stage(ctx context.Context, baseURL string, pins []Pin, stageDir string) ([]string, error) {
	resolved, err := Resolve(ctx, baseURL, pins)
	if err != nil {
		return nil, err
	}
	return StageResolved(ctx, resolved, stageDir)
}

// StageResolved fetches exactly the already-approved artifact selections.
func StageResolved(ctx context.Context, resolved []ResolvedArtifact, stageDir string) ([]string, error) {
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return nil, err
	}
	var staged []string
	for _, chosen := range resolved {
		got, err := fetch.Fetch(ctx, fetch.Spec{
			URL: chosen.URL, SHA256: chosen.SHA256,
			MaxBytes: 100 << 20, Filename: filepath.Base(chosen.Filename),
		}, stageDir)
		if err != nil {
			return nil, fmt.Errorf("%s==%s: %w", chosen.Pin.Name, chosen.Pin.Version, err)
		}
		staged = append(staged, got)
	}
	return staged, nil
}
