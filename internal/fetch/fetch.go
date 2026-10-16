// Package fetch is the trusted dependency downloader (online-install
// slice): allowlisted registry HTTPS fetches with mandatory digests
// and size caps, landing in a staging dir for offline installs inside
// the sandbox. It never executes anything and never leaves the
// allowlist: postinstall and build hooks still run only inside the
// AppContainer from staged files (amendment section 4.1).
//
// Network rule: https only (loopback http for unit tests), host must
// be on the registry allowlist. No firewall changes, no proxy, no
// ambient egress: the sandbox itself stays network-off.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Registry allowlist: npm metadata+tarballs and PyPI index+files.
// Everything else is refused before any packet is sent.
var allowlist = map[string]bool{
	"registry.npmjs.org":     true,
	"pypi.org":               true,
	"files.pythonhosted.org": true,
}

// Spec pins one download.
type Spec struct {
	URL      string // https allowlisted host (loopback http for tests)
	SHA256   string // 64 hex, mandatory
	MaxBytes int64  // cap, must be positive
	Filename string // base name only, no separators
}

// Fetch downloads spec into destDir/Filename and verifies the digest.
// Partial files are removed on any failure.
func Fetch(ctx context.Context, spec Spec, destDir string) (string, error) {
	if err := spec.validate(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.URL, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{CheckRedirect: func(next *http.Request, _ []*http.Request) error {
		// Validate every hop; validating only the user-supplied URL lets a
		// registry redirect into a private/LAN endpoint.
		return CheckURL(next.URL.String())
	}}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", spec.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %s", spec.URL, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, spec.MaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", spec.URL, err)
	}
	if int64(len(raw)) > spec.MaxBytes {
		return "", fmt.Errorf("fetch exceeds cap of %d bytes", spec.MaxBytes)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != strings.ToLower(spec.SHA256) {
		return "", fmt.Errorf("fetch %s: digest mismatch, refusing", spec.URL)
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	out := filepath.Join(destDir, spec.Filename)
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return "", err
	}
	return out, nil
}

func (s Spec) validate() error {
	if err := CheckURL(s.URL); err != nil {
		return err
	}
	if len(s.SHA256) != 64 || !isHex(s.SHA256) {
		return fmt.Errorf("fetch: SHA256 pin required (64 hex)")
	}
	if s.MaxBytes <= 0 {
		return fmt.Errorf("fetch: MaxBytes must be positive")
	}
	if s.Filename == "" || s.Filename != filepath.Base(s.Filename) {
		return fmt.Errorf("fetch: unsafe filename %q", s.Filename)
	}
	return nil
}

// CheckURL enforces the egress rule (exported for sibling downloaders
// with the same trust requirements): https on an allowlisted registry
// host, or loopback http for unit tests. Anything else is refused
// before any packet is sent.
func CheckURL(rawurl string) error {
	u, err := url.Parse(rawurl)
	if err != nil || u.Host == "" {
		return fmt.Errorf("fetch: bad URL %q", rawurl)
	}
	if u.Scheme == "https" {
		if !allowlist[strings.ToLower(u.Hostname())] {
			return fmt.Errorf("fetch: host %q not on the registry allowlist", u.Hostname())
		}
	} else if u.Scheme == "http" && isLoopback(u.Hostname()) {
	} else {
		return fmt.Errorf("fetch: only https (loopback http for tests): %q", rawurl)
	}
	return nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
