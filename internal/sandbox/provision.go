// Trusted runtime provisioning (N3b): fetch a pinned portable
// runtime archive, verify its SHA-256, extract it with traversal
// protection, and record a manifest. Network rules: HTTPS anywhere,
// plain HTTP only for loopback (unit tests). Anything else —
// including archives that escape their directory — is refused and
// partially written data is removed.
package sandbox

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// FetchSpec pins one runtime archive.
type FetchSpec struct {
	Kind       string // "node" | "python"
	URL        string // https, or http://127.0.0.1|localhost (tests)
	SHA256     string // 64 lowercase hex, mandatory
	MaxBytes   int64  // download cap, must be positive
	ExeRelPath string // exe path inside the archive, slash-separated
	Version    string // recorded into the manifest
}

var runtimeHosts = map[string]bool{
	"github.com": true, "release-assets.githubusercontent.com": true,
	"nodejs.org": true,
}

// ProvisionResult is a ready portable runtime root.
type ProvisionResult struct {
	Root    string  // contains <kind>.json + extracted files
	Runtime Runtime // resolved from the written manifest
}

// Provision fetches, verifies, extracts and records a runtime.
func Provision(ctx context.Context, spec FetchSpec, cacheDir string) (ProvisionResult, error) {
	var out ProvisionResult
	if err := spec.validate(); err != nil {
		return out, err
	}
	raw, err := download(ctx, spec)
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != strings.ToLower(spec.SHA256) {
		return out, fmt.Errorf("digest mismatch for %s: refusing", spec.Kind)
	}
	root := filepath.Join(cacheDir, spec.Kind+"-"+strings.Map(safeRune, spec.Version))
	if err := os.MkdirAll(root, 0o755); err != nil {
		return out, err
	}
	extracted := false
	defer func() {
		if !extracted {
			_ = os.RemoveAll(root)
		}
	}()
	if err := unzipInto(raw, root, spec.URL); err != nil {
		return out, err
	}
	exe := filepath.Join(root, filepath.FromSlash(spec.ExeRelPath))
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		return out, fmt.Errorf("expected exe %q missing after extract", spec.ExeRelPath)
	}
	m := manifest{Kind: spec.Kind, Exe: spec.ExeRelPath, Version: spec.Version}
	mraw, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(root, spec.Kind+".json"), append(mraw, '\n'), 0o644); err != nil {
		return out, err
	}
	// Completeness record LAST: count extracted files (excluding the
	// manifest itself) so interrupted provisions are detectable.
	// resolveCache re-counts and rejects mismatches.
	n, err := countFiles(root, spec.Kind+".json")
	if err != nil {
		return out, err
	}
	m.Files = n
	mraw, _ = json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(root, spec.Kind+".json"), append(mraw, '\n'), 0o644); err != nil {
		return out, err
	}
	if complete, err := os.Create(filepath.Join(root, ".complete")); err != nil {
		return out, err
	} else {
		complete.Close()
	}
	rt := Resolve(ctx, spec.Kind, []string{root}, nil, false)
	if rt.Origin != OriginPortable {
		return out, fmt.Errorf("provisioned runtime did not resolve")
	}
	extracted = true
	out = ProvisionResult{Root: root, Runtime: rt}
	return out, nil
}

func safeRune(r rune) rune {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
		return r
	}
	return '_'
}

func (s FetchSpec) validate() error {
	if s.Kind != RuntimeNode && s.Kind != RuntimePython {
		return fmt.Errorf("unknown runtime kind %q", s.Kind)
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("bad URL %q", s.URL)
	}
	if err := validateRuntimeURL(u); err != nil {
		return err
	}
	if len(s.SHA256) != 64 || !isHex(s.SHA256) {
		return fmt.Errorf("SHA256 pin required (64 hex)")
	}
	if s.MaxBytes <= 0 {
		return fmt.Errorf("MaxBytes must be positive")
	}
	if !safeRuntimeRelPath(s.ExeRelPath) {
		return fmt.Errorf("ExeRelPath must be a relative archive path")
	}
	return nil
}

func validateRuntimeURL(u *url.URL) error {
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "https" {
		if !runtimeHosts[host] {
			return fmt.Errorf("runtime URL host %q is not allowlisted", host)
		}
	} else if u.Scheme != "http" || !isLoopbackHost(host) {
		return fmt.Errorf("runtime URL must be https (loopback http is test-only)")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) && !isLoopbackHost(host) {
		return fmt.Errorf("runtime URL targets a private address")
	}
	return nil
}

func safeRuntimeRelPath(p string) bool {
	if p == "" || strings.ContainsRune(p, '\\') || strings.HasPrefix(p, "/") {
		return false
	}
	clean := path.Clean(p)
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// download fetches with a wall timeout and a hard size cap.
func download(ctx context.Context, spec FetchSpec) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.URL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{CheckRedirect: func(next *http.Request, _ []*http.Request) error {
		return validateRuntimeURL(next.URL)
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", spec.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %s", spec.URL, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, spec.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", spec.URL, err)
	}
	if int64(len(raw)) > spec.MaxBytes {
		return nil, fmt.Errorf("download exceeds cap of %d bytes", spec.MaxBytes)
	}
	return raw, nil
}

// countFiles counts regular files under root, skipping skipName.
// Used for the completeness record.
func countFiles(root, skipName string) (int, error) {
	n := 0
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				if err := walk(p); err != nil {
					return err
				}
				continue
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			if rel == skipName || rel == ".complete" {
				continue
			}
			n++
		}
		return nil
	}
	if err := walk(root); err != nil {
		return 0, err
	}
	return n, nil
}

// unzipInto extracts zip or tar.gz (by URL suffix) with traversal
// protection: absolute paths, parent escapes and oversized members
// are refused. Total extracted bytes are capped (bomb protection).
func unzipInto(raw []byte, dest, srcURL string) error {
	if strings.HasSuffix(strings.ToLower(srcURL), ".tar.gz") || strings.HasSuffix(strings.ToLower(srcURL), ".tgz") {
		return untarGzInto(raw, dest)
	}
	return unzipBytesInto(raw, dest)
}

const (
	maxMemberBytes = 512 << 20
	maxTotalBytes  = 2 << 30
)

func checkMember(dest, name string) (string, error) {
	rel := filepath.FromSlash(name)
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("refusing absolute member %q", name)
	}
	target := filepath.Join(dest, rel)
	if !containedPath(dest, target) && target != dest {
		return "", fmt.Errorf("refusing escaping member %q", name)
	}
	return target, nil
}

func unzipBytesInto(raw []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return fmt.Errorf("bad zip: %w", err)
	}
	var total int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			target, err := checkMember(dest, f.Name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if f.UncompressedSize64 > maxMemberBytes {
			return fmt.Errorf("refusing oversized member %q", f.Name)
		}
		target, err := checkMember(dest, f.Name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxMemberBytes+1))
		rc.Close()
		if err != nil {
			return err
		}
		total += int64(len(data))
		if total > maxTotalBytes {
			return fmt.Errorf("refusing archive: total exceeds bomb cap")
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func untarGzInto(raw []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("bad gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("bad tar: %w", err)
		}
		target, err := checkMember(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if hdr.Size > maxMemberBytes {
				return fmt.Errorf("refusing oversized member %q", hdr.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			data, err := io.ReadAll(io.LimitReader(tr, maxMemberBytes+1))
			if err != nil {
				return err
			}
			total += int64(len(data))
			if total > maxTotalBytes {
				return fmt.Errorf("refusing archive: total exceeds bomb cap")
			}
			if err := os.WriteFile(target, data, 0o644); err != nil {
				return err
			}
		default:
			return fmt.Errorf("refusing special member %q (type %q)", hdr.Name, hdr.Typeflag)
		}
	}
}
