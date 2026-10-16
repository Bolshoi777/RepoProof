// Package redact sanitizes display-layer text (G2-04, RP-014): secret
// patterns and user-identifying paths are replaced before strings
// reach exported HTML. It is a display filter, never evidence
// mutation: fingerprints and JSON evidence keep exact bytes, so hashes
// stay verifiable. Commit SHAs and content fingerprints are
// deliberately NOT matched by any pattern.
//
// All patterns are RE2 (Go regexp): no backtracking, safe on large
// inputs. Unknown secret shapes are out of scope — this is a
// fail-visible allowlist approach, not a DLP promise.
package redact

import (
	"regexp"
	"strings"
)

type rule struct {
	name string
	re   *regexp.Regexp
	// repl is either a fixed string or uses $1 to keep the key name.
	repl     string
	keepKey  bool
	keyIndex int
}

var rules = []rule{
	{
		name: "aws-key",
		re:   regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		repl: "[redacted:aws-key]",
	},
	{
		name: "github-token",
		re:   regexp.MustCompile(`\b(ghp_[A-Za-z0-9]{8,}|gho_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,})\b`),
		repl: "[redacted:github-token]",
	},
	{
		name: "slack-token",
		re:   regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{8,}\b`),
		repl: "[redacted:slack-token]",
	},
	{
		name: "private-key",
		re:   regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		repl: "[redacted:private-key]",
	},
	{
		// key=value credentials: keeps the key name for context,
		// redacts only the value (min 8 non-space chars to avoid
		// mangling prose like "token expired").
		name:     "credential-assignment",
		re:       regexp.MustCompile(`(?i)\b(api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\b(\s*[:=]\s*)['"]?[^\s'"]{8,}['"]?`),
		repl:     `$1$2[redacted]`,
		keepKey:  true,
		keyIndex: 1,
	},
	{
		name: "windows-profile",
		re:   regexp.MustCompile(`(?i)C:\\Users\\[^\\/:*?"<>|\s]+`),
		repl: `C:\Users\[user]`,
	},
	{
		name: "unix-home",
		re:   regexp.MustCompile(`/home/[^/:\s]+`),
		repl: "/home/[user]",
	},
}

// RedactText replaces secret patterns and user paths with placeholders.
// Idempotent: redacting twice yields the same string.
func RedactText(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// ContainsSecret reports whether any rule matches: useful for tests
// and for callers deciding whether a note is warranted. Not a proof
// of absence when false.
func ContainsSecret(s string) bool {
	for _, r := range rules {
		if r.re.MatchString(s) {
			return true
		}
	}
	return false
}

// FingerprintLike guards the core invariant: content hashes and SHAs
// must never be redacted. Used by tests, not by the filter itself.
func FingerprintLike(s string) bool {
	if len(s) == 40 || len(s) == 64 {
		for _, c := range s {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
		return true
	}
	return false
}
