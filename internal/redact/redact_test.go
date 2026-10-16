package redact

import (
	"strings"
	"testing"
	"time"
)

const (
	awsExampleKey     = "AKIA" + "IOSFODNN7EXAMPLE"
	githubExampleToken = "ghp_" + "abcdefgh1234567890"
	slackExampleToken  = "xoxb-" + "123456789012-abcdef"
)

func TestKnownSecretsRedacted(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string // must appear
		gone []string // must disappear
	}{
		{
			"aws key",
			"key " + awsExampleKey + " leaked",
			[]string{"[redacted:aws-key]"}, []string{awsExampleKey},
		},
		{
			"github token",
			"token " + githubExampleToken + " in log",
			[]string{"[redacted:github-token]"}, []string{githubExampleToken},
		},
		{
			"slack token",
			slackExampleToken + " here",
			[]string{"[redacted:slack-token]"}, []string{slackExampleToken},
		},
		{
			"private key block",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIB fake\n-----END RSA PRIVATE KEY-----",
			[]string{"[redacted:private-key]"}, []string{"MIIB"},
		},
		{
			"key=value keeps name",
			"export api_key=supersecretvalue123",
			[]string{"api_key=", "[redacted]"}, []string{"supersecretvalue123"},
		},
		{
			"password assignment",
			"password: hunter2hunter2",
			[]string{"password:", "[redacted]"}, []string{"hunter2hunter2"},
		},
		{
			"windows profile",
			`log at C:\Users\example-user\projects\x.log`,
			[]string{`C:\Users\[user]`}, []string{"example-user"},
		},
		{
			"unix home",
			"log at /home/example-user/x.log",
			[]string{"/home/[user]"}, []string{"/home/example-user"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactText(tc.in)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("missing %q in %q", w, got)
				}
			}
			for _, g := range tc.gone {
				if strings.Contains(got, g) {
					t.Fatalf("leaked %q in %q", g, got)
				}
			}
			if !ContainsSecret(tc.in) {
				t.Fatalf("ContainsSecret missed %q", tc.in)
			}
		})
	}
}

func TestHashesAndProseUntouched(t *testing.T) {
	clean := []string{
		"c48e3f8fd909b660f1524fe85d4b41ff107edb6c",                                       // commit SHA
		"d8730e2210b460eed9bf520ae18d3757566dd90f573373cbaef909b70a53c6dd90f573373cbaef", // 80-hex, not secret-shaped
		"The token expired yesterday, request a new one.",
		"passwords must be at least 8 chars",
		"npm install && npm start",
	}
	for _, s := range clean {
		if got := RedactText(s); got != s {
			t.Fatalf("clean text mangled:\n in %q\nout %q", s, got)
		}
		if ContainsSecret(s) {
			t.Fatalf("false positive on %q", s)
		}
	}
	// 64-hex fingerprint passes through byte-identical.
	fp := "d8730e2210b460eed9bf520ae18d3757566dd90f573373cbaef909b70a53c6dd"
	if !FingerprintLike(fp) || RedactText(fp) != fp {
		t.Fatalf("fingerprint invariant broken for %q", fp)
	}
}

func TestIdempotent(t *testing.T) {
	in := awsExampleKey + " and password: hunter2hunter2 at C:\\Users\\example-user\\x"
	once := RedactText(in)
	if twice := RedactText(once); twice != once {
		t.Fatalf("not idempotent:\n%q\n%q", once, twice)
	}
}

func TestBoundedOnLargeInput(t *testing.T) {
	big := strings.Repeat(awsExampleKey+" log line with password: hunter2hunter2\n", 20000)
	start := time.Now()
	out := RedactText(big)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("redaction too slow: %v", elapsed)
	}
	if strings.Contains(out, awsExampleKey) || strings.Contains(out, "hunter2hunter2") {
		t.Fatal("large input leaked secrets")
	}
}
