package source

import "testing"

// No token must mean NO client options, not empty credentials. go-git reads a
// blank BasicAuth as an attempt to authenticate rather than as anonymity, so
// getting this backwards would break every public clone — the common case —
// while fixing the private one.
func TestNoTokenSendsNoCredentials(t *testing.T) {
	if got := auth(""); got != nil {
		t.Fatalf("auth(\"\") = %v, want nil so the clone stays anonymous", got)
	}
	if got := auth("ghp_example"); len(got) != 1 {
		t.Fatalf("auth(token) = %d client options, want exactly 1", len(got))
	}
}
