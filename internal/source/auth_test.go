package source

import (
	"testing"

	"github.com/go-git/go-git/v6/plumbing"
)

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

// A plain scan walks the tip it was handed and never reads a tag, but a shallow
// clone that follows tags anyway fails outright — "some refs were not updated" —
// on any repository holding a tag outside the shallow frontier. That took a
// 162-tag repository out of an org scan entirely.
//
// The full clone is the fallback for `--at`, where tags are how a revision like
// v1.2.3 resolves, so it must keep them.
func TestShallowCloneDoesNotFollowTags(t *testing.T) {
	if got := tagMode(false); got != plumbing.NoTags {
		t.Errorf("tagMode(needHistory=false) = %v, want NoTags — a scan reads no tags", got)
	}
	if got := tagMode(true); got == plumbing.NoTags {
		t.Error("tagMode(needHistory=true) dropped tags — --at v1.2.3 would stop resolving")
	}
}
