// Package project turns what a scan knows about its origin — a remote URL and a
// directory on disk — into the durable identity of the thing being scanned.
//
// A run is an event: this tree, at this ref, at this instant. A project is what
// the runs are about, and it needs a different key. `internal/source` recorded
// only filepath.Base of the scanned directory, so two directories named
// data-platform were indistinguishable in the store and collided in the org
// scan's resume logic. Identity is the canonical remote, because a repository
// cloned to two directories is one repository.
package project

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	KindRemote = "remote"
	KindLocal  = "local"
)

// Origin is what a run is about, as distinct from the tree that was read.
//
// Either field may be empty and neither can be the sole identity: a remote scan
// has no local path, and a non-git directory has no remote.
type Origin struct {
	Kind   string // KindRemote, KindLocal, or "" when neither is known
	Remote string // raw remote URL, uncanonicalised; empty for a non-git tree
	Path   string // absolute path of the scanned directory; empty for a remote scan
}

// Identity is the registry row an Origin implies. Key is unique; Name is for
// display only and is never matched against.
type Identity struct {
	Key  string
	Kind string
	Name string
}

// scpLike matches git's SCP-ish remote syntax, which is not a URL and so cannot
// be handed to url.Parse: git@github.com:o/r.git. Anchored at the start with a
// character class excluding ':' and '/' so that ssh://git@host/o/r — which IS a
// URL and contains an '@' — falls through to the parser instead.
var scpLike = regexp.MustCompile(`^[A-Za-z0-9._-]+@([^:/]+):(.+)$`)

// Canonical reduces a remote URL to a stable key and a display name.
//
// ok is false for anything with no host, which is the same test that keeps the
// v5 migration away from pre-v5 local runs: their target is a bare basename.
func Canonical(remote string) (key, name string, ok bool) {
	s := strings.TrimSpace(remote)
	if s == "" {
		return "", "", false
	}

	var host, path string
	if m := scpLike.FindStringSubmatch(s); m != nil {
		host, path = m[1], m[2]
	} else {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", "", false
		}
		// Hostname() drops the port, and userinfo lives on u.User rather than
		// u.Host — which is what keeps a token out of the key, and out of the
		// database, when someone clones with a credential in the URL.
		host, path = u.Hostname(), u.Path
	}

	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if path == "" {
		return "", "", false
	}

	// The key is fully lowercased so github.com/O/R and github.com/o/r are one
	// project; the name keeps the original case because it is what gets printed.
	return strings.ToLower(host + "/" + path), path, true
}

// Of resolves an Origin to the project it belongs to.
//
// The remote wins when there is one. That is the "paths are locations" rule: two
// worktrees of one repository are one project, and the path is recorded beside
// it rather than instead of it.
func Of(o Origin) (Identity, bool) {
	if key, name, ok := Canonical(o.Remote); ok {
		return Identity{Key: key, Kind: KindRemote, Name: name}, true
	}
	if o.Path != "" {
		return Identity{Key: o.Path, Kind: KindLocal, Name: filepath.Base(o.Path)}, true
	}
	return Identity{}, false
}
