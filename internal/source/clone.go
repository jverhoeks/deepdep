package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/jverhoeks/deepdep/internal/project"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/client"
	githttp "github.com/go-git/go-git/v6/plumbing/transport/http"
)

// openRemote clones into a directory keyed by the remote URL and then reads it
// as a local source.
//
// Clone depth is conditional. Depth 1 is much cheaper, but a shallow clone
// cannot reach historical commits, so any run that will time-travel needs full
// history. Getting this wrong shows up only later, as an unresolvable revision.
func openRemote(ctx context.Context, url, cacheDir, at string, tok Token) (Source, error) {
	sum := sha256.Sum256([]byte(url))
	dst := filepath.Join(cacheDir, "repos", hex.EncodeToString(sum[:])[:16])

	needHistory := at != ""
	if fi, err := os.Stat(filepath.Join(dst, ".git")); err == nil && fi.IsDir() {
		if !needHistory || !isShallow(dst) {
			return openCloned(dst, at, url)
		}
		// Cached clone is shallow but this run needs history: re-clone in full.
		if err := os.RemoveAll(dst); err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}

	// A plain branch or tag NAME only needs that ref's tip, which git can fetch
	// shallowly. Only a SHA or a date genuinely requires history. Cloning
	// grafana in full to read one branch tip is minutes of transfer for a
	// question answerable in seconds.
	if needHistory && looksLikeRefName(at) {
		if err := shallowRef(ctx, dst, url, at, tok); err == nil {
			if s, err := openCloned(dst, at, url); err == nil {
				return s, nil
			}
		}
		// The ref was not a branch or tag after all (or the server refused the
		// narrow fetch). Fall through to the full clone rather than guess again.
		_ = os.RemoveAll(dst)
	}

	depth := 1
	if needHistory {
		depth = 0 // full clone
	}
	if _, err := git.PlainCloneContext(ctx, dst, &git.CloneOptions{
		URL:           url,
		ClientOptions: auth(tok),
		Depth:         depth,
		Tags:          tagMode(needHistory),
		Bare:          false, // v6: a field, no longer a positional argument
	}); err != nil {
		return nil, err
	}
	return openCloned(dst, at, url)
}

// tagMode decides whether to drag the remote's tags along.
//
// A shallow clone that also tries to follow every tag fails outright — "some
// refs were not updated" — on any repository holding a tag whose target lies
// outside the shallow frontier. schubergphilis/mcvs-golang-action, with 162
// tags, failed exactly this way and took the whole repository out of the org
// scan. Nothing in a plain scan reads a tag: it walks the tip it was given.
//
// A full clone is the fallback for --at when the revision is a SHA or a date,
// AND the last resort when the narrow tag fetch in shallowRef did not work, so
// it keeps its tags — they are how a revision like `--at v1.2.3` resolves.
// AllTags is go-git's default when Tags is left unset, which is how the old
// behaviour arose; the history path keeps it deliberately rather than by
// omission.
func tagMode(needHistory bool) plumbing.TagMode {
	if needHistory {
		return plumbing.AllTags
	}
	return plumbing.NoTags
}

// openCloned reads a clone out of the cache directory and restores the identity
// of the remote it came from.
//
// openLocal can only name a source after the directory holding it, which for a
// cache entry is a hash of the URL. Every path out of openRemote must go through
// here: the cache-HIT path did not, so a second scan of the same repository was
// stored under that hash instead of its URL. `org` then could not find the run
// it had just written ("no stored run") and, because alreadyScanned matches on
// clone URL too, never recognised the repository as done — resumability that
// quietly stopped resuming.
func openCloned(dst, at, url string) (Source, error) {
	s, err := openLocal(dst, at)
	if err != nil {
		return nil, err
	}
	if ls, ok := s.(*localSource); ok {
		ls.repo = url
		// The path openLocal filled in is deepdep's cache directory — a hash of
		// this URL — not a checkout the user chose. Recording it as a project
		// location would point the registry at a directory nobody asked for.
		ls.origin = project.Origin{Kind: project.KindRemote, Remote: url}
	}
	return s, nil
}

// auth turns a token into HTTP basic credentials, or nil for no token at all.
//
// Without this an org scan lists private repositories through the API — the same
// credential authorises that — and then fails every one of them at clone time
// with "authentication required", minutes in and after the listing has already
// promised them. Returning nil rather than an empty BasicAuth matters: go-git
// treats blank credentials as an attempt to authenticate, not as anonymity, so
// public clones would start failing the moment no token was found.
//
// The username is ignored by GitHub when the password is a token, but it may not
// be blank. "x-access-token" is the name GitHub's own tooling uses.
//
// go-git applies this per request and does not write it into the clone's
// .git/config, so the cache directory does not end up holding the credential.
//
// v6 moved auth off CloneOptions and into ClientOptions, hence the slice.
func auth(tok Token) []client.Option {
	if tok == "" {
		return nil
	}
	return []client.Option{client.WithHTTPAuth(
		&githttp.BasicAuth{Username: "x-access-token", Password: string(tok)},
	)}
}

func isShallow(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git", "shallow"))
	return err == nil
}

// shallowRef fetches one ref's tip. Branch first, then tag: go-git needs to be
// told which namespace the name lives in, and there is no way to ask.
func shallowRef(ctx context.Context, dst, url, ref string, tok Token) error {
	for _, name := range []plumbing.ReferenceName{
		plumbing.NewBranchReferenceName(ref),
		plumbing.NewTagReferenceName(ref),
	} {
		_, err := git.PlainCloneContext(ctx, dst, &git.CloneOptions{
			URL:           url,
			ClientOptions: auth(tok),
			ReferenceName: name,
			SingleBranch:  true,
			Depth:         1,
			// NoTags suppresses only the EXTRA tag-following that breaks a
			// shallow fetch; the ref named above is still fetched, including
			// when it is itself a tag. Without this, asking for one tag on a
			// repository with an unreachable one fails for both.
			Tags: plumbing.NoTags,
			Bare: false,
		})
		if err == nil {
			return nil
		}
		_ = os.RemoveAll(dst)
	}
	return errors.New("not a branch or tag")
}

// looksLikeRefName excludes the forms that genuinely need history: a commit SHA
// (which a shallow single-ref clone will not contain) and a date.
func looksLikeRefName(at string) bool {
	if at == "" || shaLike.MatchString(at) {
		return false
	}
	if _, err := time.Parse(time.RFC3339, at); err == nil {
		return false
	}
	if _, err := time.Parse("2006-01-02", at); err == nil {
		return false
	}
	return true
}

var shaLike = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)
