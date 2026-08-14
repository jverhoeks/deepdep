package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	git "github.com/go-git/go-git/v6"
)

// openRemote clones into a directory keyed by the remote URL and then reads it
// as a local source.
//
// Clone depth is conditional. Depth 1 is much cheaper, but a shallow clone
// cannot reach historical commits, so any run that will time-travel needs full
// history. Getting this wrong shows up only later, as an unresolvable revision.
func openRemote(ctx context.Context, url, cacheDir, at string) (Source, error) {
	sum := sha256.Sum256([]byte(url))
	dst := filepath.Join(cacheDir, "repos", hex.EncodeToString(sum[:])[:16])

	needHistory := at != ""
	if fi, err := os.Stat(filepath.Join(dst, ".git")); err == nil && fi.IsDir() {
		if !needHistory || !isShallow(dst) {
			return openLocal(dst, at)
		}
		// Cached clone is shallow but this run needs history: re-clone in full.
		if err := os.RemoveAll(dst); err != nil {
			return nil, err
		}
	}

	depth := 1
	if needHistory {
		depth = 0 // full clone
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	if _, err := git.PlainCloneContext(ctx, dst, &git.CloneOptions{
		URL:   url,
		Depth: depth,
		Bare:  false, // v6: a field, no longer a positional argument
	}); err != nil {
		return nil, err
	}
	s, err := openLocal(dst, at)
	if err != nil {
		return nil, err
	}
	if ls, ok := s.(*localSource); ok {
		ls.repo = url
	}
	return s, nil
}

func isShallow(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git", "shallow"))
	return err == nil
}
