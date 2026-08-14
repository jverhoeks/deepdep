package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// FSCache is a sharded content store on disk. There is deliberately no TTL:
// every key it accepts is immutable by construction.
type FSCache struct{ dir string }

func NewFS(dir string) *FSCache { return &FSCache{dir: dir} }

func (c *FSCache) path(key string) string {
	if len(key) < 2 {
		return filepath.Join(c.dir, key)
	}
	// Shard on the first two hex chars: a flat directory with tens of thousands
	// of entries is slow on several filesystems.
	return filepath.Join(c.dir, key[:2], key)
}

func (c *FSCache) Get(key string) ([]byte, bool) {
	b, err := os.ReadFile(c.path(key))
	if err != nil {
		return nil, false
	}
	return b, true
}

// Put writes atomically: a torn file would poison a cache that never expires.
func (c *FSCache) Put(key string, b []byte) error {
	p := c.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func (c *FSCache) PutBlob(b []byte) (string, error) {
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])
	if _, ok := c.Get(sha); ok {
		return sha, nil // already stored; content-addressed means identical
	}
	return sha, c.Put(sha, b)
}

func (c *FSCache) GetBlob(sha string) ([]byte, bool) { return c.Get(sha) }
