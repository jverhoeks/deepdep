// Package cache is the immutable half of persistence: raw bytes on the
// filesystem, addressed by keys that can never go stale.
//
// The store (internal/store) holds derived FACTS and points at these bodies by
// digest. The split matters because the two have opposite lifetimes: a
// (ecosystem, name, exact-version) requirement set is true forever, whereas a
// packument or an advisory changes under you. Only the former belongs here.
// Mutable documents go through the observation path, which records observed_at
// and re-fetches — putting one in this cache silently freezes the resolver.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
)

// Cache stores immutable bytes.
type Cache interface {
	Get(key string) ([]byte, bool)
	Put(key string, b []byte) error
	// PutBlob stores content addressed by its own digest and returns that digest.
	PutBlob(b []byte) (string, error)
	GetBlob(sha string) ([]byte, bool)
}

// Key builds a cache key from an immutable triple. Hashing keeps it path-safe
// for scoped npm names like "@types/node" and for versions containing "/".
func Key(ecosystem, name, version string) string {
	h := sha256.New()
	h.Write([]byte(ecosystem))
	h.Write([]byte{0})
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(version))
	return hex.EncodeToString(h.Sum(nil))
}
