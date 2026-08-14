package cache_test

import (
	"strings"
	"testing"

	"github.com/jverhoeks/deepdep/internal/cache"
)

func TestFSCacheRoundTrip(t *testing.T) {
	c := cache.NewFS(t.TempDir())
	k := cache.Key("npm", "lodash", "4.17.21")

	if _, ok := c.Get(k); ok {
		t.Fatal("empty cache returned a hit")
	}
	if err := c.Put(k, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get(k)
	if !ok || string(got) != `{"ok":true}` {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestKeyIsPathSafeForScopedNames(t *testing.T) {
	k := cache.Key("npm", "@scope/pkg", "1.0.0")
	if strings.ContainsAny(k, "/\\") {
		t.Errorf("key %q must not contain path separators", k)
	}
	if k == cache.Key("npm", "@scope/other", "1.0.0") {
		t.Error("distinct names must not collide")
	}
}

func TestPutBlobIsContentAddressed(t *testing.T) {
	c := cache.NewFS(t.TempDir())
	a, err := c.PutBlob([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.PutBlob([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("same content gave different digests %q %q", a, b)
	}
	if other, _ := c.PutBlob([]byte("world")); other == a {
		t.Error("different content gave the same digest")
	}
	got, ok := c.GetBlob(a)
	if !ok || string(got) != "hello" {
		t.Fatal("blob round-trip failed")
	}
}

func TestCacheSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	k := cache.Key("npm", "is-string", "1.0.7")
	if err := cache.NewFS(dir).Put(k, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	got, ok := cache.NewFS(dir).Get(k)
	if !ok || string(got) != "payload" {
		t.Fatal("cache did not persist across instances")
	}
}
