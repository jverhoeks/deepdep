package main

import (
	"strings"
	"testing"
)

// `deepdep clean` on its own must not be a store-wiping command.
func TestCleanWithNoFlagsRefuses(t *testing.T) {
	_, err := cleanCmd([]string{"--db", "/tmp/deepdep-clean-test-should-not-be-created.db"})
	if err == nil {
		t.Fatal("clean with no selection succeeded; it must refuse")
	}
	if !strings.Contains(err.Error(), "--keep") {
		t.Errorf("error %q should point at the flags that select something", err)
	}
}
