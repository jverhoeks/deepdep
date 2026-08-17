package effective

import (
	"context"
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// BunLock reads bun.lock.
//
// Only the TEXT lockfile is read. bun.lockb is a binary format with no published
// specification, and guessing at its layout would produce an answer nobody could
// check — so it stays in the catalogue as an honest `no-extractor` frontier and
// a repository using it is reported as unexpanded rather than as empty. Bun
// itself has moved to the text format by default, and `bun install --save-text-lockfile`
// converts an existing one.
//
// bun.lock is JSONC: JSON with comments and trailing commas. Those are stripped
// before decoding rather than pulling in a JSONC dependency.
type BunLock struct{}

func (BunLock) PackageManager() string { return "bun" }

type bunLockDoc struct {
	// packages maps a name to a heterogeneous array whose FIRST element is the
	// "name@version" descriptor. The rest of the array differs by entry kind, so
	// only the first element is read and the rest deliberately ignored.
	Packages map[string][]json.RawMessage `json:"packages"`
}

func (BunLock) Resolve(_ context.Context, s source.Source) ([]Instance, error) {
	var out []Instance

	err := s.WalkIf(func(p string) bool {
		if path.Base(p) != "bun.lock" {
			return false
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == "node_modules" {
				return false
			}
		}
		return true
	}, func(f source.File) error {
		var doc bunLockDoc
		if err := json.Unmarshal(stripJSONC(f.Data), &doc); err != nil {
			// A lockfile we cannot read must not fail the scan; Coverage still
			// reports the file as an unexpanded surface.
			return nil
		}
		dir := path.Dir(f.Path)
		for key, entry := range doc.Packages {
			name, ver := key, ""
			if len(entry) > 0 {
				var desc string
				if err := json.Unmarshal(entry[0], &desc); err == nil && desc != "" {
					if n, v := splitNameAt(desc); n != "" && v != "" {
						name, ver = n, v
					}
				}
			}
			if ver == "" {
				continue // a workspace or link entry, with nothing resolved
			}
			id, err := graph.NPMNodeID(name, ver)
			if err != nil {
				continue
			}
			out = append(out, Instance{
				Locator:     dir + "#" + key,
				NodeID:      id,
				DerivedFrom: "lockfile",
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dedupeInstances(out), nil
}

// stripJSONC removes comments and trailing commas so encoding/json can read a
// bun.lock. String literals are respected, or a URL's "//" would start a comment
// and silently truncate the document.
func stripJSONC(b []byte) []byte {
	var (
		out      []byte
		inString bool
		inLine   bool
		inBlock  bool
		escaped  bool
	)
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inLine:
			if c == '\n' {
				inLine = false
				out = append(out, c)
			}
		case inBlock:
			if c == '*' && i+1 < len(b) && b[i+1] == '/' {
				inBlock = false
				i++
			}
		case inString:
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			inLine = true
			i++
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			inBlock = true
			i++
		default:
			out = append(out, c)
		}
	}
	return trailingComma.ReplaceAll(out, []byte("$1"))
}

var trailingComma = regexp.MustCompile(`,\s*([}\]])`)
