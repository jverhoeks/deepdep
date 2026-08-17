package effective

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// YarnLock reads yarn.lock.
//
// There are TWO formats behind that one filename and they are different
// parsers, not one with a flag:
//
//   - Yarn v1 uses a bespoke format — an unquoted descriptor line ending in a
//     colon, then indented "key value" pairs.
//   - Yarn Berry (v2+) emits real YAML, with a `__metadata` block and
//     `resolution:` entries.
//
// Berry is detected by its metadata block rather than by guessing from syntax,
// because v1 files are ALMOST valid YAML and a YAML parser will happily read
// part of one and return a confidently incomplete answer.
type YarnLock struct{}

func (YarnLock) PackageManager() string { return "yarn" }

func (YarnLock) Resolve(_ context.Context, s source.Source) ([]Instance, error) {
	var out []Instance

	err := s.WalkIf(func(p string) bool {
		if path.Base(p) != "yarn.lock" {
			return false
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == "node_modules" {
				return false
			}
		}
		return true
	}, func(f source.File) error {
		dir := path.Dir(f.Path)
		var pairs [][2]string
		if isYarnBerry(f.Data) {
			pairs = parseYarnBerry(f.Data)
		} else {
			pairs = parseYarnV1(f.Data)
		}
		for _, nv := range pairs {
			id, err := graph.NPMNodeID(nv[0], nv[1])
			if err != nil {
				continue
			}
			// Yarn hoists like npm but the lockfile records one entry per
			// resolved (name, version), so the version is part of the locator:
			// two majors of one package legitimately coexist.
			out = append(out, Instance{
				Locator:     dir + "#" + nv[0] + "@" + nv[1],
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

// isYarnBerry looks for the __metadata block Berry always writes. Sniffing the
// format rather than trying YAML first matters: a v1 file parses as YAML far
// enough to return a partial, wrong answer instead of an error.
func isYarnBerry(data []byte) bool {
	return bytes.Contains(data, []byte("__metadata:"))
}

type yarnBerryDoc map[string]struct {
	Version    string `yaml:"version"`
	Resolution string `yaml:"resolution"`
}

func parseYarnBerry(data []byte) [][2]string {
	var doc yarnBerryDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var out [][2]string
	for key, entry := range doc {
		if entry.Version == "" {
			continue // __metadata and workspace entries
		}
		name, protocol := "", ""
		if entry.Resolution != "" {
			// "lodash@npm:4.17.21" — the resolution names the real package,
			// which matters when a dependency was declared under an alias.
			name, protocol = splitNameAt(entry.Resolution)
		}
		if name == "" {
			name, protocol = splitNameAt(key)
		}
		// The protocol sits AFTER the separator: "app@workspace:." is a member
		// of this repository, not something fetched. Testing the whole string
		// for a "workspace:" prefix never matches and counts the project as its
		// own dependency.
		if name == "" || strings.HasPrefix(protocol, "workspace:") {
			continue
		}
		out = append(out, [2]string{name, entry.Version})
	}
	return out
}

// parseYarnV1 reads the bespoke v1 format: a descriptor line ending in ":",
// then indented fields, of which only `version` is needed.
func parseYarnV1(data []byte) [][2]string {
	var (
		out  [][2]string
		name string
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			// A descriptor line can list several ranges for one package:
			//   "lodash@^4.0.0", "lodash@^4.17.0":
			desc := strings.TrimSuffix(strings.TrimSpace(line), ":")
			first := strings.Split(desc, ",")[0]
			first = strings.Trim(strings.TrimSpace(first), `"`)
			name, _ = splitNameAt(first)
			continue
		}
		t := strings.TrimSpace(line)
		if name != "" && strings.HasPrefix(t, "version ") {
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "version")), `"`)
			if v != "" {
				out = append(out, [2]string{name, v})
			}
			name = ""
		}
	}
	return out
}

// splitNameAt splits "name@range" while keeping an @scope intact, which is why
// the separator is looked for AFTER the first character.
func splitNameAt(s string) (name, rest string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	i := strings.LastIndex(s, "@")
	if i <= 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// dedupeInstances collapses identical (locator, node) pairs. A v1 lockfile lists
// one entry per DESCRIPTOR, so several ranges resolving to the same version
// would otherwise count that package several times.
func dedupeInstances(in []Instance) []Instance {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, i := range in {
		k := i.Locator + "\x00" + string(i.NodeID)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, i)
	}
	return out
}
