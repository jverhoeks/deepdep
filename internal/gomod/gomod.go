// Package gomod parses go.mod.
//
// It sits in its own package because two layers legitimately need the same
// parse and mean different things by it. internal/extract reads the DIRECT
// requirements as this repository's declarations; internal/effective reads the
// whole selected build list, indirect entries included, as the lockfile Go does
// not otherwise have. Duplicating a parser between them would let the two
// answers drift apart, and having one import the other would couple layers that
// are deliberately independent.
//
// It is written by hand rather than with golang.org/x/mod/modfile. The file is
// line-oriented and the directives that matter are trivially recognised; adding
// a dependency in order to read a dependency manifest is a poor trade for a tool
// whose entire subject is dependency weight.
package gomod

import (
	"bufio"
	"bytes"
	"strings"
)

// Requirement is one `require` entry.
type Requirement struct {
	Module  string
	Version string
	// Indirect marks an entry written with `// indirect`: a transitive module
	// that MVS pulled up into the main module's go.mod. It is part of the build
	// but it is NOT something this repository declared, and the two must not be
	// conflated — "who can fix it" turns entirely on the difference.
	Indirect bool
}

// Replacement is one `replace` target.
type Replacement struct {
	Target  string
	Version string
	// Local marks a replacement pointing at a directory rather than a module.
	// There is no published package to resolve and no advisory record to find.
	Local bool
}

// Parse reads the require and replace directives.
//
// exclude and retract are deliberately ignored. Neither names a dependency:
// exclude removes a version from MVS's consideration, and retract is a statement
// by a module's own author about its own versions. Recording either as an edge
// would invent a dependency on a version named precisely because it is unwanted.
func Parse(data []byte) ([]Requirement, map[string]Replacement) {
	var (
		reqs     []Requirement
		replaces = map[string]Replacement{}
		block    string // which parenthesised block we are inside, if any
	)

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		indirect := strings.Contains(line, "// indirect")
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
			consume(block, line, indirect, &reqs, replaces)
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch {
		case fields[1] == "(" && isDirective(fields[0]):
			block = fields[0]
		case fields[0] == "require" || fields[0] == "replace":
			consume(fields[0], strings.Join(fields[1:], " "), indirect, &reqs, replaces)
		}
	}
	return reqs, replaces
}

// isDirective covers exclude too: its block must be RECOGNISED so its contents
// are skipped as a block, rather than falling through and being read as
// requirements.
func isDirective(s string) bool {
	return s == "require" || s == "replace" || s == "exclude" || s == "retract"
}

// consume reads one directive body — the part after `require` or `replace`, or
// one line inside the corresponding block.
func consume(kind, body string, indirect bool, reqs *[]Requirement, replaces map[string]Replacement) {
	fields := strings.Fields(body)
	switch kind {
	case "require":
		if len(fields) >= 2 {
			*reqs = append(*reqs, Requirement{Module: fields[0], Version: fields[1], Indirect: indirect})
		}
	case "replace":
		// old [version] => new [version]
		arrow := -1
		for i, f := range fields {
			if f == "=>" {
				arrow = i
				break
			}
		}
		if arrow <= 0 || arrow == len(fields)-1 {
			return
		}
		right := fields[arrow+1:]
		rep := Replacement{Target: right[0]}
		if len(right) > 1 {
			rep.Version = right[1]
		}
		// A filesystem path is the one target form that is not a module path.
		// Go requires it to start with ./ or ../, or to be absolute.
		rep.Local = strings.HasPrefix(rep.Target, "./") ||
			strings.HasPrefix(rep.Target, "../") ||
			strings.HasPrefix(rep.Target, "/")
		replaces[fields[0]] = rep
	}
}
