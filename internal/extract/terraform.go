package extract

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
	versionpkg "github.com/jverhoeks/deepdep/internal/version"
)

// Terraform reads .tf files.
//
// Three things in a Terraform configuration pull in code, and all three run with
// the credentials of whoever applies it:
//
//   - required_providers — plugin binaries downloaded from a registry;
//   - required_version   — the CLI itself, which has its own CVEs;
//   - module blocks      — other people's configuration, fetched from a
//     registry or straight from git.
//
// HCL is parsed by hand rather than with hashicorp/hcl. The blocks that matter
// are a small, regular subset — attribute assignments inside named blocks — and
// pulling in a large parser to read a dependency manifest is a poor trade for a
// tool whose subject is dependency weight. The cost is that exotic HCL
// (dynamic blocks, interpolated versions) is not understood; those become
// frontier nodes rather than wrong ones.
type Terraform struct{}

func (Terraform) Name() string { return "terraform" }

func (Terraform) Match(p string) bool {
	if !strings.HasSuffix(p, ".tf") {
		return false
	}
	// .terraform/ holds modules and plugins already downloaded — someone else's
	// configuration, not this repository's declaration.
	for _, seg := range strings.Split(p, "/") {
		if seg == ".terraform" {
			return false
		}
	}
	return true
}

func (Terraform) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	var (
		edges []graph.Edge
		nodes []graph.Node
	)
	doc := parseHCL(f.Data)

	// --- the CLI itself ---------------------------------------------------
	//
	// Terraform gets its OWN ecosystem, not pkg:golang, even though its
	// advisories are filed against github.com/hashicorp/terraform and that is
	// what the query is translated to.
	//
	// Identifying it as a Go module directly made the walker resolve it through
	// the module proxy and expand Terraform's entire internal build tree — 2,082
	// Go modules on a repository whose actual supply chain is two providers.
	// Those are Terraform's own dependencies, not this configuration's: nothing
	// here can change them, and no advisory against them describes a risk this
	// repository took on. The CLI is a leaf.
	if c := doc.requiredVersion; c != "" {
		id := TerraformCLIID("")
		edges = append(edges, graph.Edge{
			To: id, Kind: graph.BuildsOn, Spec: c, Scope: graph.Prod,
		})
		nodes = append(nodes, graph.Node{
			ID: id, Ecosystem: TerraformCLIEcosystem, Name: "terraform",
			Completeness: graph.Declared, Reason: graph.ReasonUnpinnedRef,
			Source: f.Path,
		})
	}

	// --- providers --------------------------------------------------------
	for _, p := range doc.providers {
		id, err := TerraformProviderID(p.source, "")
		if err != nil {
			continue
		}
		edges = append(edges, graph.Edge{
			To: id, Kind: graph.DependsOn, Spec: p.version, Scope: graph.Prod,
		})
	}

	// --- modules ----------------------------------------------------------
	for _, m := range doc.modules {
		n, ok := terraformModuleNode(m)
		if !ok {
			continue
		}
		n.Source = f.Path
		nodes = append(nodes, n)
		edges = append(edges, graph.Edge{
			To: n.ID, Kind: graph.DependsOn, Spec: m.version, Scope: graph.Prod,
		})
	}

	return edges, nodes, nil
}

// TerraformModule is the Go module Terraform itself is developed as, and the
// name its advisories are filed under.
const TerraformModule = "github.com/hashicorp/terraform"

// TerraformCLIEcosystem identifies the Terraform binary. It is deliberately not
// "golang": see the comment at the required_version branch above.
const TerraformCLIEcosystem = "terraform-cli"

// TerraformCLIID mints the node for the Terraform binary at a version.
func TerraformCLIID(version string) graph.NodeID {
	p := packageurl.NewPackageURL(TerraformCLIEcosystem, "hashicorp", "terraform", version, nil, "")
	return graph.NodeID(p.ToString())
}

// TerraformProviderID mints a provider node id.
//
// Providers get their own PURL type rather than being identified as the Go
// module they are built from. The module is not what a configuration declares,
// not what the registry serves, and not what the lockfile pins — and Go's
// version semantics (a lower bound resolved by MVS) cannot express the upper
// bound a "~>" constraint states. The mapping to a Go module happens at
// ADVISORY QUERY time instead, where it is needed and nowhere else.
//
// A bare "aws" means the hashicorp namespace, exactly as Terraform resolves it.
func TerraformProviderID(src, version string) (graph.NodeID, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return "", fmt.Errorf("empty provider source")
	}
	// A source may carry a registry host: registry.terraform.io/hashicorp/aws.
	parts := strings.Split(src, "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	ns, name := "hashicorp", parts[0]
	if len(parts) == 2 {
		ns, name = parts[0], parts[1]
	}
	if name == "" {
		return "", fmt.Errorf("unrecognised provider source %q", src)
	}
	p := packageurl.NewPackageURL("terraform", ns, name, version, nil, "")
	return graph.NodeID(p.ToString()), nil
}

// terraformModuleNode describes one module block.
func terraformModuleNode(m hclModule) (graph.Node, bool) {
	src := strings.TrimSpace(m.source)
	if src == "" {
		return graph.Node{}, false
	}
	// A local module is a directory in this repository. It is not fetched, has
	// no version and no advisory record; the code it contains is read by this
	// same extractor from its own files.
	if strings.HasPrefix(src, "./") || strings.HasPrefix(src, "../") {
		return graph.Node{}, false
	}

	// A registry source is NAMESPACE/NAME/PROVIDER — three parts, where the
	// third names the target platform rather than another path segment.
	if parts := strings.Split(src, "/"); len(parts) == 3 && !strings.Contains(src, "::") && !strings.Contains(src, ".git") {
		p := packageurl.NewPackageURL("terraform-module", parts[0], parts[1]+"-"+parts[2], m.version, nil, "")
		return graph.Node{
			ID:           graph.NodeID(p.ToString()),
			Ecosystem:    "terraform-module",
			Name:         src,
			Version:      m.version,
			Completeness: graph.Declared,
			Reason:       graph.ReasonUnpinnedRef,
		}, true
	}

	// Anything else — git::, github.com/..., a URL — is fetched from source
	// control. There is no registry to ask and no version list to expand, so it
	// is an honest frontier rather than a resolvable package.
	p := packageurl.NewPackageURL(packageurl.TypeGeneric, "terraform-module", sanitiseModuleName(src), m.version, nil, "")
	return graph.Node{
		ID:           graph.NodeID(p.ToString()),
		Ecosystem:    packageurl.TypeGeneric,
		Name:         src,
		Version:      m.version,
		Completeness: graph.Declared,
		Reason:       "vcs-module",
		Note:         src,
	}, true
}

var moduleNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func sanitiseModuleName(s string) string {
	return strings.Trim(moduleNameUnsafe.ReplaceAllString(s, "-"), "-")
}

// ------------------------------------------------------------------ HCL ---

type hclProvider struct{ source, version string }
type hclModule struct{ source, version string }

type hclDoc struct {
	requiredVersion string
	providers       []hclProvider
	modules         []hclModule
}

var (
	hclAttr        = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*"([^"]*)"`)
	hclBlockHeader = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_-]*)(?:\s+"([^"]*)")?(?:\s+"([^"]*)")?\s*\{`)
)

// parseHCL walks the brace structure far enough to find the three blocks that
// declare dependencies. It tracks a path of block names rather than building a
// tree: the questions are all of the form "which block am I inside?".
func parseHCL(data []byte) hclDoc {
	var (
		doc   hclDoc
		stack []string
		// providerName is the label of the required_providers entry currently
		// open, e.g. `aws = {` — its source may be omitted, in which case the
		// label itself is the source.
		providerName string
		cur          hclProvider
		curModule    hclModule
	)

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		trimmed := strings.TrimSpace(stripHCLComment(sc.Text()))
		if trimmed == "" {
			continue
		}

		if trimmed == "}" || strings.HasPrefix(trimmed, "}") {
			if len(stack) > 0 {
				closing := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				switch {
				case closing == "provider-entry" && providerName != "":
					if cur.source == "" {
						cur.source = providerName
					}
					doc.providers = append(doc.providers, cur)
					cur, providerName = hclProvider{}, ""
				case strings.HasPrefix(closing, "module:"):
					doc.modules = append(doc.modules, curModule)
					curModule = hclModule{}
				}
			}
			continue
		}

		if m := hclBlockHeader.FindStringSubmatch(trimmed); m != nil {
			name := m[1]
			switch {
			case name == "module":
				stack = append(stack, "module:"+m[2])
				curModule = hclModule{}
			case inBlock(stack, "required_providers"):
				// Inside required_providers every block header is a provider
				// local name: `aws = {` parses as a header once the "=" is gone.
				stack = append(stack, "provider-entry")
				providerName = name
			default:
				stack = append(stack, name)
			}
			continue
		}
		// `aws = {` has an equals sign the header regex does not accept.
		if inBlock(stack, "required_providers") && strings.HasSuffix(trimmed, "{") {
			if eq := strings.Index(trimmed, "="); eq > 0 {
				stack = append(stack, "provider-entry")
				providerName = strings.TrimSpace(trimmed[:eq])
				continue
			}
		}

		if m := hclAttr.FindStringSubmatch(trimmed); m != nil {
			key, val := m[1], m[2]
			switch {
			case key == "required_version" && inBlock(stack, "terraform"):
				doc.requiredVersion = val
			case len(stack) > 0 && stack[len(stack)-1] == "provider-entry":
				if key == "source" {
					cur.source = val
				}
				if key == "version" {
					cur.version = val
				}
			case len(stack) > 0 && strings.HasPrefix(stack[len(stack)-1], "module:"):
				if key == "source" {
					curModule.source = val
				}
				if key == "version" {
					curModule.version = val
				}
			}
		}
	}
	return doc
}

// stripHCLComment removes a trailing # or // comment, ignoring both inside a
// quoted string.
//
// A module source is routinely "git::https://example.com/mod.git", and cutting
// at the first "//" truncates it mid-string — the line then fails to parse and
// the dependency vanishes silently. The same trap caught the bun lockfile's
// JSONC reader, where a registry URL inside a string started a comment.
func stripHCLComment(line string) string {
	inString, escaped := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
		case c == '#':
			return line[:i]
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return line[:i]
		}
	}
	return line
}

func inBlock(stack []string, name string) bool {
	for _, s := range stack {
		if s == name {
			return true
		}
	}
	return false
}

// TerraformVersionFile reads the files that PIN the Terraform binary.
//
// required_version in a .tf file is a constraint — ">= 1.5.0" names no version
// and cannot be checked against an advisory. The concrete version lives
// elsewhere: .terraform-version (tfenv) or a terraform line in .tool-versions
// (asdf). Those are what make Terraform's own CVEs checkable rather than merely
// declared.
type TerraformVersionFile struct{}

func (TerraformVersionFile) Name() string { return "terraform-version" }

func (TerraformVersionFile) Match(p string) bool {
	switch path.Base(p) {
	case ".terraform-version", ".tool-versions":
		return true
	}
	return false
}

func (TerraformVersionFile) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	ver := ""
	if path.Base(f.Path) == ".terraform-version" {
		ver = strings.TrimSpace(string(f.Data))
	} else {
		// .tool-versions is one "tool version..." per line and names many tools;
		// only the terraform line is ours. Other tools are left to Coverage.
		sc := bufio.NewScanner(bytes.NewReader(f.Data))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && fields[0] == "terraform" {
				ver = fields[1]
				break
			}
		}
	}
	// "latest" and a tfenv range like "latest:^1.5" name no single version, so
	// there is nothing an advisory could be matched against.
	if ver == "" || strings.HasPrefix(ver, "latest") {
		return nil, nil, nil
	}
	if _, err := versionpkg.Terraform.Parse(ver); err != nil {
		return nil, nil, nil
	}

	id := TerraformCLIID(ver)
	return []graph.Edge{{To: id, Kind: graph.BuildsOn, Spec: ver, Scope: graph.Prod}},
		[]graph.Node{{
			ID: id, Ecosystem: TerraformCLIEcosystem, Name: "terraform", Version: ver,
			// A pinned binary version is a fact, and the whole point: this is
			// what an advisory can actually be matched against.
			Completeness: graph.Resolved, ResolvedRef: ver, Source: f.Path,
		}}, nil
}
