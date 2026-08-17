// Package graph holds the heterogeneous supply-chain graph: PURL-identified
// nodes of any kind (packages, container images, CI actions, opaque frontiers)
// joined by typed "pulls in" edges.
package graph

import (
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
)

// NodeID is a canonical Package URL. It is ALWAYS produced by packageurl-go,
// never by string concatenation: npm scopes percent-encode (@types/node becomes
// pkg:npm/%40types/node), and a hand-built ID would silently split a node in two
// and corrupt every join against the store.
type NodeID string

// NewNodeID canonicalises an existing PURL string.
func NewNodeID(purl string) (NodeID, error) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return "", err
	}
	return NodeID(p.ToString()), nil
}

// NodeIDFor mints a canonical PURL for any ecosystem.
//
// Naming rules are per-ecosystem and not interchangeable: npm scopes become a
// namespace so they percent-encode, while PyPI folds case and separators per
// PEP 503. Minting an id without the right rule splits one package across
// several nodes and silently understates how many paths reach it.
func NodeIDFor(ecosystem, name, version string) (NodeID, error) {
	switch ecosystem {
	case packageurl.TypeNPM:
		return NPMNodeID(name, version)
	case packageurl.TypePyPi:
		return PyPINodeID(name, version), nil
	default:
		// A name carrying a slash is a namespace/name pair that has already been
		// flattened once — deb/debian/curl round-trips through split() as
		// name="debian/curl". Passing that through whole percent-encodes the
		// slash and mints pkg:deb/debian%2Fcurl, a SECOND node for a package
		// that already exists, splitting its paths and its advisories.
		namespace := ""
		if i := strings.LastIndex(name, "/"); i > 0 {
			namespace, name = name[:i], name[i+1:]
		}
		p := packageurl.NewPackageURL(ecosystem, namespace, name, version, nil, "")
		return NodeID(p.ToString()), nil
	}
}

// PyPINodeID applies PEP 503 normalisation: names are case-insensitive and runs
// of -, _ and . are equivalent, so "Typing_Extensions" and "typing-extensions"
// are one package.
func PyPINodeID(name, version string) NodeID {
	norm := pypiSep.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	p := packageurl.NewPackageURL(packageurl.TypePyPi, "", norm, version, nil, "")
	return NodeID(p.ToString())
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// NPMNodeID mints a canonical npm PURL. An @scope becomes the PURL namespace so
// it is percent-encoded correctly. An empty version yields a version-less PURL
// (pkg:npm/lodash) — the walker uses that form for a target that is still just a
// range, before any concrete version has been chosen.
func NPMNodeID(name, version string) (NodeID, error) {
	namespace := ""
	if strings.HasPrefix(name, "@") {
		if i := strings.Index(name, "/"); i > 0 {
			namespace, name = name[:i], name[i+1:]
		}
	}
	p := packageurl.NewPackageURL(packageurl.TypeNPM, namespace, name, version, nil, "")
	return NodeID(p.ToString()), nil
}

// packageTypes are the PURL types that denote a software package — something a
// registry publishes and an advisory database can match.
var packageTypes = map[string]bool{
	"npm": true, "pypi": true, "deb": true, "apk": true, "rpm": true,
	"cargo": true, "maven": true, "golang": true, "nuget": true,
	"gem": true, "composer": true, "hex": true, "pub": true, "conan": true,
	"cocoapods": true, "swift": true, "cran": true, "hackage": true,

	// Terraform providers and the CLI are published by a registry AND matchable
	// by an advisory database — through the Go module each is developed as, which
	// is what advisory.TerraformProviderPURL and TerraformCLIPURL translate to.
	//
	// "terraform-module" is deliberately ABSENT. The registry publishes modules,
	// but no advisory database files against them, so counting them as packages
	// would enlarge the auditable denominator with things that can never be
	// audited — suppressing the grade of every Terraform repository in the name
	// of covering it. They remain nodes, and inventory, just not package
	// versions.
	"terraform": true, "terraform-cli": true,
}

// IsPackage reports whether an id denotes a software package.
//
// A container image, a workflow file, a shell step and a coverage frontier are
// all legitimate NODES, and none of them is a package version. Treating them as
// one inflated every "checked N package versions" claim — kubernetes reported
// 198 where 3 were packages — sent build-file PURLs to OSV, and counted shell
// steps as floating dependencies in the hygiene metrics.
func IsPackage(id NodeID) bool {
	s := strings.TrimPrefix(string(id), "pkg:")
	typ, _, ok := strings.Cut(s, "/")
	if !ok {
		return false
	}
	return packageTypes[typ]
}
