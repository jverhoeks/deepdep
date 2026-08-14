package extract

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"

	"github.com/jverhoeks/deepdep/internal/graph"
	"github.com/jverhoeks/deepdep/internal/source"
)

// GitLabCI reads .gitlab-ci.yml.
//
// GitLab's include: is the richest recursion in any CI system: a pipeline can
// pull in a raw URL, a file from another project, a GitLab-provided template, or
// a CI/CD component — and each of those can include further pipelines. All of it
// executes with the runner's credentials, and none of it appears in any manifest.
type GitLabCI struct{}

func (GitLabCI) Name() string { return "gitlab-ci" }

func (GitLabCI) Match(p string) bool {
	base := path.Base(p)
	if base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml" || strings.HasSuffix(base, ".gitlab-ci.yml") {
		return true
	}
	// Local includes conventionally live under .gitlab/.
	return strings.HasPrefix(p, ".gitlab/") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"))
}

// image is either a bare string or a mapping with a name key.
type image struct{ Name string }

func (i *image) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		i.Name = value.Value
		return nil
	}
	var m struct {
		Name string `yaml:"name"`
	}
	if err := value.Decode(&m); err != nil {
		return err
	}
	i.Name = m.Name
	return nil
}

// script is either a single command or a list of them.
type script []string

func (s *script) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*s = []string{value.Value}
		return nil
	}
	var list []string
	if err := value.Decode(&list); err != nil {
		return nil // a script can hold nested structures we do not model
	}
	*s = list
	return nil
}

// job covers both real jobs and the `default:` block; GitLab gives them the
// same shape for the fields that matter here.
type job struct {
	Image        *image  `yaml:"image"`
	Services     []image `yaml:"services"`
	Script       script  `yaml:"script"`
	BeforeScript script  `yaml:"before_script"`
	AfterScript  script  `yaml:"after_script"`
}

// includeItem is one entry of include:. A bare string is a local path, or a URL
// when it looks like one.
type includeItem struct {
	Local     string `yaml:"local"`
	Remote    string `yaml:"remote"`
	Template  string `yaml:"template"`
	Project   string `yaml:"project"`
	Ref       string `yaml:"ref"`
	File      any    `yaml:"file"`
	Component string `yaml:"component"`
}

func (i *includeItem) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		if strings.HasPrefix(value.Value, "http://") || strings.HasPrefix(value.Value, "https://") {
			i.Remote = value.Value
		} else {
			i.Local = value.Value
		}
		return nil
	}
	type raw includeItem
	var r raw
	if err := value.Decode(&r); err != nil {
		return err
	}
	*i = includeItem(r)
	return nil
}

type includeList []includeItem

func (l *includeList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		var items []includeItem
		if err := value.Decode(&items); err != nil {
			return err
		}
		*l = items
		return nil
	}
	var one includeItem
	if err := one.UnmarshalYAML(value); err != nil {
		return err
	}
	*l = includeList{one}
	return nil
}

// reserved top-level keys that are not jobs.
var reservedKeys = map[string]bool{
	"include": true, "default": true, "stages": true, "variables": true,
	"workflow": true, "image": true, "services": true, "before_script": true,
	"after_script": true, "cache": true, "pages": true,
}

func (GitLabCI) Extract(_ context.Context, f source.File) ([]graph.Edge, []graph.Node, error) {
	// Jobs are arbitrary top-level keys, so the document is decoded generically
	// and each key classified rather than mapped to a fixed struct.
	var doc map[string]yaml.Node
	if err := yaml.Unmarshal(f.Data, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", f.Path, err)
	}

	var (
		edges []graph.Edge
		nodes []graph.Node
		seen  = map[graph.NodeID]bool{}
	)
	emit := func(n graph.Node, kind graph.EdgeKind) {
		if seen[n.ID] {
			return
		}
		seen[n.ID] = true
		n.Source = f.Path
		nodes = append(nodes, n)
		edges = append(edges, graph.Edge{From: "", To: n.ID, Kind: kind})
	}

	addJob := func(j job) {
		if j.Image != nil && j.Image.Name != "" {
			n, err := imageNode(j.Image.Name)
			if err == nil {
				emit(n, graph.BuildsOn)
			}
		}
		for _, s := range j.Services {
			if s.Name == "" {
				continue
			}
			if n, err := imageNode(s.Name); err == nil {
				emit(n, graph.BuildsOn)
			}
		}
		// before_script, script and after_script all execute arbitrary shell.
		for _, block := range []script{j.BeforeScript, j.Script, j.AfterScript} {
			if len(block) == 0 {
				continue
			}
			emit(opaqueNode(strings.Join(block, "\n")), graph.Installs)
		}
	}

	// Sorted keys keep extraction deterministic; YAML maps decode unordered.
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		node := doc[k]
		switch {
		case k == "include":
			var incs includeList
			if err := node.Decode(&incs); err != nil {
				return nil, nil, fmt.Errorf("%s: include: %w", f.Path, err)
			}
			for _, in := range incs {
				if n, kind, ok := includeNode(in); ok {
					emit(n, kind)
				}
			}
		case k == "default", !reservedKeys[k]:
			var j job
			if err := node.Decode(&j); err != nil {
				continue // not a job shape (a YAML anchor, a scalar); nothing to pull in
			}
			addJob(j)
		}
	}
	return edges, nodes, nil
}

// includeNode turns one include entry into a node.
//
// A local include stays inside the repository, so it is only reported when our
// own Match would not have picked the file up anyway — otherwise it would appear
// twice, once as a marker and once as real content.
func includeNode(in includeItem) (graph.Node, graph.EdgeKind, bool) {
	switch {
	case in.Component != "":
		// gitlab.com/components/sonarqube@1.0.0
		spec, ver, _ := strings.Cut(in.Component, "@")
		parts := strings.Split(strings.TrimPrefix(spec, "gitlab.com/"), "/")
		if len(parts) < 2 {
			return graph.Node{}, "", false
		}
		ns := strings.Join(parts[:len(parts)-1], "/")
		name := parts[len(parts)-1]
		p := packageurl.NewPackageURL("gitlab", ns, name, ver, nil, "")
		n := graph.Node{
			ID: graph.NodeID(p.ToString()), Ecosystem: "gitlab",
			Name: ns + "/" + name, Version: ver,
			Completeness: graph.Resolved,
		}
		if ver == "" {
			n.Completeness, n.Reason = graph.Declared, graph.ReasonUnpinnedRef
		}
		return n, graph.Invokes, true

	case in.Project != "":
		ns, name := splitLast(in.Project)
		p := packageurl.NewPackageURL("gitlab", ns, name, in.Ref, nil, fileOf(in.File))
		n := graph.Node{
			ID: graph.NodeID(p.ToString()), Ecosystem: "gitlab",
			Name: in.Project, Version: in.Ref,
			Completeness: graph.Resolved,
		}
		// No ref means the default branch, which moves under you between runs.
		if in.Ref == "" {
			n.Completeness, n.Reason = graph.Declared, graph.ReasonUnpinnedRef
		}
		return n, graph.Invokes, true

	case in.Remote != "":
		// A URL has no version at all: its contents can change between two runs
		// and nothing records what it served last time.
		n := hashedNode("remote-include", in.Remote)
		n.Completeness, n.Reason = graph.Declared, graph.ReasonUnpinnedRef
		return n, graph.Invokes, true

	case in.Template != "":
		n := hashedNode("gitlab-template", in.Template)
		n.Completeness, n.Reason = graph.Declared, graph.ReasonUnpinnedRef
		return n, graph.Invokes, true

	case in.Local != "":
		if (GitLabCI{}).Match(strings.TrimPrefix(in.Local, "/")) {
			return graph.Node{}, "", false // we will scan the file itself
		}
		n := hashedNode("local-include", in.Local)
		n.Completeness, n.Reason = graph.Declared, "no-extractor"
		return n, graph.Invokes, true
	}
	return graph.Node{}, "", false
}

func splitLast(p string) (namespace, name string) {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

// fileOf handles include:file being either a single path or a list of them.
func fileOf(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		var parts []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}
