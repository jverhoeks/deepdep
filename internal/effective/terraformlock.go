package effective

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/jverhoeks/deepdep/internal/extract"
	"github.com/jverhoeks/deepdep/internal/source"
)

// TerraformLock reads .terraform.lock.hcl.
//
// This is the file that makes a Terraform repository auditable. A configuration
// declares ranges — "~> 5.31" admits every 5.31.x — but the lock records the
// exact provider version `terraform init` selected, together with its hashes.
// Those are facts about what will be downloaded and executed on the next apply.
//
// Providers install one version each per configuration directory, so the
// locator is the directory plus the provider address.
type TerraformLock struct{}

func (TerraformLock) PackageManager() string { return "terraform" }

var (
	tfLockProvider = regexp.MustCompile(`^\s*provider\s+"([^"]+)"\s*\{`)
	tfLockVersion  = regexp.MustCompile(`^\s*version\s*=\s*"([^"]+)"`)
)

func (TerraformLock) Resolve(_ context.Context, s source.Source) ([]Instance, error) {
	var out []Instance

	err := s.WalkIf(func(p string) bool {
		if path.Base(p) != ".terraform.lock.hcl" {
			return false
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".terraform" {
				return false
			}
		}
		return true
	}, func(f source.File) error {
		dir := path.Dir(f.Path)
		var addr string
		sc := bufio.NewScanner(bytes.NewReader(f.Data))
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if m := tfLockProvider.FindStringSubmatch(line); m != nil {
				addr = m[1]
				continue
			}
			if addr == "" {
				continue
			}
			if m := tfLockVersion.FindStringSubmatch(line); m != nil {
				id, err := extract.TerraformProviderID(addr, m[1])
				if err == nil {
					out = append(out, Instance{
						Locator:     dir + "#" + addr,
						NodeID:      id,
						DerivedFrom: "lockfile",
					})
				}
				addr = "" // one version per provider block
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
