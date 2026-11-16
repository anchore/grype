package search

import (
	"fmt"

	"github.com/anchore/grype/grype/internal/architecture"
	"github.com/anchore/grype/grype/vulnerability"
)

// ByArchitecture returns criteria which will match vulnerabilities that apply to a package of the
// given architecture. The same rules apply to affected and unaffected vulnerabilities: an unset
// architecture on either side matches anything (unless required, see WithRequired), and case is
// normalized. Other spelling differences (deb "source" vs "src", "x86_64" vs "amd64") are folded
// through the built-in default aliases, or through the table given to WithAliases, which the v6
// vulnerability provider uses to apply its DB's alias table.
func ByArchitecture(arch string) *ArchitectureCriteria {
	return &ArchitectureCriteria{
		Arch: arch,
	}
}

type ArchitectureCriteria struct {
	Arch string

	// required excludes vulnerabilities that do not specify an architecture (see WithRequired).
	required bool

	// aliases is the architecture alias table (alias spelling -> canonical token) both sides are
	// folded through before comparing (see WithAliases); nil uses the built-in default aliases.
	aliases map[string]string
}

// WithAliases returns a copy of the criteria that folds architectures through the provided alias
// table (alias spelling -> canonical token) instead of the built-in defaults, leaving c unchanged.
func (c *ArchitectureCriteria) WithAliases(aliases map[string]string) *ArchitectureCriteria {
	out := *c
	out.aliases = aliases
	return &out
}

// WithRequired returns a copy of the criteria that, when required, only matches vulnerabilities that
// specify an architecture, rather than also those that apply to all architectures, leaving c unchanged.
func (c *ArchitectureCriteria) WithRequired(required bool) *ArchitectureCriteria {
	out := *c
	out.required = required
	return &out
}

func (c *ArchitectureCriteria) MatchesVulnerability(v vulnerability.Vulnerability) (bool, string, error) {
	if c.required && v.Arch == "" {
		return false, fmt.Sprintf("vulnerability does not specify an architecture, which is required for package architecture %q", c.Arch), nil
	}
	if architecture.Matches(c.Arch, v.Arch, c.aliases) {
		return true, "", nil
	}
	return false, fmt.Sprintf("vulnerability architecture %q does not apply to package architecture %q", v.Arch, c.Arch), nil
}

func (c *ArchitectureCriteria) Summarize() string {
	return fmt.Sprintf("does not match architecture %q", c.Arch)
}

var _ interface {
	vulnerability.Criteria
} = (*ArchitectureCriteria)(nil)
