package search

import (
	"fmt"

	"github.com/anchore/grype/grype/internal/architecture"
	"github.com/anchore/grype/grype/vulnerability"
)

// ByArchitecture returns criteria which will match vulnerabilities that apply to a package of the
// given architecture. An unset architecture on either side matches anything (unless required, see
// WithRequired), except that an unaffected vulnerability scoped to an architecture does not match a
// package without one: unaffected vulnerabilities suppress matches, so they only apply where the
// architecture is known. Case is normalized. Other spelling differences (deb "source" vs "src",
// "x86_64" vs "amd64") are folded through the built-in default aliases, or through the table given to
// WithAliases, which the v6 vulnerability provider uses to apply its DB's alias table.
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

// reasons ArchitectureCriteria does not match a vulnerability
const (
	archRequiredReason          = "architecture required"
	archUnaffectedUnknownReason = "unknown package architecture"
	archMismatchReason          = "architecture mismatch"
)

func (c *ArchitectureCriteria) MatchesVulnerability(v vulnerability.Vulnerability) (bool, string, error) {
	if c.required && v.Arch == "" {
		return false, archRequiredReason, nil
	}
	if v.Unaffected && c.Arch == "" && v.Arch != "" {
		return false, archUnaffectedUnknownReason, nil
	}
	if architecture.Matches(c.Arch, v.Arch, c.aliases) {
		return true, "", nil
	}
	return false, archMismatchReason, nil
}

func (c *ArchitectureCriteria) Summarize() string {
	return fmt.Sprintf("does not match architecture %q", c.Arch)
}

var _ interface {
	vulnerability.Criteria
} = (*ArchitectureCriteria)(nil)
