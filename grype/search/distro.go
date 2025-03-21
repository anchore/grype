package search

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/db/v5/namespace"
	distroNs "github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/vulnerability"
)

// ByDistro returns criteria which will match vulnerabilities based on any of the provided Distros
func ByDistro(d ...distro.Distro) vulnerability.Criteria {
	return &DistroCriteria{
		Distros: d,
	}
}

type DistroCriteria struct {
	Distros []distro.Distro
}

func (c *DistroCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, string, error) {
	ns, err := namespace.FromString(value.Namespace)
	if err != nil {
		return false, fmt.Sprintf("unable to determine namespace for vulnerability %v: %v", value.Reference.ID, err), nil
	}
	dns, ok := ns.(*distroNs.Namespace)
	if !ok || dns == nil {
		// not a Distro-based vulnerability
		return false, "not a distro-based vulnerability", nil
	}
	if len(c.Distros) == 0 {
		return true, "", nil
	}
	var distroStrs []string
	for _, d := range c.Distros {
		if matchesDistro(&d, dns) {
			return true, "", nil
		}
		distroStrs = append(distroStrs, d.String())
	}

	return false, fmt.Sprintf("does not match any known distro: %q", strings.Join(distroStrs, ", ")), nil
}

func (c *DistroCriteria) Summarize() string {
	var distroStrs []string
	for _, d := range c.Distros {
		distroStrs = append(distroStrs, d.String())
	}
	return "does not match distro(s): " + strings.Join(distroStrs, ", ")
}

var _ interface {
	vulnerability.Criteria
} = (*DistroCriteria)(nil)

// matchesDistro returns true distro types are equal and versions are compatible
func matchesDistro(d *distro.Distro, ns *distroNs.Namespace) bool {
	if d == nil || ns == nil {
		return false
	}

	distroType := ns.DistroType()
	if distroType != d.Type {
		return false
	}
	return compatibleVersion(d.Version, ns.Version())
}

// compatibleVersion returns true when the versions are the same or the partial version describes the matching parts
// of the fullVersion
func compatibleVersion(fullVersion string, partialVersion string) bool {
	if fullVersion == "" {
		return true
	}
	if fullVersion == partialVersion {
		return true
	}
	if strings.HasPrefix(fullVersion, partialVersion) && len(fullVersion) > len(partialVersion) && fullVersion[len(partialVersion)] == '.' {
		return true
	}
	return false
}
