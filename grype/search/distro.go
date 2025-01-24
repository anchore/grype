package search

import (
	"strings"

	"github.com/anchore/grype/grype/db/v5/namespace"
	distroNs "github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
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

func (c *DistroCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, error) {
	ns, err := namespace.FromString(value.Namespace)
	if err != nil {
		log.Debugf("unable to determine namespace for vulnerability %v: %v", value.Reference.ID, err)
		return false, nil
	}
	dns, ok := ns.(*distroNs.Namespace)
	if !ok || dns == nil {
		// not a Distro-based vulnerability
		return false, nil
	}
	if len(c.Distros) == 0 {
		return true, nil
	}
	for _, d := range c.Distros {
		if matchesDistro(&d, dns) {
			return true, nil
		}
	}
	return false, nil
}

var _ interface {
	vulnerability.Criteria
	// queryOSSpecifier
} = (*DistroCriteria)(nil)

// matchesDistro returns true distro types are equal and versions are compatible
func matchesDistro(d *distro.Distro, ns *distroNs.Namespace) bool {
	if d == nil || ns == nil {
		return false
	}

	ty := namespace.DistroTypeString(d.Type)

	distroType := ns.DistroType()
	if distroType != d.Type && distroType != distro.Type(ty) {
		return false
	}
	return compatibleVersion(d.FullVersion(), ns.Version())
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
