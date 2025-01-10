package v5

import (
	"strings"

	"github.com/anchore/grype/grype/db/v5/namespace"
	distroNs "github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/db/v5/namespace/language"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type criteria struct {
	Distro      *distro.Distro
	Language    *syftPkg.Language
	CPE         *cpe.CPE
	PackageName string
	ID          string
	Namespace   string
}

func (c *criteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, error) {
	if c.ID != "" && c.ID != value.ID {
		return false, nil
	}
	if c.Namespace != "" && c.Namespace != value.Namespace {
		return false, nil
	}
	if c.Distro != nil {
		ns, err := namespace.FromString(value.Namespace)
		if err != nil {
			log.Debugf("unable to determine namespace for vulnerability %v: %v", value.Reference.ID, err)
			return false, nil
		}
		d, ok := ns.(*distroNs.Namespace)
		if !ok || d == nil {
			// not a distro-based vulnerability
			return false, nil
		}
		return matchesDistro(c.Distro, d), nil
	}
	if c.Language != nil {
		ns, err := namespace.FromString(value.Namespace)
		if err != nil {
			log.Debugf("unable to determine namespace for vulnerability %v: %v", value.Reference.ID, err)
			return false, nil
		}
		lang, ok := ns.(*language.Namespace)
		if !ok || lang == nil {
			// not a language-based vulnerability
			return false, nil
		}
		return *c.Language == lang.Language(), nil
	}
	if c.CPE != nil {
		matchesCPE := false
		for _, cp := range value.CPEs {
			if matchesAttributes(c.CPE.Attributes, cp.Attributes) {
				matchesCPE = true
				break
			}
		}
		if !matchesCPE {
			return false, nil
		}
	}
	if c.PackageName != "" && c.PackageName != value.PackageName {
		return false, nil
	}
	return true, nil
}

// matchesDistro returns true distro types are equal and versions are compatible
func matchesDistro(d *distro.Distro, ns *distroNs.Namespace) bool {
	if d == nil || ns == nil {
		return false
	}
	if d.Type != ns.DistroType() {
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

func matchesAttributes(a1 cpe.Attributes, a2 cpe.Attributes) bool {
	if !matchesAttribute(a1.Product, a2.Product) ||
		!matchesAttribute(a1.Vendor, a2.Vendor) ||
		!matchesAttribute(a1.Part, a2.Part) ||
		!matchesAttribute(a1.Language, a2.Language) ||
		!matchesAttribute(a1.SWEdition, a2.SWEdition) ||
		!matchesAttribute(a1.TargetSW, a2.TargetSW) ||
		!matchesAttribute(a1.TargetHW, a2.TargetHW) ||
		!matchesAttribute(a1.Other, a2.Other) ||
		!matchesAttribute(a1.Edition, a2.Edition) {
		return false
	}
	return true
}

func matchesAttribute(a1, a2 string) bool {
	return a1 == "" || a2 == "" || strings.EqualFold(a1, a2)
}

func NewPackageNameCriteria(name string) vulnerability.Criteria {
	return &criteria{
		PackageName: name,
	}
}

func NewPackageLanguageCriteria(language syftPkg.Language) vulnerability.Criteria {
	return &criteria{
		Language: &language,
	}
}

func NewDistroCriteria(d distro.Distro) vulnerability.Criteria {
	return &criteria{
		Distro: &d,
	}
}

func NewCPECriteria(c cpe.CPE) vulnerability.Criteria {
	return &criteria{
		CPE: &c,
	}
}

func NewIDCriteria(id string) vulnerability.Criteria {
	return &criteria{
		ID: id,
	}
}
