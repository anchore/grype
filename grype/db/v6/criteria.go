package v6

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type vulnerabilityCriteria struct {
	p        pkg.Package
	cpe      *cpe.CPE
	language *syftPkg.Language
	distro   *distro.Distro
	id       string
}

func (v *vulnerabilityCriteria) MatchesVulnerability(_ vulnerability.Vulnerability) bool {
	return true
}

var _ vulnerability.Criteria = (*vulnerabilityCriteria)(nil)

func NewCPECriteria(c *cpe.CPE) vulnerability.Criteria {
	return &vulnerabilityCriteria{
		cpe: c,
	}
}

func NewLanguageCriteria(lang *syftPkg.Language) vulnerability.Criteria {
	return &vulnerabilityCriteria{
		language: lang,
	}
}

func NewDistroCriteria(d *distro.Distro) vulnerability.Criteria {
	return &vulnerabilityCriteria{
		distro: d,
	}
}

func NewIDCriteria(id string) vulnerability.Criteria {
	return &vulnerabilityCriteria{
		id: id,
	}
}

func NewPackageNameCriteria(name string) vulnerability.Criteria {
	return &vulnerabilityCriteria{
		p: pkg.Package{
			Name: name,
		},
	}
}
