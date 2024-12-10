package v6

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/cpe"
)

func CPECriteria(p pkg.Package, c cpe.CPE) VulnerabilityCriteria {
	return VulnerabilityCriteria{
		p:   p,
		cpe: &c,
	}
}

func LanguageCriteria(p pkg.Package) VulnerabilityCriteria {
	return VulnerabilityCriteria{
		p:        p,
		language: &p.Language,
	}
}

func DistroCriteria(p pkg.Package, d *distro.Distro) VulnerabilityCriteria {
	return VulnerabilityCriteria{
		p:      p,
		distro: d,
	}
}

func NameCriteria(name string) VulnerabilityCriteria {
	return VulnerabilityCriteria{
		id: name,
	}
}
