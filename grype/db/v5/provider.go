package v5

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type VulnerabilityProvider interface {
	Get(id, namespace string) ([]vulnerability.Vulnerability, error)
	ProviderByDistro
	ProviderByLanguage
	ProviderByCPE
}

type ProviderByDistro interface {
	GetByDistro(*distro.Distro, pkg.Package) ([]vulnerability.Vulnerability, error)
}

type ProviderByLanguage interface {
	GetByLanguage(syftPkg.Language, pkg.Package) ([]vulnerability.Vulnerability, error)
}

type ProviderByCPE interface {
	GetByCPE(cpe.CPE) ([]vulnerability.Vulnerability, error)
}

type VulnerabilityMetadataProvider interface {
	GetMetadata(id, namespace string) (*vulnerability.Metadata, error)
}
