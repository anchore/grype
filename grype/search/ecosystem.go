package search

import (
	"github.com/anchore/grype/grype/db/v5/namespace"
	"github.com/anchore/grype/grype/db/v5/namespace/language"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// ByEcosystem returns criteria which will search based on the package Language and or package type
func ByEcosystem(lang syftPkg.Language, t syftPkg.Type) vulnerability.Criteria {
	return &EcosystemCriteria{
		Language:    lang,
		PackageType: t,
	}
}

type EcosystemCriteria struct {
	Language    syftPkg.Language
	PackageType syftPkg.Type
}

func (c *EcosystemCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, error) {
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
	return c.Language == lang.Language(), nil

	// TODO: add package type?
}

var _ interface {
	vulnerability.Criteria
} = (*EcosystemCriteria)(nil)
