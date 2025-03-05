package search

import (
	"fmt"

	"github.com/anchore/grype/grype/db/v5/namespace"
	"github.com/anchore/grype/grype/db/v5/namespace/language"
	"github.com/anchore/grype/grype/vulnerability"
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

func (c *EcosystemCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, string, error) {
	ns, err := namespace.FromString(value.Namespace)
	if err != nil {
		return false, fmt.Sprintf("unable to determine namespace for vulnerability %v: %v", value.Reference.ID, err), nil
	}
	lang, ok := ns.(*language.Namespace)
	if !ok || lang == nil {
		// not a language-based vulnerability
		return false, "not a language-based vulnerability", nil
	}

	// TODO: add package type?

	vulnLanguage := lang.Language()
	matchesLanguage := c.Language == vulnLanguage
	if !matchesLanguage {
		return false, fmt.Sprintf("vulnerability language %q does not match package language %q", vulnLanguage, c.Language), nil
	}

	return true, "", nil
}

var _ interface {
	vulnerability.Criteria
} = (*EcosystemCriteria)(nil)
