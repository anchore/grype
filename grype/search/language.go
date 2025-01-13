package search

import (
	"github.com/anchore/grype/grype/db/v5/namespace"
	"github.com/anchore/grype/grype/db/v5/namespace/language"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// ByLanguage returns criteria which will search based on the package Language
func ByLanguage(lang syftPkg.Language) vulnerability.Criteria {
	return &LanguageCriteria{
		Language: lang,
	}
}

type LanguageCriteria struct {
	Language syftPkg.Language
}

// func (c *LanguageCriteria) PackageSpecifier(specifier *PackageSpecifier) error {
//	specifier.Type = string(v.Language)
//	return nil
//}

func (c *LanguageCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, error) {
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
}

var _ interface {
	vulnerability.Criteria
	// queryPackageSpecifier
} = (*LanguageCriteria)(nil)
