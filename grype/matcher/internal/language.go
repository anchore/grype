package internal

import (
	"fmt"
	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackageByLanguage(store vulnerability.Provider, p pkg.Package, matcherType match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	provider := result.NewProvider(store, p, matcherType)
	pkgVersion := version.New(p.Version, pkg.VersionFormat(p))

	// split once across names so a NAK under `rootio-foo` denies a disclosure under `foo`
	applicable := result.Set{}
	for _, name := range store.PackageSearchNames(p) {
		searched := p
		searched.Name = name
		found, err := provider.FindAll(
			search.ByEcosystem(p.Language, p.Type),
			search.ByPackageName(name),
			OnlyQualifiedPackages(p),
			OnlyNonWithdrawnVulnerabilities(),
			search.WithPackage(searched),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch disclosure language=%q pkg=%q: %w", p.Language, name, err)
		}
		applicable = applicable.Merge(found)
	}

	disclosures, notVulnerable := SplitVulnerable(applicable, pkgVersion)

	// only NAKs become ignores: a fixed record speaks only for this version
	return disclosures.ToMatches(p), constructIgnoreFilters(naks(notVulnerable), p), nil
}

func naks(s result.Set) result.Set {
	return s.Filter(search.ForUnaffected())
}

func MatchPackageByEcosystemPackageName(vp vulnerability.Provider, p pkg.Package, packageName string, matcherType match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	provider := result.NewProvider(vp, p, matcherType)

	pkgVersion := version.New(p.Version, pkg.VersionFormat(p))

	searched := p
	searched.Name = packageName
	applicable, err := provider.FindAll(
		search.ByEcosystem(p.Language, p.Type),
		search.ByPackageName(packageName),
		OnlyQualifiedPackages(p),
		OnlyNonWithdrawnVulnerabilities(),
		search.WithPackage(searched),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch disclosure language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	disclosures, notVulnerable := SplitVulnerable(applicable, pkgVersion)

	return disclosures.ToMatches(p), constructIgnoreFilters(naks(notVulnerable), p), nil
}

func constructIgnoreFilters(unaffectedVulns result.Set, p pkg.Package) []match.IgnoreFilter {
	var ignores []match.IgnoreFilter

	var ids []string
	appendID := func(id string) {
		if id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	for _, vulnResults := range unaffectedVulns {
		for _, vulnResult := range vulnResults {
			appendID(vulnResult.ID)
			for _, vuln := range vulnResult.Vulnerabilities {
				appendID(vuln.ID)
				for _, id := range vuln.RelatedVulnerabilities {
					appendID(id.ID)
				}
			}
		}
	}

	// ignore rules for all IDs
	for _, id := range ids {
		ignores = append(ignores, match.IgnoreRule{
			Vulnerability:  id,
			IncludeAliases: true,
			Reason:         "UnaffectedPackageEntry",
			Package: match.IgnoreRulePackage{
				Type:    string(p.Type),
				Name:    p.Name,
				Version: p.Version,
			},
		})
	}
	return ignores
}
