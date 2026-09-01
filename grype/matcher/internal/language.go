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

	// Gather every applicable record across every name the provider claims for p, then split once.
	// Splitting per name would silo a NAK keyed under one name (e.g. `rootio-foo`) away from a
	// disclosure keyed under another (`foo`).
	applicable := result.Set{}
	for _, name := range store.PackageSearchNames(p) {
		found, err := provider.FindAll(
			search.ByEcosystem(p.Language, p.Type),
			search.ByPackageName(name),
			OnlyQualifiedPackages(p),
			OnlyNonWithdrawnVulnerabilities(),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch disclosure language=%q pkg=%q: %w", p.Language, name, err)
		}
		applicable = applicable.Merge(found)
	}

	disclosures, notVulnerable := applicable.SplitVulnerable(pkgVersion)

	// Only the naks become ignore rules: a nak states this package is not affected at all, while
	// everything else the split set aside is only saying this version is not the vulnerable one --
	// too weak to suppress the same vulnerability on another package by name and version.
	return disclosures.ToMatches(), constructIgnoreFilters(naks(notVulnerable), p), nil
}

// naks narrows a not-vulnerable set to the provider's explicit unaffected records.
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

	// TODO: previous impl set confidence to 1, this results in
	// a confidence of zero. What should it be?
	applicable, err := provider.FindAll(
		search.ByEcosystem(p.Language, p.Type),
		search.ByPackageName(packageName),
		OnlyQualifiedPackages(p),
		OnlyNonWithdrawnVulnerabilities(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch disclosure language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	disclosures, notVulnerable := applicable.SplitVulnerable(pkgVersion)

	// only the explicit naks become ignore rules -- see MatchPackageByLanguage
	return disclosures.ToMatches(), constructIgnoreFilters(naks(notVulnerable), p), nil
}

func constructIgnoreFilters(unaffectedVulns result.Set, p pkg.Package) []match.IgnoreFilter {
	var ignores []match.IgnoreFilter

	// collect all IDs to exclude. One entry routinely holds several records for the same
	// vulnerability -- one per affected version window the advisory names -- and each says the same
	// thing about which IDs to ignore, so the IDs are deduped rather than the rules repeated.
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
