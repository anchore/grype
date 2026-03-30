package internal

import (
	"fmt"
	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/artifact"
)

func OwnershipIgnores(p pkg.Package, reason string, ignoredVulnerabilities ...vulnerability.Vulnerability) []match.IgnoreFilter {
	var ignores []match.IgnoreFilter

	paths := ownedFilesFor(p)

	for _, ignoredVulnerability := range ignoredVulnerabilities {
		for _, ignoreVulnID := range collectVulnerabilityIDs(ignoredVulnerability) {
			for _, path := range paths {
				ignores = append(ignores,
					match.IgnoreRule{
						Vulnerability:  ignoreVulnID,
						IncludeAliases: true,
						Reason:         fmt.Sprintf("%s from package: %v", reason, p),
						Package: match.IgnoreRulePackage{
							Location: path,
						},
					},
				)
			}

			ignores = append(ignores, match.IgnoreRelatedPackage{
				Reason:           fmt.Sprintf("%s by Ownership from package: %v", reason, p),
				RelationshipType: artifact.OwnershipByFileOverlapRelationship,
				VulnerabilityID:  ignoreVulnID,
				RelatedPackageID: p.ID,
			})
		}
	}

	return ignores
}

// ownedFilesFor returns the files owned by the package if its metadata implements [pkg.FileOwner].
func ownedFilesFor(p pkg.Package) []string {
	if fo, ok := p.Metadata.(pkg.FileOwner); ok {
		return fo.OwnedFiles()
	}
	return nil
}

// collectVulnerabilityIDs returns the primary ID plus all related/alias IDs for a vulnerability.
func collectVulnerabilityIDs(v vulnerability.Vulnerability) []string {
	ids := make([]string, 1, len(v.RelatedVulnerabilities)+1)
	ids[0] = v.ID
	for _, related := range v.RelatedVulnerabilities {
		if !slices.Contains(ids, related.ID) {
			ids = append(ids, related.ID)
		}
	}
	return ids
}
