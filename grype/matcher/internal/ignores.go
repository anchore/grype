package internal

import (
	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/artifact"
)

func OwnershipIgnores(p pkg.Package, reason string, ignoredVulnerabilities ...vulnerability.Vulnerability) []match.IgnoreFilter {
	var ignores []match.IgnoreFilter

	// the same vulnerability can reach here from more than one source record (e.g. an
	// exact-match unaffected handle plus the affected record it overrides), which would
	// otherwise emit duplicate, identical ignore filters.
	seen := make(map[string]struct{})

	for _, ignoredVulnerability := range ignoredVulnerabilities {
		for _, ignoreVulnID := range collectVulnerabilityIDs(ignoredVulnerability) {
			if _, ok := seen[ignoreVulnID]; ok {
				continue
			}
			seen[ignoreVulnID] = struct{}{}
			ignores = append(ignores, match.IgnoreRelatedPackage{
				Reason:           reason,
				RelationshipType: artifact.OwnershipByFileOverlapRelationship,
				VulnerabilityID:  ignoreVulnID,
				RelatedPackageID: p.ID,
			})
		}
	}

	return ignores
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
