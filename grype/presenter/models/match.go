package models

import (
	"fmt"
	"sort"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// Match is a single item for the JSON array reported
type Match struct {
	Vulnerability          Vulnerability           `json:"vulnerability"`
	RelatedVulnerabilities []VulnerabilityMetadata `json:"relatedVulnerabilities"`
	MatchDetails           []MatchDetails          `json:"matchDetails"`
	Artifact               Package                 `json:"artifact"`
}

// MatchDetails contains all data that indicates how the result match was found
type MatchDetails struct {
	Type       string      `json:"type"`
	Matcher    string      `json:"matcher"`
	SearchedBy interface{} `json:"searchedBy"` // The specific attributes that were used to search (other than package name and version) --this indicates "how" the match was made.
	Found      interface{} `json:"found"`      // The specific attributes on the vulnerability object that were matched with --this indicates "what" was matched on / within.
	Fix        *FixDetails `json:"fix,omitempty"`
}

// FixDetails contains any data that is relevant to fixing the vulnerability specific to the package searched with
type FixDetails struct {
	SuggestedVersion string `json:"suggestedVersion"`
}

func newMatch(m match.Match, p pkg.Package, metadataProvider vulnerability.MetadataProvider) (*Match, error) {
	relatedVulnerabilities := make([]VulnerabilityMetadata, 0)
	for _, r := range m.Vulnerability.RelatedVulnerabilities {
		relatedMetadata, err := metadataProvider.VulnerabilityMetadata(r)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch related vuln=%q metadata: %+v", r, err)
		}
		if relatedMetadata != nil {
			relatedVulnerabilities = append(relatedVulnerabilities, NewVulnerabilityMetadata(r.ID, r.Namespace, relatedMetadata))
		}
	}

	// vulnerability.Vulnerability should always have vulnerability.Metadata populated, however, in the case of test mocks
	// and other edge cases, it may not be populated. In these cases, we should fetch the metadata from the provider.
	metadata := m.Vulnerability.Metadata
	if metadata == nil {
		var err error
		metadata, err = metadataProvider.VulnerabilityMetadata(m.Vulnerability.Reference)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch related vuln=%q metadata: %+v", m.Vulnerability.Reference, err)
		}
	}

	format := version.FormatFromPkg(p)

	details := make([]MatchDetails, len(m.Details))
	for idx, d := range m.Details {
		details[idx] = MatchDetails{
			Type:       string(d.Type),
			Matcher:    string(d.Matcher),
			SearchedBy: d.SearchedBy,
			Found:      d.Found,
			Fix:        getFix(m, p, format),
		}
	}

	return &Match{
		Vulnerability:          NewVulnerability(m.Vulnerability, metadata, format),
		Artifact:               newPackage(p),
		RelatedVulnerabilities: relatedVulnerabilities,
		MatchDetails:           details,
	}, nil
}

func getFix(m match.Match, p pkg.Package, format version.Format) *FixDetails {
	suggested := calculateSuggestedFixedVersion(p, m.Vulnerability.Fix.Versions, format)
	if suggested == "" {
		return nil
	}
	return &FixDetails{
		SuggestedVersion: suggested,
	}
}

func calculateSuggestedFixedVersion(p pkg.Package, fixedVersions []string, format version.Format) string {
	if len(fixedVersions) == 0 {
		return ""
	}

	if len(fixedVersions) == 1 {
		return fixedVersions[0]
	}

	parseConstraint := func(constStr string) (version.Constraint, error) {
		constraint, err := version.GetConstraint(constStr, format)
		if err != nil {
			log.WithFields("package", p.Name).Trace("skipping sorting fixed versions")
		}
		return constraint, err
	}

	checkSatisfaction := func(constraint version.Constraint, v *version.Version) bool {
		satisfied, err := constraint.Satisfied(v)
		if err != nil {
			log.WithFields("package", p.Name).Trace("error while checking version satisfaction for sorting")
		}
		return satisfied && err == nil
	}

	sort.SliceStable(fixedVersions, func(i, j int) bool {
		v1, err1 := version.NewVersion(fixedVersions[i], format)
		v2, err2 := version.NewVersion(fixedVersions[j], format)
		if err1 != nil || err2 != nil {
			log.WithFields("package", p.Name).Trace("error while parsing version for sorting")
			return false
		}

		packageConstraint, err := parseConstraint(fmt.Sprintf("<=%s", p.Version))
		if err != nil {
			return false
		}

		v1Satisfied := checkSatisfaction(packageConstraint, v1)
		v2Satisfied := checkSatisfaction(packageConstraint, v2)

		if v1Satisfied != v2Satisfied {
			return !v1Satisfied
		}

		internalConstraint, err := parseConstraint(fmt.Sprintf("<=%s", v1.Raw))
		if err != nil {
			return false
		}
		return !checkSatisfaction(internalConstraint, v2)
	})

	return fixedVersions[0]
}
