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
	SearchedBy any         `json:"searchedBy"` // The specific attributes that were used to search (other than package name and version) --this indicates "how" the match was made.
	Found      any         `json:"found"`      // The specific attributes on the vulnerability object that were matched with --this indicates "what" was matched on / within.
	Fix        *FixDetails `json:"fix,omitempty"`
}

// FixDetails contains any data that is relevant to fixing the vulnerability specific to the package searched with
type FixDetails struct {
	SuggestedVersion string `json:"suggestedVersion"`
}

//nolint:staticcheck // MetadataProvider is deprecated but still used internally
func newMatch(m match.Match, p pkg.Package, metadataProvider vulnerability.MetadataProvider) (*Match, error) {
	relatedVulnerabilities := make([]VulnerabilityMetadata, 0)
	for _, r := range m.Vulnerability.RelatedVulnerabilities {
		relatedMetadata, err := metadataProvider.VulnerabilityMetadata(r) //nolint:staticcheck // deprecated API still used internally
		if err != nil {
			return nil, fmt.Errorf("unable to fetch related vuln=%q metadata: %+v", r, err)
		}
		if relatedMetadata != nil {
			relatedVulnerabilities = append(relatedVulnerabilities, NewVulnerabilityMetadata(r.ID, r.Namespace, relatedMetadata))
		}
	}

	// unmerged matches are in DB order
	sort.SliceStable(relatedVulnerabilities, func(i, j int) bool {
		if relatedVulnerabilities[i].Namespace != relatedVulnerabilities[j].Namespace {
			return relatedVulnerabilities[i].Namespace < relatedVulnerabilities[j].Namespace
		}
		return relatedVulnerabilities[i].ID < relatedVulnerabilities[j].ID
	})

	// vulnerability.Vulnerability should always have vulnerability.Metadata populated, however, in the case of test mocks
	// and other edge cases, it may not be populated. In these cases, we should fetch the metadata from the provider.
	metadata := m.Vulnerability.Metadata
	if metadata == nil {
		var err error
		metadata, err = metadataProvider.VulnerabilityMetadata(m.Vulnerability.Reference) //nolint:staticcheck // deprecated API still used internally
		if err != nil {
			return nil, fmt.Errorf("unable to fetch related vuln=%q metadata: %+v", m.Vulnerability.Reference, err)
		}
	}

	format := pkg.VersionFormat(p)

	reported := m.Vulnerability
	reported.Fix = upgradesFor(m.Vulnerability.Fix, p, format)

	details := make([]MatchDetails, len(m.Details))
	for idx, d := range m.Details {
		details[idx] = MatchDetails{
			Type:       string(d.Type),
			Matcher:    string(d.Matcher),
			SearchedBy: d.SearchedBy,
			Found:      d.Found,
			Fix:        getFix(reported, p, format),
		}
	}

	return &Match{
		Vulnerability:          NewVulnerability(reported, metadata, format),
		Artifact:               newPackage(p),
		RelatedVulnerabilities: relatedVulnerabilities,
		MatchDetails:           details,
	}, nil
}

func getFix(vuln vulnerability.Vulnerability, p pkg.Package, format version.Format) *FixDetails {
	suggested := calculateSuggestedFixedVersion(p, vuln.Fix.Versions, format)
	if suggested == "" {
		return nil
	}
	return &FixDetails{
		SuggestedVersion: suggested,
	}
}

// upgradesFor drops fix versions at or below the installed version, which a record's other affected
// ranges can contribute. Matchers need those versions to reconcile streams, so they are only dropped
// for reporting. A fix left with no versions is reported as not-fixed; incomparable versions are kept.
func upgradesFor(fix vulnerability.Fix, p pkg.Package, format version.Format) vulnerability.Fix {
	if len(fix.Versions) == 0 || p.Version == "" {
		return fix
	}

	installed := version.New(p.Version, format)
	if err := installed.Validate(); err != nil {
		log.WithFields("package", p.Name, "version", p.Version, "error", err).
			Trace("unable to parse package version; reporting all fix versions")
		return fix
	}

	kept := make([]string, 0, len(fix.Versions))
	keptSet := make(map[string]struct{}, len(fix.Versions))
	for _, raw := range fix.Versions {
		if isUpgrade(installed, raw, format, p.Name) {
			kept = append(kept, raw)
			keptSet[raw] = struct{}{}
		}
	}

	if len(kept) == len(fix.Versions) {
		return fix
	}

	out := vulnerability.Fix{Versions: kept, State: fix.State}
	for _, a := range fix.Available {
		if _, ok := keptSet[a.Version]; ok {
			out.Available = append(out.Available, a)
		}
	}
	if len(kept) == 0 && fix.State == vulnerability.FixStateFixed {
		out.State = vulnerability.FixStateNotFixed
	}
	return out
}

// isUpgrade treats an unparseable or incomparable fix version as an upgrade.
func isUpgrade(installed *version.Version, fixVersion string, format version.Format, pkgName string) bool {
	fixed := version.New(fixVersion, format)
	if err := fixed.Validate(); err != nil {
		log.WithFields("package", pkgName, "fixVersion", fixVersion, "error", err).
			Trace("unable to parse fix version; reporting it")
		return true
	}
	// installed is the receiver so its comparison config applies
	cmp, err := installed.Compare(fixed)
	if err != nil {
		log.WithFields("package", pkgName, "fixVersion", fixVersion, "error", err).
			Trace("unable to compare fix version to package version; reporting it")
		return true
	}
	return cmp < 0
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
		v1 := version.New(fixedVersions[i], format)
		v2 := version.New(fixedVersions[j], format)
		err1 := v1.Validate()
		err2 := v2.Validate()
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
