package os // nolint:revive

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/versionutil"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	transformers2 "github.com/anchore/grype/grype/db/v5/build/internal/transformers"
	"github.com/anchore/grype/grype/db/v5/namespace"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier/rpmmodularity"
	"github.com/anchore/grype/grype/distro"
)

func buildGrypeNamespace(group string) (namespace.Namespace, error) {
	feedGroupComponents := strings.Split(group, ":")

	if len(feedGroupComponents) < 2 {
		return nil, fmt.Errorf("unable to determine grype namespace for enterprise namespace=%s", group)
	}

	// Currently known enterprise feed groups are expected to be of the form {distroID}:{version}
	feedGroupDistroID := feedGroupComponents[0]
	d, ok := distro.IDMapping[feedGroupDistroID]
	if !ok {
		return nil, fmt.Errorf("unable to determine grype namespace for enterprise namespace=%s", group)
	}

	providerName := d.String()
	distroName := d.String()
	ver := feedGroupComponents[1]

	switch d {
	case distro.OracleLinux:
		providerName = "oracle"
	case distro.AmazonLinux:
		providerName = "amazon"
	case distro.Mariner, distro.Azure:
		providerName = "mariner"
		if strings.HasPrefix(ver, "3") {
			distroName = distro.Azure.String() // Mariner Linux 3 is known as "Azure Linux 3"
		}
	}

	// distro channels are not supported in the grype v5 schema, so the records should be dropped entirely
	if strings.Contains(ver, "+") {
		return nil, nil
	}

	ns, err := namespace.FromString(fmt.Sprintf("%s:distro:%s:%s", providerName, distroName, ver))
	if err != nil {
		return nil, err
	}

	return ns, nil
}

func buildPackageQualifiers(fixedInEntry unmarshal.OSFixedIn) (qualifiers []qualifier.Qualifier) {
	if fixedInEntry.VersionFormat == "rpm" {
		module := ""
		if fixedInEntry.Module != nil {
			module = *fixedInEntry.Module
		}

		qualifiers = []qualifier.Qualifier{rpmmodularity.Qualifier{
			Kind:   "rpm-modularity",
			Module: module,
		}}
	}

	return qualifiers
}

func Transform(vulnerability unmarshal.OSVulnerability) ([]data.Entry, error) {
	var allVulns []grypeDB.Vulnerability

	// TODO: stop capturing record source in the vulnerability metadata record (now that feed groups are not real)
	recordSource := fmt.Sprintf("vulnerabilities:%s", vulnerability.Vulnerability.NamespaceName)

	grypeNamespace, err := buildGrypeNamespace(vulnerability.Vulnerability.NamespaceName)
	if err != nil {
		return nil, err
	}
	if grypeNamespace == nil {
		// this is an enterprise feed group that does not have a corresponding grype namespace, so skip it
		return nil, nil
	}

	entryNamespace := grypeNamespace.String()

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespace combo) while merging
	// constraint ranges as they are found.
	for idx, fixedInEntry := range vulnerability.Vulnerability.FixedIn {
		// create vulnerability entry
		allVulns = append(allVulns, grypeDB.Vulnerability{
			ID:                     vulnerability.Vulnerability.Name,
			PackageQualifiers:      buildPackageQualifiers(fixedInEntry),
			VersionConstraint:      enforceConstraint(fixedInEntry.Version, fixedInEntry.VulnerableRange, fixedInEntry.VersionFormat, vulnerability.Vulnerability.Name),
			VersionFormat:          fixedInEntry.VersionFormat,
			PackageName:            grypeNamespace.Resolver().Normalize(fixedInEntry.Name),
			Namespace:              entryNamespace,
			RelatedVulnerabilities: getRelatedVulnerabilities(vulnerability),
			Fix:                    getFix(vulnerability, idx),
			Advisories:             getAdvisories(vulnerability, idx),
		})
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := grypeDB.VulnerabilityMetadata{
		ID:           vulnerability.Vulnerability.Name,
		Namespace:    entryNamespace,
		DataSource:   vulnerability.Vulnerability.Link,
		RecordSource: recordSource,
		Severity:     vulnerability.Vulnerability.Severity,
		URLs:         getLinks(vulnerability),
		Description:  vulnerability.Vulnerability.Description,
		Cvss:         getCvss(vulnerability),
	}

	return transformers2.NewEntries(allVulns, metadata), nil
}

func getLinks(entry unmarshal.OSVulnerability) []string {
	// find all URLs related to the vulnerability
	links := []string{entry.Vulnerability.Link}
	if entry.Vulnerability.Metadata.CVE != nil {
		for _, cve := range entry.Vulnerability.Metadata.CVE {
			if cve.Link != "" {
				links = append(links, cve.Link)
			}
		}
	}
	return links
}

func getCvss(entry unmarshal.OSVulnerability) (cvss []grypeDB.Cvss) {
	for _, vendorCvss := range entry.Vulnerability.CVSS {
		cvss = append(cvss, grypeDB.Cvss{
			Version: vendorCvss.Version,
			Vector:  vendorCvss.VectorString,
			Metrics: grypeDB.NewCvssMetrics(
				vendorCvss.BaseMetrics.BaseScore,
				vendorCvss.BaseMetrics.ExploitabilityScore,
				vendorCvss.BaseMetrics.ImpactScore,
			),
			VendorMetadata: transformers2.VendorBaseMetrics{
				BaseSeverity: vendorCvss.BaseMetrics.BaseSeverity,
				Status:       vendorCvss.Status,
			},
		})
	}
	return cvss
}

func getAdvisories(entry unmarshal.OSVulnerability, idx int) (advisories []grypeDB.Advisory) {
	fixedInEntry := entry.Vulnerability.FixedIn[idx]

	for _, advisory := range fixedInEntry.VendorAdvisory.AdvisorySummary {
		advisories = append(advisories, grypeDB.Advisory{
			ID:   advisory.ID,
			Link: advisory.Link,
		})
	}
	return advisories
}

func getFix(entry unmarshal.OSVulnerability, idx int) grypeDB.Fix {
	fixedInEntry := entry.Vulnerability.FixedIn[idx]

	var fixedInVersions []string
	fixedInVersion := versionutil.CleanFixedInVersion(fixedInEntry.Version)
	if fixedInVersion != "" {
		fixedInVersions = append(fixedInVersions, fixedInVersion)
	}

	fixState := grypeDB.NotFixedState
	if len(fixedInVersions) > 0 {
		fixState = grypeDB.FixedState
	} else if fixedInEntry.VendorAdvisory.NoAdvisory {
		fixState = grypeDB.WontFixState
	}

	return grypeDB.Fix{
		Versions: fixedInVersions,
		State:    fixState,
	}
}

func getRelatedVulnerabilities(entry unmarshal.OSVulnerability) (vulns []grypeDB.VulnerabilityReference) {
	// associate related vulnerabilities from the NVD namespace
	if strings.HasPrefix(entry.Vulnerability.Name, "CVE") {
		vulns = append(vulns, grypeDB.VulnerabilityReference{
			ID:        entry.Vulnerability.Name,
			Namespace: "nvd:cpe",
		})
	}

	// note: an example of multiple CVEs for a record is centos:5 RHSA-2007:0055 which maps to CVE-2007-0002 and CVE-2007-1466
	for _, ref := range entry.Vulnerability.Metadata.CVE {
		vulns = append(vulns, grypeDB.VulnerabilityReference{
			ID:        ref.Name,
			Namespace: "nvd:cpe",
		})
	}
	return vulns
}

func deriveConstraintFromFix(fixVersion, vulnerabilityID string) string {
	constraint := fmt.Sprintf("< %s", fixVersion)

	if strings.HasPrefix(vulnerabilityID, "ALASKERNEL-") {
		// Amazon advisories of the form ALASKERNEL-5.4-2023-048 should be interpreted as only applying to
		// the 5.4.x kernel line since Amazon issue a separate advisory per affected line, thus the constraint
		// should be >= 5.4, < {fix version}.  In the future the vunnel schema for OS vulns should be enhanced
		// to emit actual constraints rather than fixed-in entries (tracked in https://github.com/anchore/vunnel/issues/266)
		// at which point this workaround in grype-db can be removed.

		components := strings.Split(vulnerabilityID, "-")

		if len(components) == 4 {
			base := components[1]
			constraint = fmt.Sprintf(">= %s, < %s", base, fixVersion)
		}
	}

	return constraint
}

func enforceConstraint(fixedVersion, vulnerableRange, format, vulnerabilityID string) string {
	if len(vulnerableRange) > 0 {
		return vulnerableRange
	}
	fixedVersion = versionutil.CleanConstraint(fixedVersion)
	if len(fixedVersion) == 0 {
		return ""
	}
	switch strings.ToLower(format) {
	case "semver":
		return versionutil.EnforceSemVerConstraint(fixedVersion)
	default:
		// the passed constraint is a fixed version
		return deriveConstraintFromFix(fixedVersion, vulnerabilityID)
	}
}
