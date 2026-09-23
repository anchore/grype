package os // nolint:revive

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/versionutil"
	db "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/build/transformers"
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

	// secureos and photon are not supported in the grype v5 schema, so the records should be dropped entirely
	if feedGroupDistroID == "secureos" || feedGroupDistroID == "photon" {
		return nil, nil
	}

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
	var allVulns []db.Vulnerability

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
		allVulns = append(allVulns, db.Vulnerability{
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
	metadata := db.VulnerabilityMetadata{
		ID:           vulnerability.Vulnerability.Name,
		Namespace:    entryNamespace,
		DataSource:   vulnerability.Vulnerability.Link,
		RecordSource: recordSource,
		Severity:     vulnerability.Vulnerability.Severity,
		URLs:         getLinks(vulnerability),
		Description:  vulnerability.Vulnerability.Description,
		Cvss:         getCvss(vulnerability),
	}

	return transformers.NewEntries(allVulns, metadata), nil
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

func getCvss(entry unmarshal.OSVulnerability) (cvss []db.Cvss) {
	for _, vendorCvss := range entry.Vulnerability.CVSS {
		cvss = append(cvss, db.Cvss{
			Version: vendorCvss.Version,
			Vector:  vendorCvss.VectorString,
			Metrics: db.NewCvssMetrics(
				vendorCvss.BaseMetrics.BaseScore,
				vendorCvss.BaseMetrics.ExploitabilityScore,
				vendorCvss.BaseMetrics.ImpactScore,
			),
			VendorMetadata: transformers.VendorBaseMetrics{
				BaseSeverity: vendorCvss.BaseMetrics.BaseSeverity,
				Status:       vendorCvss.Status,
			},
		})
	}
	return cvss
}

func getAdvisories(entry unmarshal.OSVulnerability, idx int) (advisories []db.Advisory) {
	fixedInEntry := entry.Vulnerability.FixedIn[idx]

	for _, advisory := range fixedInEntry.VendorAdvisory.AdvisorySummary {
		advisories = append(advisories, db.Advisory{
			ID:   advisory.ID,
			Link: advisory.Link,
		})
	}
	return advisories
}

func getFix(entry unmarshal.OSVulnerability, idx int) db.Fix {
	fixedInEntry := entry.Vulnerability.FixedIn[idx]

	var fixedInVersions []string
	fixedInVersion := versionutil.CleanFixedInVersion(fixedInEntry.Version)
	if fixedInVersion != "" {
		fixedInVersions = append(fixedInVersions, fixedInVersion)
	}

	fixState := db.NotFixedState
	if len(fixedInVersions) > 0 {
		fixState = db.FixedState
	} else if fixedInEntry.VendorAdvisory.NoAdvisory {
		fixState = db.WontFixState
	}

	return db.Fix{
		Versions: fixedInVersions,
		State:    fixState,
	}
}

func getRelatedVulnerabilities(entry unmarshal.OSVulnerability) (vulns []db.VulnerabilityReference) {
	// associate related vulnerabilities from the NVD namespace
	if strings.HasPrefix(entry.Vulnerability.Name, "CVE") {
		vulns = append(vulns, db.VulnerabilityReference{
			ID:        entry.Vulnerability.Name,
			Namespace: "nvd:cpe",
		})
	}

	// note: an example of multiple CVEs for a record is centos:5 RHSA-2007:0055 which maps to CVE-2007-0002 and CVE-2007-1466
	for _, ref := range entry.Vulnerability.Metadata.CVE {
		vulns = append(vulns, db.VulnerabilityReference{
			ID:        ref.Name,
			Namespace: "nvd:cpe",
		})
	}
	return vulns
}

// amazonKernelAdvisoryID matches Amazon's per-kernel-line advisory ids and captures the line: the
// original ALASKERNEL-5.4-2023-048 form and the current ALAS2KERNEL-5.10-2026-123 form.
var amazonKernelAdvisoryID = regexp.MustCompile(`^ALAS2?KERNEL-(\d+\.\d+)-\d+-\d+$`)

func deriveConstraintFromFix(fixVersion, vulnerabilityID string) string {
	constraint := fmt.Sprintf("< %s", fixVersion)

	// Amazon Linux 2 ships several kernel lines (4.14, 5.4, 5.10, 5.15) under the same package names
	// and issues a separate advisory per line, so an ALAS2KERNEL-5.15-* fix must only apply to the
	// 5.15.x line: without a lower bound a 5.10 kernel satisfies "< 5.15.209" and picks up every 5.15
	// advisory. The lower bound is only added when the fix version itself is in the advisory's line,
	// since the same advisory also ships packages that do not track it (kernel-livepatch-* is
	// versioned 1.0-x) and ">= 5.10, < 1.0-0" would match nothing. In the future the vunnel schema for
	// OS vulns should be enhanced to emit actual constraints rather than fixed-in entries (tracked in
	// https://github.com/anchore/vunnel/issues/266) at which point this workaround can be removed.
	if m := amazonKernelAdvisoryID.FindStringSubmatch(vulnerabilityID); m != nil {
		kernelLine := m[1]

		if strings.HasPrefix(stripRpmEpoch(fixVersion), kernelLine+".") {
			constraint = fmt.Sprintf(">= %s, < %s", kernelLine, fixVersion)
		}
	}

	return constraint
}

// stripRpmEpoch drops a leading "<epoch>:" from an rpm version string.
func stripRpmEpoch(version string) string {
	if i := strings.Index(version, ":"); i > 0 {
		if _, err := strconv.Atoi(version[:i]); err == nil {
			return version[i+1:]
		}
	}
	return version
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
