package os

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/data/provider"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/db/data/unmarshal"
	"github.com/anchore/grype/internal/db/internal/codename"
	v6 "github.com/anchore/grype/internal/db/v6"
	"github.com/anchore/grype/internal/db/v6/data/transformers"
	"github.com/anchore/grype/internal/db/v6/data/transformers/internal"
	"github.com/anchore/grype/internal/db/v6/name"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

func Transform(vulnerability unmarshal.OSVulnerability, state provider.State) ([]data.Entry, error) {
	in := []any{
		v6.VulnerabilityHandle{
			Name:          vulnerability.Vulnerability.Name,
			ProviderID:    state.Provider,
			Provider:      internal.ProviderModel(state),
			Status:        v6.VulnerabilityActive,
			ModifiedDate:  internal.ParseTime(vulnerability.Vulnerability.Metadata.Updated),
			PublishedDate: internal.ParseTime(vulnerability.Vulnerability.Metadata.Issued),
			BlobValue: &v6.VulnerabilityBlob{
				ID:          vulnerability.Vulnerability.Name,
				Assigners:   nil,
				Description: strings.TrimSpace(vulnerability.Vulnerability.Description),
				References:  getReferences(vulnerability),
				Aliases:     getAliases(vulnerability),
				Severities:  getSeverities(vulnerability),
			},
		},
	}

	for _, a := range getAffectedPackages(vulnerability) {
		in = append(in, a)
	}

	return transformers.NewEntries(in...), nil
}

func getAffectedPackages(vuln unmarshal.OSVulnerability) []v6.AffectedPackageHandle {
	var afs []v6.AffectedPackageHandle
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {
		// we only care about a single qualifier: rpm modules. The important thing to note about this is that
		// a package with no module vs a package with a module should be detectable in the DB.
		var qualifiers *v6.AffectedPackageQualifiers
		if group.format == "rpm" {
			module := "" // means the target package must have no module (where as nil means the module has no sway on matching)
			if group.hasModule {
				module = group.module
			}
			qualifiers = &v6.AffectedPackageQualifiers{
				RpmModularity: &module,
			}
		}

		aph := v6.AffectedPackageHandle{
			OperatingSystem: getOperatingSystem(group.osName, group.id, group.osVersion, group.osChannel),
			Package:         getPackage(group),
			BlobValue: &v6.AffectedPackageBlob{
				CVEs:       getAliases(vuln),
				Qualifiers: qualifiers,
				Ranges:     nil,
			},
		}

		var ranges []v6.AffectedRange
		for _, fixedInEntry := range fixedIns {
			ranges = append(ranges, v6.AffectedRange{
				Version: v6.AffectedVersion{
					Type:       fixedInEntry.VersionFormat,
					Constraint: enforceConstraint(fixedInEntry.Version, fixedInEntry.VulnerableRange, fixedInEntry.VersionFormat, vuln.Vulnerability.Name),
				},
				Fix: getFix(fixedInEntry),
			})
		}
		aph.BlobValue.Ranges = ranges
		afs = append(afs, aph)
	}

	// stable ordering
	sort.Sort(internal.ByAffectedPackage(afs))

	return afs
}

func getFix(fixedInEntry unmarshal.OSFixedIn) *v6.Fix {
	fixedInVersion := internal.CleanFixedInVersion(fixedInEntry.Version)

	fixState := v6.NotFixedStatus
	if len(fixedInVersion) > 0 {
		fixState = v6.FixedStatus
	} else if fixedInEntry.VendorAdvisory.NoAdvisory {
		fixState = v6.WontFixStatus
	}

	var linkOrder []string
	linkSet := strset.New()
	for _, a := range fixedInEntry.VendorAdvisory.AdvisorySummary {
		if a.Link != "" && !linkSet.Has(a.Link) {
			linkOrder = append(linkOrder, a.Link)
			linkSet.Add(a.Link)
		}
	}

	var refs []v6.Reference
	for _, l := range linkOrder {
		refs = append(refs, v6.Reference{
			URL:  l,
			Tags: []string{v6.AdvisoryReferenceTag},
		})
	}

	var detail *v6.FixDetail
	if len(refs) > 0 {
		detail = &v6.FixDetail{
			References: refs,
		}
	}

	return &v6.Fix{
		Version: fixedInVersion,
		State:   fixState,
		Detail:  detail,
	}
}

func enforceConstraint(fixedVersion, vulnerableRange, format, vulnerabilityID string) string {
	if len(vulnerableRange) > 0 {
		return vulnerableRange
	}
	fixedVersion = internal.CleanConstraint(fixedVersion)
	if len(fixedVersion) == 0 {
		return ""
	}
	switch strings.ToLower(format) {
	case "semver":
		return internal.EnforceSemVerConstraint(fixedVersion)
	default:
		// the passed constraint is a fixed version
		return deriveConstraintFromFix(fixedVersion, vulnerabilityID)
	}
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

type groupIndex struct {
	name      string
	id        string
	osName    string
	osVersion string
	osChannel string
	hasModule bool
	module    string
	format    string
}

func groupFixedIns(vuln unmarshal.OSVulnerability) map[groupIndex][]unmarshal.OSFixedIn {
	grouped := make(map[groupIndex][]unmarshal.OSFixedIn)
	osName, osID, osVersion, osChannel := getOSInfo(vuln.Vulnerability.NamespaceName)

	for _, fixedIn := range vuln.Vulnerability.FixedIn {
		var mod string
		if fixedIn.Module != nil {
			mod = *fixedIn.Module
		}
		g := groupIndex{
			name:      fixedIn.Name,
			id:        osID,
			osName:    osName,
			osVersion: osVersion,
			osChannel: osChannel,
			hasModule: fixedIn.Module != nil,
			module:    mod,
			format:    fixedIn.VersionFormat,
		}

		grouped[g] = append(grouped[g], fixedIn)
	}
	return grouped
}

func getPackageType(osName string) pkg.Type {
	switch osName {
	case "redhat", "amazonlinux", "oraclelinux", "sles", "mariner", "azurelinux":
		return pkg.RpmPkg
	case "ubuntu", "debian", "echo":
		return pkg.DebPkg
	case "alpine", "chainguard", "wolfi", "minimos":
		return pkg.ApkPkg
	case "windows":
		return pkg.KbPkg
	}

	return ""
}

func getPackage(group groupIndex) *v6.Package {
	t := getPackageType(group.osName)
	return &v6.Package{
		Ecosystem: string(t),
		Name:      name.Normalize(group.name, t),
	}
}

func getOSInfo(group string) (string, string, string, string) {
	// derived from enterprise feed groups, expected to be of the form {distro release ID}:{version}
	feedGroupComponents := strings.Split(group, ":")

	id := feedGroupComponents[0]
	version := feedGroupComponents[1]
	channel := ""
	if strings.Contains(feedGroupComponents[1], "+") {
		versionParts := strings.Split(feedGroupComponents[1], "+")
		channel = versionParts[1]
		version = versionParts[0]
	}
	if strings.ToLower(id) == "mariner" {
		verFields := strings.Split(version, ".")
		majorVersionStr := verFields[0]
		majorVer, err := strconv.Atoi(majorVersionStr)
		if err == nil {
			if majorVer >= 3 {
				id = string(distro.Azure)
			}
		}
	}

	return normalizeOsName(id), id, version, channel
}

func normalizeOsName(id string) string {
	d, ok := distro.IDMapping[id]
	if !ok {
		log.WithFields("distro", id).Warn("unknown distro name")

		return id
	}

	return d.String()
}

func getOperatingSystem(osName, osID, osVersion, channel string) *v6.OperatingSystem {
	if osName == "" || osVersion == "" {
		return nil
	}

	versionFields := strings.Split(osVersion, ".")
	var majorVersion, minorVersion, labelVersion string
	majorVersion = versionFields[0]
	if len(majorVersion) > 0 {
		// is the first field a number?
		_, err := strconv.Atoi(majorVersion[0:1])
		if err != nil {
			labelVersion = majorVersion
			majorVersion = ""
		} else if len(versionFields) > 1 {
			minorVersion = versionFields[1]
		}
	}

	return &v6.OperatingSystem{
		Name:         osName,
		ReleaseID:    osID,
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		LabelVersion: labelVersion,
		Channel:      channel,
		Codename:     codename.LookupOS(osName, majorVersion, minorVersion),
	}
}

func getReferences(vuln unmarshal.OSVulnerability) []v6.Reference {
	clean := strings.TrimSpace(vuln.Vulnerability.Link)
	if clean == "" {
		return nil
	}

	var linkOrder []string
	linkSet := strset.New()
	if vuln.Vulnerability.Link != "" {
		linkSet.Add(vuln.Vulnerability.Link)
		linkOrder = append(linkOrder, vuln.Vulnerability.Link)
	}
	for _, a := range vuln.Vulnerability.Metadata.CVE {
		if a.Link != "" && !linkSet.Has(a.Link) {
			linkOrder = append(linkOrder, a.Link)
		}
	}

	var refs []v6.Reference
	for _, l := range linkOrder {
		refs = append(refs,
			v6.Reference{
				URL: l,
			},
		)
	}

	return refs
}

func getAliases(vuln unmarshal.OSVulnerability) []string {
	var aliases []string
	for _, cve := range vuln.Vulnerability.Metadata.CVE {
		aliases = append(aliases,
			cve.Name,
		)
	}
	return aliases
}

func getSeverities(vuln unmarshal.OSVulnerability) []v6.Severity {
	var severities []v6.Severity

	// TODO: should we clean this here or not?
	if vuln.Vulnerability.Severity != "" && strings.ToLower(vuln.Vulnerability.Severity) != "unknown" {
		severities = append(severities, v6.Severity{
			Scheme: v6.SeveritySchemeCHMLN,
			Value:  strings.ToLower(vuln.Vulnerability.Severity),
			Rank:   1, // TODO: enum this
			// TODO Source?
		})
	}
	for _, vendorSeverity := range vuln.Vulnerability.CVSS {
		severities = append(severities, v6.Severity{
			Scheme: v6.SeveritySchemeCVSS,
			Value: v6.CVSSSeverity{
				Vector:  vendorSeverity.VectorString,
				Version: vendorSeverity.Version,
			},
			Rank: 2,
			// TODO: source?
		})
	}

	return severities
}
