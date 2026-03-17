package os // nolint:revive

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/codename"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/versionutil"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// advisoryKey is an internal struct used for sorting and deduplicating advisories
// that have both a link and ID from the vunnel results data
type advisoryKey struct {
	id   string
	link string
}

func Transform(vulnerability unmarshal.OSVulnerability, state provider.State) ([]data.Entry, error) {
	in := []any{
		db.VulnerabilityHandle{
			Name:          vulnerability.Vulnerability.Name,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			Status:        db.VulnerabilityActive,
			ModifiedDate:  internal.ParseTime(vulnerability.Vulnerability.Metadata.Updated),
			PublishedDate: internal.ParseTime(vulnerability.Vulnerability.Metadata.Issued),
			BlobValue: &db.VulnerabilityBlob{
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

func getAffectedPackages(vuln unmarshal.OSVulnerability) []db.AffectedPackageHandle {
	var afs []db.AffectedPackageHandle
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {
		// we only care about a single qualifier: rpm modules. The important thing to note about this is that
		// a package with no module vs a package with a module should be detectable in the DB.
		var qualifiers *db.PackageQualifiers
		if group.format == "rpm" {
			module := "" // means the target package must have no module (where as nil means the module has no sway on matching)
			if group.hasModule {
				module = group.module
			}
			qualifiers = &db.PackageQualifiers{
				RpmModularity: &module,
			}
		}

		aph := db.AffectedPackageHandle{
			OperatingSystem: getOperatingSystem(group.osName, group.id, group.osVersion, group.osChannel),
			Package:         getPackage(group),
			BlobValue: &db.PackageBlob{
				CVEs:       getAliases(vuln),
				Qualifiers: qualifiers,
				Ranges:     nil,
			},
		}

		var ranges []db.Range
		for _, fixedInEntry := range fixedIns {
			ranges = append(ranges, db.Range{
				Version: db.Version{
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

func getFix(fixedInEntry unmarshal.OSFixedIn) *db.Fix {
	fixedInVersion := versionutil.CleanFixedInVersion(fixedInEntry.Version)

	fixState := db.NotFixedStatus
	if len(fixedInVersion) > 0 {
		fixState = db.FixedStatus
	} else if fixedInEntry.VendorAdvisory.NoAdvisory {
		fixState = db.WontFixStatus
	}

	var advisoryOrder []advisoryKey
	advisorySet := strset.New()
	for _, a := range fixedInEntry.VendorAdvisory.AdvisorySummary {
		if a.Link != "" && !advisorySet.Has(a.Link) {
			advisoryOrder = append(advisoryOrder, advisoryKey{id: a.ID, link: a.Link})
			advisorySet.Add(a.Link)
		}
	}

	var refs []db.Reference
	for _, adv := range advisoryOrder {
		refs = append(refs, db.Reference{
			ID:   adv.id,
			URL:  adv.link,
			Tags: []string{db.AdvisoryReferenceTag},
		})
	}

	var detail *db.FixDetail
	availability := getFixAvailability(fixedInEntry)
	if len(refs) > 0 || availability != nil {
		detail = &db.FixDetail{
			Available:  availability,
			References: refs,
		}
	}

	return &db.Fix{
		Version: fixedInVersion,
		State:   fixState,
		Detail:  detail,
	}
}

func getFixAvailability(fixedInEntry unmarshal.OSFixedIn) *db.FixAvailability {
	if fixedInEntry.Available.Date == "" {
		return nil
	}

	t := internal.ParseTime(fixedInEntry.Available.Date)
	if t == nil {
		log.WithFields("date", fixedInEntry.Available.Date).Warn("unable to parse fix availability date")
		return nil
	}

	return &db.FixAvailability{
		Date: t,
		Kind: fixedInEntry.Available.Kind,
	}
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
	oi := getOSInfo(vuln.Vulnerability.NamespaceName)

	for _, fixedIn := range vuln.Vulnerability.FixedIn {
		var mod string
		if fixedIn.Module != nil {
			mod = *fixedIn.Module
		}
		g := groupIndex{
			name:      fixedIn.Name,
			id:        oi.id,
			osName:    oi.name,
			osVersion: oi.version,
			osChannel: oi.channel,
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
	case "redhat", "amazonlinux", "oraclelinux", "sles", "mariner", "azurelinux", "photon", "fedora", "rocky", "rockylinux", "almalinux", "centos":
		return pkg.RpmPkg
	case "ubuntu", "debian", "echo":
		return pkg.DebPkg
	case "alpine", "chainguard", "wolfi", "minimos", "secureos":
		return pkg.ApkPkg
	case "windows":
		return pkg.KbPkg
	}

	return ""
}

func getPackage(group groupIndex) *db.Package {
	t := getPackageType(group.osName)
	return &db.Package{
		Ecosystem: string(t),
		Name:      name.Normalize(group.name, t),
	}
}

type osInfo struct {
	name    string
	id      string
	version string
	channel string
}

func getOSInfo(group string) osInfo {
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

	return osInfo{
		name:    normalizeOsName(id),
		id:      id,
		version: version,
		channel: channel,
	}
}

func normalizeOsName(id string) string {
	d, ok := distro.IDMapping[id]
	if !ok {
		log.WithFields("distro", id).Warn("unknown distro name")

		return id
	}

	return d.String()
}

func getOperatingSystem(osName, osID, osVersion, channel string) *db.OperatingSystem {
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

	return &db.OperatingSystem{
		Name:         osName,
		ReleaseID:    osID,
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		LabelVersion: labelVersion,
		Channel:      channel,
		Codename:     codename.LookupOS(osName, majorVersion, minorVersion),
	}
}

func getReferences(vuln unmarshal.OSVulnerability) []db.Reference {
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

	var refs []db.Reference
	for _, l := range linkOrder {
		refs = append(refs,
			db.Reference{
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

func getSeverities(vuln unmarshal.OSVulnerability) []db.Severity {
	var severities []db.Severity

	// TODO: should we clean this here or not?
	if vuln.Vulnerability.Severity != "" && strings.ToLower(vuln.Vulnerability.Severity) != "unknown" {
		severities = append(severities, db.Severity{
			Scheme: db.SeveritySchemeCHMLN,
			Value:  strings.ToLower(vuln.Vulnerability.Severity),
			Rank:   1, // TODO: enum this
			// TODO Source?
		})
	}
	for _, vendorSeverity := range vuln.Vulnerability.CVSS {
		severities = append(severities, db.Severity{
			Scheme: db.SeveritySchemeCVSS,
			Value: db.CVSSSeverity{
				Vector:  vendorSeverity.VectorString,
				Version: vendorSeverity.Version,
			},
			Rank: 2,
			// TODO: source?
		})
	}

	return severities
}
