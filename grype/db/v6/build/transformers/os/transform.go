package os // nolint:revive

import (
	"fmt"
	"regexp"
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
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// bareGARelease matches an RPM release suffix that is a bare GA .elN dist tag
// (e.g. ".el9") but NOT a z-stream/modular one (".el9_2", ".el9_2.3"). The negative
// lookahead is emulated below since Go's regexp lacks lookahead.
var bareGARelease = regexp.MustCompile(`\.el\d+($|[^_\d])`)

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

	affected, unaffected := getPackages(vulnerability)
	for _, a := range affected {
		in = append(in, a)
	}
	for _, u := range unaffected {
		in = append(in, u)
	}

	return transformers.NewEntries(in...), nil
}

func isNotAffectedGroup(fixedIns []unmarshal.OSFixedIn) bool {
	for _, f := range fixedIns {
		if versionutil.CleanFixedInVersion(f.Version) != "0" {
			return false
		}
	}
	return true
}

func getPackages(vuln unmarshal.OSVulnerability) ([]db.AffectedPackageHandle, []db.UnaffectedPackageHandle) {
	var afs []db.AffectedPackageHandle
	var unafs []db.UnaffectedPackageHandle
	groups := groupFixedIns(vuln)
	for group, fixedIns := range groups {
		// APK providers already handle not-affected signaling in their own matching layer,
		// so skip emitting unaffected package handles for them.
		pkgType := getPackageType(group.osName)
		if pkgType != pkg.ApkPkg && isNotAffectedGroup(fixedIns) {
			unafs = append(unafs, db.UnaffectedPackageHandle{
				OperatingSystem: getOperatingSystem(group.osName, group.id, group.osVersion, group.osChannel),
				Package:         getPackage(group),
				BlobValue: &db.PackageBlob{
					CVEs: getAliases(vuln),
					Ranges: []db.Range{
						{
							Version: db.Version{
								Type:       fixedIns[0].VersionFormat,
								Constraint: "",
							},
							Fix: &db.Fix{
								State: db.NotAffectedFixStatus,
							},
						},
					},
				},
			})
			continue
		}

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

		// SERVER-SIDE stream-affinity expansion: when the group's fixedIns carry
		// per-stream Advisories with at least one known minor, emit one
		// operating_system row per minor (each with the fix that governs that minor)
		// plus a major-only fallback row. This lets a stock grype client get
		// minor-affine matching purely by resolving its host minor to the right row,
		// without any matcher changes. Single-stream records fall through unchanged.
		if expanded := expandPerMinorHandles(vuln, group, fixedIns, qualifiers); expanded != nil {
			afs = append(afs, expanded...)
			continue
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

		aph.BlobValue.Ranges = buildRanges(vuln, fixedIns)
		afs = append(afs, aph)
	}

	// stable ordering
	sort.Sort(internal.ByAffectedPackage(afs))
	sort.Sort(internal.ByUnaffectedPackage(unafs))

	return afs, unafs
}

// buildRanges turns a group's fixedIns into the per-fix version ranges used on a
// package handle's blob (the original, unexpanded behavior).
func buildRanges(vuln unmarshal.OSVulnerability, fixedIns []unmarshal.OSFixedIn) []db.Range {
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
	return ranges
}

// minorFix pairs a known fix minor with the fix build (Version) that governs it.
type minorFix struct {
	minor   int
	version string
}

// expandPerMinorHandles implements the server-side stream-affinity prototype. It
// returns a slice of per-minor affected-package handles (plus one major-only fallback
// handle) when the group's fixedIns carry per-stream Advisories with at least one
// KNOWN (non-null) minor. It returns nil when the group is single-stream (no
// Advisories, or every advisory minor is null), signaling the caller to keep today's
// single-handle behavior.
//
// One known minor is enough to expand: the glibc/CVE-2023-4813 shape carries a single
// known minor (9.2) alongside a GA null-minor build (-100.el9) whose EVR outranks it.
// Without expansion that GA build becomes the lone major-only constraint and a 9.2 host
// past its own stream fix is falsely flagged against it. Expansion pins the major-only
// fallback to the highest KNOWN-minor fix instead, fixing the cross-minor false positive.
//
// Worked example (fixes at 9.2="Alpha", 9.3="Bravo"):
//
//	minors 9.0, 9.1, 9.2 -> "< Alpha"   (governed by the largest known fix <= m;
//	                                      for m below the lowest known minor, the
//	                                      lowest known fix is used)
//	minor  9.3            -> "< Bravo"
//	major-only (9, "")    -> "< Bravo"   (highest KNOWN-minor fix; rolls hosts on
//	                                      minors > maxKnownMinor forward)
//
// A GA null-minor (.elN) advisory cannot be placed on a minor directly. Rather than
// drop it (a false negative for hosts on a minor above the highest pinned one running a
// build below the GA fix), infer its minor by EVR-ordering it against the pinnable
// builds: if its full EVR exceeds the max pinnable EVR it is a genuinely-later fix for
// minor (maxKnownMinor+1) and is placed there (also becoming the major-only fallback);
// otherwise it is superseded by a pinnable fix and dropped (safe, no FN).
func expandPerMinorHandles(vuln unmarshal.OSVulnerability, group groupIndex, fixedIns []unmarshal.OSFixedIn, qualifiers *db.PackageQualifiers) []db.AffectedPackageHandle {
	// only RPM-style multi-stream RHEL-family data carries per-stream Advisories;
	// the per-minor OS rows only make sense when matching is minor-aware.
	if group.format != "rpm" {
		return nil
	}

	// at least one known minor is required; pure single-stream records (no Advisories,
	// or only GA null-minor advisories) are left to the unchanged single-handle path.
	fixes, versionFormat := collectKnownMinorFixes(fixedIns)
	if len(fixes) < 1 {
		return nil
	}

	// infer minors for GA null-minor builds by EVR ordering against the pinnable fixes.
	fixes = inferGAMinors(fixes, collectNullMinorGABuilds(fixedIns))

	lowestFix := fixes[0].version
	maxKnownMinor := fixes[len(fixes)-1].minor
	highestKnownMinorFix := fixes[len(fixes)-1].version

	// governing(m): the fix at the LARGEST known fix-minor <= m; below the lowest
	// known minor, use the lowest known fix.
	governing := func(m int) string {
		v := lowestFix
		for _, f := range fixes {
			if f.minor <= m {
				v = f.version
			} else {
				break
			}
		}
		return v
	}

	mkHandle := func(os *db.OperatingSystem, fixVersion string) db.AffectedPackageHandle {
		return db.AffectedPackageHandle{
			OperatingSystem: os,
			Package:         getPackage(group),
			BlobValue: &db.PackageBlob{
				CVEs:       getAliases(vuln),
				Qualifiers: qualifiers,
				Ranges: []db.Range{
					{
						Version: db.Version{
							Type:       versionFormat,
							Constraint: deriveConstraintFromFix(versionutil.CleanConstraint(fixVersion), vuln.Vulnerability.Name),
						},
						// the governing fix for this minor; the per-stream advisory
						// reference detail is intentionally omitted in this prototype.
						Fix: &db.Fix{
							Version: versionutil.CleanFixedInVersion(fixVersion),
							State:   db.FixedStatus,
						},
					},
				},
			},
		}
	}

	var out []db.AffectedPackageHandle
	for m := 0; m <= maxKnownMinor; m++ {
		os := getOperatingSystemWithMinor(group.osName, group.id, group.osVersion, strconv.Itoa(m), group.osChannel)
		if os == nil {
			return nil
		}
		out = append(out, mkHandle(os, governing(m)))
	}

	// major-only fallback for hosts on minors > maxKnownMinor (rolled forward to the
	// highest KNOWN-minor fix - never a GA null-minor build).
	majorOnly := getOperatingSystemWithMinor(group.osName, group.id, group.osVersion, "", group.osChannel)
	if majorOnly == nil {
		return nil
	}
	out = append(out, mkHandle(majorOnly, highestKnownMinorFix))

	return out
}

// collectKnownMinorFixes gathers the known (non-null) minor -> fix version across all
// fixedIns in the group, returning them sorted ascending by minor (plus the version
// format). Last write wins per minor; in practice vunnel emits one advisory per minor.
func collectKnownMinorFixes(fixedIns []unmarshal.OSFixedIn) ([]minorFix, string) {
	knownByMinor := make(map[int]string)
	var versionFormat string
	for _, f := range fixedIns {
		for _, adv := range f.Advisories {
			if adv.Minor == nil {
				continue
			}
			knownByMinor[*adv.Minor] = adv.Version
			versionFormat = f.VersionFormat
		}
	}

	fixes := make([]minorFix, 0, len(knownByMinor))
	for m, v := range knownByMinor {
		fixes = append(fixes, minorFix{minor: m, version: v})
	}
	sort.Slice(fixes, func(i, j int) bool { return fixes[i].minor < fixes[j].minor })

	return fixes, versionFormat
}

// collectNullMinorGABuilds returns the fix Versions of advisories whose Minor is null
// AND whose Version is a bare GA .elN build (not a z-stream .elN_M).
func collectNullMinorGABuilds(fixedIns []unmarshal.OSFixedIn) []string {
	var out []string
	for _, f := range fixedIns {
		for _, adv := range f.Advisories {
			if adv.Minor == nil && isBareGABuild(adv.Version) {
				out = append(out, adv.Version)
			}
		}
	}
	return out
}

// isBareGABuild reports whether an RPM EVR carries a bare GA .elN dist tag (e.g.
// 0:2.34-100.el9) rather than a z-stream/modular one (0:2.34-60.el9_2.7).
func isBareGABuild(evr string) bool {
	return bareGARelease.MatchString(evr)
}

// inferGAMinors folds each GA null-minor build into the sorted per-minor fixes by EVR
// ordering: a GA build whose full EVR exceeds the current max pinnable EVR is inferred
// to fix minor (maxMinor+1) and appended (governing that minor and up, and becoming the
// new highest fix); a GA build at or below some pinnable EVR is superseded and dropped.
// Comparison is version-first RPM EVR (epoch->version->release), NOT a release-int
// compare, so an upstream rebase whose release counter reset (e.g. 2.40.5-1.el9 vs a
// pinned 2.38.5-1.el9_2.3) still orders correctly by version.
func inferGAMinors(fixes []minorFix, gaBuilds []string) []minorFix {
	// ascending EVR so successively-higher GA builds land on successive minors.
	sort.Slice(gaBuilds, func(i, j int) bool { return compareRPMEVR(gaBuilds[i], gaBuilds[j]) < 0 })
	for _, ga := range gaBuilds {
		maxFix := fixes[len(fixes)-1]
		if compareRPMEVR(ga, maxFix.version) > 0 {
			fixes = append(fixes, minorFix{minor: maxFix.minor + 1, version: ga})
		}
	}
	return fixes
}

// compareRPMEVR compares two RPM EVR strings, returning -1/0/1. On a parse/compare
// error it returns 0 (treated as "not greater" by callers -> conservative drop).
func compareRPMEVR(a, b string) int {
	cmp, err := version.New(a, version.RpmFormat).Compare(version.New(b, version.RpmFormat))
	if err != nil {
		log.WithFields("a", a, "b", b, "error", err).Trace("unable to compare RPM EVRs for GA-minor inference")
		return 0
	}
	return cmp
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
	case "arch", "archlinux":
		return pkg.AlpmPkg
	case "redhat", "amazonlinux", "oraclelinux", "sles", "mariner", "azurelinux", "photon", "fedora", "rocky", "rockylinux", "almalinux", "centos", "hummingbird":
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

// getOperatingSystemWithMinor builds an OS row reusing getOperatingSystem but forces
// the minor version to the supplied value (empty string means a major-only row). This
// lets the stream-affinity expansion materialize one OS row per minor from a group
// whose osVersion only carries the major (e.g. RHEL "9"). Codename is recomputed for
// the overridden minor.
func getOperatingSystemWithMinor(osName, osID, osVersion, minor, channel string) *db.OperatingSystem {
	os := getOperatingSystem(osName, osID, osVersion, channel)
	if os == nil {
		return nil
	}
	os.MinorVersion = minor
	os.Codename = codename.LookupOS(osName, os.MajorVersion, minor)
	return os
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
