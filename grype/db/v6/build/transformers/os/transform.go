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
			// A not-affected handle SUPPRESSES an affected match for the same package+OS.
			// Because affected handles are expanded per-minor (below), the suppressing
			// handle must be expanded to the same minor rows -- otherwise a minored host
			// resolves to a per-minor affected row while the lone major-only unaffected
			// handle is never consulted (grype returns the most-specific OS row and does
			// not union the major row back in), leaking a false positive.
			unafs = append(unafs, expandUnaffectedHandles(vuln, group, fixedIns)...)
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
			// when the advisory scoped this fix to a specific architecture, carry it so the
			// architecture qualifier only applies the fix to packages of that arch (see
			// pkg/qualifier/architecture). Absent arch means the fix applies to all arches.
			if group.arch != "" {
				arch := group.arch
				qualifiers.Architecture = &arch
			}
		}

		// SERVER-SIDE stream-affinity expansion: for RHEL GA groups, emit one
		// operating_system row per minor across the major's full minor span (plus a
		// major-only fallback row). A stock grype client resolves its host to the
		// most-specific OS row and does NOT union in the major row, so EVERY package
		// must appear on EVERY minor row or minored hosts lose coverage; the expansion
		// is therefore cumulative and uniform across records. Single-stream packages
		// carry their normal ranges on every minor (verdict unchanged); multi-stream
		// packages pin each minor's own stream fix. Non-RHEL / EUS / already-minored
		// groups fall through to the single-handle path unchanged.
		if expanded := expandRHELMinorRows(vuln, group, fixedIns, qualifiers); expanded != nil {
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

// minorFix pairs a known fix minor with the fix build (Version) shipped for it.
type minorFix struct {
	minor    int
	version  string
	advisory string // RHSA id that shipped this build ("" when unknown); becomes the fix's reference
}

// expandRHELMinorRows implements the cumulative server-side stream-affinity expansion.
// For a RHEL GA (channel-less), major-only group it returns one affected-package handle
// per minor across the major's full span (rhelMinorSpan) plus a major-only fallback
// handle. It returns nil for any group that should keep the single-handle path: non-rpm,
// non-RHEL, an EUS/other channel, an already-minored namespace, or an unknown major.
//
// The expansion is result-preserving for the common single-stream package: with no known
// per-minor fixes, every minor row (and the major fallback) carries the group's normal
// ranges, so a host on any minor sees the same verdict it does today. It only changes
// behavior for same-base multi-RHSA packages: a minor with its own stream fix pins that
// fix, and every other minor carries the record's base (canonical top-level) fix:
//
//	stream fixes at 9.2="Alpha", 9.4="Bravo" (base/top-level = "Base"):
//	  minor 9.2         -> "< Alpha"
//	  minor 9.4         -> "< Bravo"
//	  every other minor -> "< Base"   (gaps, minors past the streams, and major-only "")
func expandRHELMinorRows(vuln unmarshal.OSVulnerability, group groupIndex, fixedIns []unmarshal.OSFixedIn, qualifiers *db.PackageQualifiers) []db.AffectedPackageHandle {
	minors := rhelGAExpansionMinors(group)
	if minors == nil {
		return nil
	}

	// known per-minor stream fixes (empty for the common single-stream case).
	fixes, versionFormat := collectKnownMinorFixes(fixedIns)

	// Per-minor pinning is correct for same-base multi-minor RHSAs, but a MULTI-UPSTREAM-BASE
	// group carries a disjoint VulnerableRange that a single per-minor "< fix" cannot represent
	// (it would flag a host still on the lower base that already carries its own base's fix -- a
	// false positive). Those fall back to the group's normal ranges (which honor VulnerableRange)
	// on every row, exactly as single-stream groups do; we still expand across the span so the
	// package stays present on every minor row (completeness), just carrying the disjoint range.
	perMinor := len(fixes) > 0 && !hasVulnerableRange(fixedIns)

	// baseRanges is the group's normal per-fix range set (honors VulnerableRange, wont-fix, and
	// the record's top-level advisory); carried on every non-per-minor row and every per-minor
	// row that has no stream fix of its own.
	baseRanges := buildRanges(vuln, fixedIns)

	// rangesFor returns the ranges for a given minor row (minor=="" is the major fallback).
	// Non-per-minor groups carry baseRanges on every row; per-minor groups pin a minor's own
	// stream fix and fall back to baseRanges for every other minor.
	rangesFor := func(minor string) []db.Range {
		if !perMinor || minor == "" {
			return baseRanges
		}
		m, _ := strconv.Atoi(minor)
		var minorFixes []minorFix
		for _, fix := range fixes {
			if fix.minor == m {
				minorFixes = append(minorFixes, fix)
			}
		}
		if len(minorFixes) == 0 {
			return baseRanges
		}

		maxFix := minorFixes[len(minorFixes)-1] // highest fix targeting this minor
		fix := &db.Fix{
			Version: versionutil.CleanFixedInVersion(maxFix.version),
			State:   db.FixedStatus,
		}
		if ref := advisoryReference(maxFix.advisory); ref != nil {
			fix.Detail = &db.FixDetail{References: []db.Reference{*ref}}
		}
		return []db.Range{{
			Version: db.Version{
				Type:       versionFormat,
				Constraint: deriveConstraintFromFix(versionutil.CleanConstraint(maxFix.version), vuln.Vulnerability.Name),
			},
			Fix: fix,
		}}
	}

	out := make([]db.AffectedPackageHandle, 0, len(minors))
	for _, minor := range minors {
		out = append(out, db.AffectedPackageHandle{
			OperatingSystem: getOperatingSystemWithMinor(group.osName, group.id, group.osVersion, minor, group.osChannel),
			Package:         getPackage(group),
			BlobValue: &db.PackageBlob{
				CVEs:       getAliases(vuln),
				Qualifiers: qualifiers,
				Ranges:     rangesFor(minor),
			},
		})
	}
	return out
}

// expandUnaffectedHandles builds the not-affected package handle(s) for a group. For a
// RHEL GA group it mirrors expandRHELMinorRows' minor set exactly (same gating and span,
// via rhelGAExpansionMinors) so that every affected minor row has a co-located
// suppressing handle; without this the expanded affected rows would match a minored host
// while the major-only unaffected handle is never consulted (a false positive). For all
// other groups it returns the single major-scoped handle (unchanged behavior).
func expandUnaffectedHandles(vuln unmarshal.OSVulnerability, group groupIndex, fixedIns []unmarshal.OSFixedIn) []db.UnaffectedPackageHandle {
	mk := func(os *db.OperatingSystem) db.UnaffectedPackageHandle {
		return db.UnaffectedPackageHandle{
			OperatingSystem: os,
			Package:         getPackage(group),
			BlobValue: &db.PackageBlob{
				CVEs: getAliases(vuln),
				Ranges: []db.Range{
					{
						Version: db.Version{Type: fixedIns[0].VersionFormat, Constraint: ""},
						Fix:     &db.Fix{State: db.NotAffectedFixStatus},
					},
				},
			},
		}
	}

	minors := rhelGAExpansionMinors(group)
	if minors == nil {
		return []db.UnaffectedPackageHandle{mk(getOperatingSystem(group.osName, group.id, group.osVersion, group.osChannel))}
	}
	out := make([]db.UnaffectedPackageHandle, 0, len(minors))
	for _, minor := range minors {
		out = append(out, mk(getOperatingSystemWithMinor(group.osName, group.id, group.osVersion, minor, group.osChannel)))
	}
	return out
}

// rhelGAExpansionMinors returns the minor-version strings to materialize for a RHEL GA
// group -- "0".."span" then "" (the major-only fallback row) -- or nil if the group must
// not be expanded (non-rpm, non-RHEL, a specific channel like EUS, an already-minored
// namespace, or an unrecognized major). Both the affected and unaffected expansions call
// this so they always emit the identical set of OS rows.
func rhelGAExpansionMinors(group groupIndex) []string {
	// only RHEL GA (channel-less) major-only namespaces (e.g. "rhel:8"). EUS groups
	// already carry their minor in the namespace ("rhel:8.4+eus"); non-RHEL rpm distros
	// do not use the RHEL minor model.
	if group.format != "rpm" || group.osName != "redhat" || group.osChannel != "" {
		return nil
	}
	if strings.Contains(group.osVersion, ".") {
		return nil // already minor-specific
	}
	span, ok := rhelMinorSpan[group.osVersion]
	if !ok {
		return nil // unknown major: keep the single major-only handle
	}
	if getOperatingSystemWithMinor(group.osName, group.id, group.osVersion, "", group.osChannel) == nil {
		return nil
	}

	minors := make([]string, 0, span+2)
	for m := 0; m <= span; m++ {
		minors = append(minors, strconv.Itoa(m))
	}
	return append(minors, "") // major-only fallback row
}

// advisoryReference builds a fix Detail reference from an RHSA id, deriving the canonical Red Hat
// errata URL. Returns nil for an empty id so a fix with no known advisory carries no reference.
func advisoryReference(rhsaID string) *db.Reference {
	if rhsaID == "" {
		return nil
	}
	return &db.Reference{
		ID:   rhsaID,
		URL:  "https://access.redhat.com/errata/" + rhsaID,
		Tags: []string{db.AdvisoryReferenceTag},
	}
}

// collectKnownMinorFixes gathers the known (non-null) minor -> fix version across all
// fixedIns in the group, returning them sorted ascending by minor (plus the version
// format). Last write wins per minor; in practice vunnel emits one advisory per minor.
func collectKnownMinorFixes(fixedIns []unmarshal.OSFixedIn) ([]minorFix, string) {
	knownByMinor := make(map[int]minorFix)
	var versionFormat string
	for _, f := range fixedIns {
		for _, adv := range f.Advisories {
			if adv.Minor == nil {
				continue
			}
			knownByMinor[*adv.Minor] = minorFix{minor: *adv.Minor, version: adv.Version, advisory: adv.Advisory}
			versionFormat = f.VersionFormat
		}
	}

	fixes := make([]minorFix, 0, len(knownByMinor))
	for _, mf := range knownByMinor {
		fixes = append(fixes, mf)
	}
	sort.Slice(fixes, func(i, j int) bool { return fixes[i].minor < fixes[j].minor })

	return fixes, versionFormat
}

// hasVulnerableRange reports whether any fixedIn carries a VulnerableRange, which vunnel emits for
// multi-upstream-base groups (disjoint per-base vulnerable ranges). Such groups must not be
// collapsed to a single per-minor governing fix.
func hasVulnerableRange(fixedIns []unmarshal.OSFixedIn) bool {
	for _, f := range fixedIns {
		if f.VulnerableRange != "" {
			return true
		}
	}
	return false
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
	arch      string
}

func groupFixedIns(vuln unmarshal.OSVulnerability) map[groupIndex][]unmarshal.OSFixedIn {
	grouped := make(map[groupIndex][]unmarshal.OSFixedIn)
	oi := getOSInfo(vuln.Vulnerability.NamespaceName)

	for _, fixedIn := range vuln.Vulnerability.FixedIn {
		var mod string
		if fixedIn.Module != nil {
			mod = *fixedIn.Module
		}
		var arch string
		if fixedIn.Arch != nil {
			arch = *fixedIn.Arch
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
			// arch splits a per-arch fix into its own affected package handle so the architecture
			// qualifier can scope it; empty means the fix applies to all arches.
			arch: arch,
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
