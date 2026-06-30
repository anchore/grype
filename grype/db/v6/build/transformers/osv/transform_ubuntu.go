package osv

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/codename"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

// ubuntuStrategy handles UBUNTU-CVE-* records from Canonical's published OSV
// feed (osv-all.tar.xz). These records describe vulnerable version ranges of
// Ubuntu source packages — AK semantics — and must produce DB rows that are
// indistinguishable from what the OS-schema transformer produces for Ubuntu
// records today, because the dpkg matcher already queries against those rows
// via search.ByPackageName + search.ByDistro.
//
// The ubuntu strategy diverges from alma/bitnami/rootio in three load-bearing
// ways:
//
//   - CVE aliases come from the record's top-level `upstream` field, not
//     `aliases`. Canonical leaves `aliases` empty and puts the CVE link in
//     `upstream`. The unmarshal wrapper exposes this via vuln.Upstream.
//   - Vendor severity is `severity[].type == "Ubuntu"` with a lowercase string
//     score ("high"/"medium"/"low"/"negligible"). This maps to the CHMLN
//     scheme — the same scheme the legacy OS transformer uses for its
//     Vulnerability.Severity string, so downstream consumers don't have to
//     branch on transformer source.
//   - Records with `withdrawn` set are skipped entirely. Canonical retracted
//     the CVE; emitting it would produce stale hits.
const (
	ubuntu           = "ubuntu"
	ubuntuESMChannel = "esm"
	ubuntuPkgFormat  = "dpkg"
)

type ubuntuStrategy struct{}

func (ubuntuStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "UBUNTU-CVE-")
}

func (ubuntuStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	// Withdrawn records are dropped. The legacy passthrough is the only path
	// a Canonical-retracted CVE can still reach the DB (if a frozen row
	// survives in the legacy results.db for an EOL release).
	if !vuln.Withdrawn.IsZero() {
		return nil, nil
	}

	severities, err := ubuntuSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain ubuntu severities: %w", err)
	}

	// The vulnerability is keyed by its upstream CVE — that's the identifier
	// users have always seen for Ubuntu records (legacy OS-schema records set
	// VulnerabilityHandle.Name directly to "CVE-..."). The UBUNTU-CVE-* id is
	// Canonical's internal record key; storing it would change the column in
	// every existing report.
	//
	// If there is no upstream (e.g. some withdrawn 1.6.3 records — not
	// reached today since withdrawn records are already dropped above), fall
	// back to the OSV record id so we don't silently lose the row.
	primaryID, extraAliases := splitUbuntuUpstream(vuln)

	in := []any{
		db.VulnerabilityHandle{
			Name:          primaryID,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			Status:        db.VulnerabilityActive,
			ModifiedDate:  &vuln.Modified,
			PublishedDate: &vuln.Published,
			BlobValue: &db.VulnerabilityBlob{
				ID:          primaryID,
				Description: vuln.Details,
				References:  ubuntuReferences(vuln),
				Aliases:     extraAliases,
				Severities:  severities,
			},
		},
	}

	for _, aph := range ubuntuAffectedPackages(vuln, extraAliases) {
		in = append(in, aph)
	}
	return transformers.NewEntries(in...), nil
}

// splitUbuntuUpstream picks the primary user-visible ID from the OSV record's
// upstream field. Real Ubuntu OSV records carry exactly one upstream CVE
// (the wrapper around vuln.ID), so the dominant case is upstream=[CVE-X] →
// primary=CVE-X, extras=nil. The rare multi-upstream case (a single Ubuntu
// CVE wrapping multiple upstream CVEs) keeps the first as primary and stores
// the rest as aliases. If upstream is missing entirely, fall back to the
// OSV record id so the row is still emitted.
func splitUbuntuUpstream(vuln unmarshal.OSVVulnerability) (primary string, extras []string) {
	if len(vuln.Upstream) == 0 {
		return vuln.ID, nil
	}
	primary = vuln.Upstream[0]
	if len(vuln.Upstream) > 1 {
		extras = append([]string{}, vuln.Upstream[1:]...)
	}
	return primary, extras
}

func ubuntuReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

// ubuntuSeverities normalizes Ubuntu's mixed severity shapes. The Ubuntu vendor
// severity is a lowercase string ("high"/"medium"/"low"/...); CVSS entries
// are standard "CVSS:x.y/<vector>" strings. CHMLN-scheme entries lead the
// slice so downstream rank-ordering picks the vendor severity first, matching
// the OS transformer's order.
func ubuntuSeverities(vuln unmarshal.OSVVulnerability) ([]db.Severity, error) {
	var chmln []db.Severity
	var cvss []db.Severity

	classify := func(sev osvmodel.Severity) error {
		if sev.Type == "Ubuntu" {
			chmln = append(chmln, db.Severity{
				Scheme: db.SeveritySchemeCHMLN,
				Value:  strings.ToLower(sev.Score),
				Rank:   1,
			})
			return nil
		}
		n, err := normalizeSeverity(sev)
		if err != nil {
			return err
		}
		n.Rank = 2
		cvss = append(cvss, n)
		return nil
	}

	for _, sev := range vuln.Severity {
		if err := classify(sev); err != nil {
			return nil, err
		}
	}
	for _, affected := range vuln.Affected {
		for _, sev := range affected.Severity {
			if err := classify(sev); err != nil {
				return nil, err
			}
		}
	}

	if len(chmln) == 0 && len(cvss) == 0 {
		return nil, nil
	}
	return append(chmln, cvss...), nil
}

func ubuntuAffectedPackages(vuln unmarshal.OSVVulnerability, aliases []string) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		osRow := ubuntuOSFromEcosystem(affected.Package.Ecosystem)
		if osRow == nil {
			// Unparseable ecosystem — skip this affected entry rather than
			// emitting a row the matcher could never resolve.
			continue
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			Package:         ubuntuPackage(affected.Package),
			OperatingSystem: osRow,
			BlobValue: &db.PackageBlob{
				CVEs:   aliases,
				Ranges: ubuntuRangesFromAffected(affected),
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

func ubuntuPackage(p osvmodel.Package) *db.Package {
	return &db.Package{
		Ecosystem: pkg.DebPkg.String(),
		Name:      name.Normalize(p.Name, pkg.DebPkg),
	}
}

// ubuntuRangesFromAffected produces dpkg-typed ranges that match what
// os.Transform emits for ubuntu records:
//
//   - introduced=0 + fixed=X → "< X" range + Fix{Version:X, State:FixedStatus,
//     Detail.Available:<from anchore.fixes>}. Handled by the shared helper.
//   - bare introduced=0 (no fixed event) → "" constraint + Fix sentinel. State
//     depends on the wont-fix disposition surfaced by the vunnel-side VEX
//     overlay (see ubuntuFixStateForNoFixSentinel below). The shared helper
//     returns no ranges for this shape, so we add the sentinel here. This
//     mirrors os.Transform's behavior for an AffectedPackageHandle whose
//     FixedIn.Version cleans to empty: NotFixedStatus by default, or
//     WontFixStatus when VendorAdvisory.NoAdvisory was true (the OS-schema
//     equivalent of what the VEX overlay marks).
//
// Without the sentinel the dpkg matcher would see a gap where Canonical says
// "we acknowledge this CVE but no fix has shipped" — the row would simply
// not exist in the DB, and the scan would miss the disclosure.
func ubuntuRangesFromAffected(affected osvmodel.Affected) []db.Range {
	var ranges []db.Range
	for _, r := range affected.Ranges {
		ranges = append(ranges, getGrypeRangesFromRange(r, ubuntuRangeType(r.Type))...)
	}
	if len(ranges) == 0 && len(affected.Ranges) > 0 {
		ranges = []db.Range{{
			Version: db.Version{Type: ubuntuRangeType(affected.Ranges[0].Type)},
			Fix:     &db.Fix{State: ubuntuFixStateForNoFixSentinel(affected)},
		}}
	}
	return ranges
}

// ubuntuFixStateForNoFixSentinel reads the vunnel-side VEX overlay annotation
// to decide whether a no-fix sentinel range should be NotFixed (default,
// "Canonical hasn't shipped a fix yet") or WontFix (Canonical explicitly
// decided not to fix this on this release).
//
// The vunnel ubuntu provider stamps
//
//	affected[].database_specific.anchore.status = "wont-fix"
//
// onto sliced OSV records whose (cve, distro, source-pkg) tuple is
// marked won't-fix in Canonical's OpenVEX feed. Canonical's published OSV
// records do NOT carry this signal directly (they collapse six tracker
// statuses into one OSV shape — see the publisher's status mapping table at
// documentation.ubuntu.com/security/security-updates/osv/), so vunnel pulls
// the disposition from the parallel VEX feed and bakes it into the fragment
// at write time. Reading it here closes the loop.
func ubuntuFixStateForNoFixSentinel(affected osvmodel.Affected) db.FixStatus {
	if osvmodel.AffectedExtension(affected.DatabaseSpecific).Status == "wont-fix" {
		return db.WontFixStatus
	}
	return db.NotFixedStatus
}

// ubuntuRangeType maps OSV's RangeType to grype's version-format string. For
// Ubuntu the ECOSYSTEM type means dpkg-formatted versions; any other shape
// falls through to the default so unexpected inputs are caught rather than
// silently emitted as ECOSYSTEM-typed.
func ubuntuRangeType(t osvmodel.RangeType) string {
	if t == osvmodel.RangeEcosystem {
		return ubuntuPkgFormat
	}
	return defaultRangeType(t)
}

// ubuntuOSFromEcosystem parses Canonical's ecosystem strings. Three real
// shapes (per actual osv-all.tar.xz records):
//
//   - "Ubuntu:24.04:LTS"     — 3-segment, LTS suffix decorative.
//   - "Ubuntu:25.10"         — 2-segment, interim release.
//   - "Ubuntu:Pro:14.04:LTS" — 4-segment, Pro/ESM marker in slot 2.
//
// Anything else is unparseable; the caller skips that affected entry rather
// than synthesizing partial OS rows.
func ubuntuOSFromEcosystem(ecosystem string) *db.OperatingSystem {
	parts := strings.Split(ecosystem, ":")
	if len(parts) < 2 || !strings.EqualFold(parts[0], "Ubuntu") {
		return nil
	}

	var channel, version string
	switch {
	case strings.EqualFold(parts[1], "Pro"):
		// Ubuntu:Pro:<version>[:LTS]
		if len(parts) < 3 {
			return nil
		}
		channel = ubuntuESMChannel
		version = parts[2]
	default:
		// Ubuntu:<version>[:LTS]
		version = parts[1]
	}

	major, minor, ok := splitUbuntuVersion(version)
	if !ok {
		return nil
	}

	return &db.OperatingSystem{
		Name:         ubuntu,
		ReleaseID:    ubuntu,
		MajorVersion: major,
		MinorVersion: minor,
		Channel:      channel,
		Codename:     codename.LookupOS(ubuntu, major, minor),
	}
}

func splitUbuntuVersion(v string) (string, string, bool) {
	if v == "" {
		return "", "", false
	}
	fields := strings.SplitN(v, ".", 2)
	major := fields[0]
	if _, err := strconv.Atoi(major); err != nil {
		return "", "", false
	}
	var minor string
	if len(fields) > 1 {
		minor = fields[1]
	}
	return major, minor, true
}
