package osv

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

type chainguardStrategy struct{}

// Matches identifies CG OSV records by their "CGA-" prefix
func (chainguardStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "CGA-")
}

// Strict on purpose: the feed carries "cve36" and CVE ids typed with U+2011 hyphens, which
// must fall through to a later tier rather than become a wrong CVE name.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// cgNames picks the name(s): every strict CVE, else the smallest GHSA, else the smallest GO,
// else the CGA. Only `upstream` is read.
//
// Chainguard mints one CGA per (package x arch x bundled component), so one CVE spreads over
// up to ~14k records identical in every rendered field. match.Fingerprint keys on the
// vulnerability id, so CGA names both hide the searchable id and multiply findings. Only the
// CVE tier fans out: two-CVE records were checked and are genuinely distinct issues. The
// GHSA and GO tiers take the smallest id rather than the first, so two CGAs listing the same
// ids in a different order still share one handle.
func cgNames(vuln unmarshal.OSVVulnerability) []string {
	var cves, ghsas, gos []string
	for _, id := range vuln.Upstream {
		switch {
		case cveIDPattern.MatchString(id):
			cves = append(cves, id)
		case strings.HasPrefix(id, "GHSA-"):
			ghsas = append(ghsas, id)
		case strings.HasPrefix(id, "GO-"):
			gos = append(gos, id)
		}
	}

	switch {
	case len(cves) > 0:
		return cves
	case len(ghsas) > 0:
		return []string{slices.Min(ghsas)}
	case len(gos) > 0:
		return []string{slices.Min(gos)}
	}

	log.WithFields("id", vuln.ID, "upstream", vuln.Upstream).
		Warn("chainguard record carries no usable upstream identifier; keeping the CGA as the vulnerability name")
	return []string{vuln.ID}
}

// Transform CG OSV records into grype DB entries. CG OSV records specify the range of vulnerable versions
// for a given vulnerability. Entries are marked MergeByName because renaming alone would
// leave one handle per CGA; see name_merge.go.
func (chainguardStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	// Every id this CGA carries lives on its own package rows, never in the shared handle's
	// Aliases. `upstream` says what the CGA derives from, not that those ids are one
	// vulnerability: a record listing [CVE-A, CVE-B] put into the merged CVE-A handle would make
	// every other package's CVE-A finding claim CVE-B too (suppressing its NVD match and pulling
	// in its KEV/EPSS). Row CVEs feed RelatedVulnerabilities, so the link stays scoped to this
	// CGA's packages. `related` is ignored: it means "different", and row CVEs are identity.
	packageCVEs := dedupeIDs(slices.Concat(vuln.Aliases, vuln.Upstream, []string{vuln.ID}))

	var entries []data.Entry
	for _, vulnName := range cgNames(vuln) {
		in := []any{
			db.VulnerabilityHandle{
				Name:          vulnName,
				Status:        db.VulnerabilityActive,
				PublishedDate: &vuln.Published,
				ModifiedDate:  &vuln.Modified,
				WithdrawnDate: nil,
				ProviderID:    state.Provider,
				Provider:      provider.Model(state),
				BlobValue: &db.VulnerabilityBlob{
					// must track Name: blobs dedupe by digest, so a per-record CGA here
					// would keep every digest distinct and forfeit the collapse
					ID:          vulnName,
					Assigners:   nil,
					Description: vuln.Details,
					References:  cgReferences(vuln),
					Severities:  append([]db.Severity{}, severities...),
				},
			},
		}

		for _, uph := range cgAffectedPackages(vuln, packageCVEs) {
			in = append(in, uph)
		}
		entries = append(entries, transformers.NewMergeableEntries(in...)...)
	}
	return entries, nil
}

// dedupeIDs preserves first-seen (feed) order, so blob digests stay reproducible across builds.
func dedupeIDs(ids []string) []string {
	if len(ids) < 2 {
		return ids
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// cgReferences convert OSV references into grype DB references.
//
// Reference.ID is left empty: stamping the CGA on ADVISORY refs mislabeled third-party URLs
// (Red Hat errata) and re-injected per-record entropy into the blob, defeating the merge.
func cgReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

// cgAffectedPackages converts OSV affected packages into grype DB affected package handles. CG OSV records
// specify the range of vulnerable versions for a given vulnerability, so we convert those ranges into grype
// DB ranges and attach them to the affected package handle blob.
func cgAffectedPackages(vuln unmarshal.OSVVulnerability, cves []string) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r, cgRangeType(r.Type))...)
		}
		ranges = cgWithUnfixedState(ranges, affected)
		purlType := pkg.TypeFromPURL(affected.Package.Purl)
		aphs = append(aphs, db.AffectedPackageHandle{
			OperatingSystem: cgOperatingSystem(affected.Package.Ecosystem),
			Package: &db.Package{
				// the OSV ecosystem names the distro, which is
				// the row's OS, ecosystem here is the package type
				Ecosystem: purlType.String(),
				Name:      name.Normalize(affected.Package.Name, purlType),
			},
			BlobValue: &db.PackageBlob{
				CVEs:       cves,
				Ranges:     ranges,
				Qualifiers: cgGetQualifiers(affected),
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

// affected[].ecosystem_specific.components[].latest_event_status. The feed's other two values
// ("fixed", and "false_positive_determination" = the apk NAK) already reach grype via the range.
const (
	cgStatusFixNotPlanned   = "fix_not_planned"
	cgStatusPendingUpstream = "pending_upstream_fix"
	cgStatusTruePositive    = "true_positive_determination"
	cgStatusDetection       = "detection"
)

// cgLatestEventStatus requires unanimity rather than taking components[0]: zero affected
// entries in the feed disagree, so insisting costs nothing and refuses to invent an answer
// if that ever changes. A component with no status is not agreement: one component saying
// fix_not_planned beside a silent sibling leaves the state unknown.
func cgLatestEventStatus(affected osvmodel.Affected) string {
	components, ok := affected.EcosystemSpecific["components"].([]any)
	if !ok {
		return ""
	}
	var status string
	for i, component := range components {
		fields, _ := component.(map[string]any)
		value, _ := fields["latest_event_status"].(string)
		switch {
		case i == 0:
			status = value
		case status != value:
			log.WithFields("package", affected.Package.Name, "statuses", []string{status, value}).
				Warn("chainguard affected entry has components with disagreeing latest_event_status; leaving the fix state unknown")
			return ""
		}
	}
	return status
}

// "detection" stays unknown deliberately: NotFixedStatus affirms "affected, no fix available",
// which Chainguard has not said -- detection means triage is unfinished, and grype has no state
// for that.
func cgUnfixedFixStatus(affected osvmodel.Affected) db.FixStatus {
	switch cgLatestEventStatus(affected) {
	case cgStatusFixNotPlanned:
		return db.WontFixStatus
	case cgStatusPendingUpstream, cgStatusTruePositive:
		return db.NotFixedStatus
	case cgStatusDetection:
		return db.UnknownFixStatus
	}
	return db.UnknownFixStatus
}

// An entry whose only event is `introduced: "0"` produces no range, and a fix state has
// nowhere to live but a Range. The synthesized one carries no version: getVersionConstraint
// ignores a range's Type when its Constraint is empty, so matching is unchanged.
func cgWithUnfixedState(ranges []db.Range, affected osvmodel.Affected) []db.Range {
	if len(ranges) > 0 {
		return ranges
	}
	state := cgUnfixedFixStatus(affected)
	if state == db.UnknownFixStatus {
		return ranges
	}
	return []db.Range{{Fix: &db.Fix{State: state}}}
}

// cgRangeType maps an OSV range type to the grype version-format string.
// ECOSYSTEM ranges describe APK versions ("apk" format); all other range
// types fall back to the default mapping. CG OSV records should all use
// ECOSYSTEM, but the fallback is here so unexpected shapes don't silently
// become "unknown".
func cgRangeType(t osvmodel.RangeType) string {
	if t == osvmodel.RangeEcosystem {
		// ECOSYSTEM ranges carry versions in the ecosystem's native scheme; for
		// Chainguard/Wolfi that is apk versioning (e.g. "2.4.63-r1"). Store the apk
		// format explicitly — the default "ecosystem" string parses to UnknownFormat,
		// whose fuzzy comparison mis-orders apk pkgrels (e.g. it would call
		// 2.4.63-r10 vulnerable against "< 2.4.63-r9").
		return pkg.ApkPkg.String()
	}
	return defaultRangeType(t)
}

// cgGetQualifiers extracts qualifiers from the affected package's PURL. CG OSV records
// may specify an "arch" qualifier in the PURL, which we extract and store in the grype
// DB PackageQualifiers. If the PURL is malformed, empty, or carries no "arch" qualifier,
// returns nil.
func cgGetQualifiers(affected osvmodel.Affected) *db.PackageQualifiers {
	if affected.Package.Purl == "" {
		return nil
	}
	purl, err := packageurl.FromString(affected.Package.Purl)
	if err != nil {
		return nil
	}
	for _, q := range purl.Qualifiers {
		// if we have a purl with an "arch" qualifier, we want to pull that out and
		// store it in the qualifiers for this affected package
		if q.Key == "arch" && q.Value != "" {
			arch := q.Value
			return &db.PackageQualifiers{
				Architecture: &arch,
			}
		}
	}
	return nil
}

// cgOperatingSystem maps the OSV ecosystem string to a grype DB OperatingSystem row.
// CG OSV advisories can carry affected entries across multiple apk-based distros
// (Chainguard, Wolfi). Each becomes its own OS row so apk-distro matchers can find
// them via the operating_systems table + operating_system_specifier_overrides.
// Returns nil if the ecosystem is not a known apk distro — caller skips that entry.
func cgOperatingSystem(ecosystem string) *db.OperatingSystem {
	lower := strings.ToLower(ecosystem)
	switch lower {
	case "chainguard", "wolfi":
		return &db.OperatingSystem{
			Name:         lower,
			ReleaseID:    lower,
			LabelVersion: "rolling",
		}
	}
	return nil
}
