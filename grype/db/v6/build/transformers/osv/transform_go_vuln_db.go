package osv

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

// govulndbStrategy handles GO-* records from the Go vulnerability database
// (vuln.go.dev). These records describe *affected* version ranges of Go
// modules — both regular modules (github.com/foo/bar, golang.org/x/net) and
// the special "stdlib" and "toolchain" pseudo-modules. Records are
// disclosures (vulnerable ranges), not NAKs.
//
// Govulndb-specific decisions:
//   - CVEs and GHSAs are in `aliases` directly; the schema has no `related`
//     field, so no augmentation.
//   - Ecosystem is always "Go"; mapped to the syft go-module package type so
//     the matcher reaches these records via its standard ecosystem-name
//     search.
//   - Range type is always SEMVER; mapped to "go" so the runtime parses
//     constraints as GolangFormat (which handles Go pseudo-versions like
//     v0.0.0-<timestamp>-<commit>).
//   - `ecosystem_specific.imports` (symbol-level reachability info) is
//     intentionally dropped: grype matches at module granularity and has no
//     way to use per-symbol vulnerability info today.
//   - References pass through with their OSV type as a tag; refID is left
//     empty (the GO records' references don't include the canonical advisory
//     page in `references` — that lives in `database_specific.url`, which we
//     don't synthesize a reference for).
type govulndbStrategy struct{}

func (govulndbStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "GO-")
}

func (govulndbStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	// Withdrawn GO advisories retain their `affected` ranges but should not
	// match user-scanned packages — go.dev periodically withdraws records
	// when an issue is downgraded out of vuln-db scope or duplicated under a
	// different ID. Mirror github's pattern: set Status=Rejected and surface
	// the WithdrawnDate so the matcher's OnlyNonWithdrawnVulnerabilities
	// filter skips them.
	status := db.VulnerabilityActive
	var withdrawnDate *time.Time
	if !vuln.Withdrawn.IsZero() {
		status = db.VulnerabilityRejected
		withdrawnDate = &vuln.Withdrawn
	}

	in := []any{
		db.VulnerabilityHandle{
			Name:          vuln.ID,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			Status:        status,
			ModifiedDate:  &vuln.Modified,
			PublishedDate: &vuln.Published,
			WithdrawnDate: withdrawnDate,
			BlobValue: &db.VulnerabilityBlob{
				ID:          vuln.ID,
				Description: vuln.Details,
				References:  govulndbReferences(vuln),
				Aliases:     vuln.Aliases,
				Severities:  severities,
			},
		},
	}

	for _, aph := range govulndbAffectedPackages(vuln) {
		in = append(in, aph)
	}
	return transformers.NewEntries(in...), nil
}

func govulndbReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func govulndbAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r, govulndbRangeType(r.Type))...)
		}

		// ecosystem_specific.custom_ranges is go.dev's escape hatch for the
		// "+incompatible" case: when a module ships vN tags for N>1 but never
		// moved its path to /vN, go.dev cannot map the source advisory's
		// versions onto canonical Go module semver. Its presence is the signal
		// that the standard `ranges` are an unreliable best-effort artifact, so
		// custom_ranges (which mirrors the advisory's own affected windows, per
		// the record's details text) is authoritative.
		//
		// We do not blindly replace the standard ranges, though: the two often
		// describe *complementary* version namespaces. github.com/grafana
		// /grafana lists +incompatible tags (v6.0.0, v12.0.7) in custom_ranges,
		// while github.com/mattermost/mattermost-server can carry bounded
		// +incompatible tag windows in the standard ranges and pseudo-version
		// windows in custom_ranges. Dropping the standard side entirely would
		// turn the mattermost case into a false negative.
		//
		// The actual false-positive generator is an *open-ended* standard range
		// — a ">= X" lower bound with no fix and no upper bound (a trailing
		// `introduced` event with no matching `fixed`/`last_affected`). go.dev
		// emits these for the unmappable versions (e.g. grafana
		// >= a v1.9.2 pseudo-version, GO-2025-4153), and ">= v1.9.2-pre" matches
		// *every* later release including v11/v12. So when custom_ranges is
		// present we drop only the open-ended standard ranges, keep the bounded
		// ones, and union with custom_ranges. go.dev's own details warn this "is
		// causing false-positive reports from vulnerability scanners."
		if custom := govulndbCustomRanges(affected); len(custom) > 0 {
			ranges = append(dropOpenEndedRanges(ranges), custom...)
		}

		aphs = append(aphs, db.AffectedPackageHandle{
			Package: govulndbPackage(affected.Package),
			BlobValue: &db.PackageBlob{
				CVEs:   vuln.Aliases,
				Ranges: ranges,
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

// dropOpenEndedRanges removes ranges that are unbounded above — a ">= X" lower
// bound with no upper bound — keeping every range that has one. It is applied to
// the *standard* ranges only when custom_ranges is present (see
// govulndbAffectedPackages): in that situation an open-ended standard range is
// go.dev's "couldn't map to Go module semver" artifact and over-matches every
// version above its lower bound, while bounded windows (whether real semver or
// +incompatible tag ranges) stay trustworthy and must be preserved.
func dropOpenEndedRanges(ranges []db.Range) []db.Range {
	var kept []db.Range
	for _, r := range ranges {
		if isUnboundedAbove(r) {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// isUnboundedAbove reports whether a range has a lower bound but no upper bound.
// Normalized constraints always express an upper bound with a "<" token ("< Y",
// ">= X,< Y", or "<= Y" for last_affected); a constraint with no "<" at all is
// open-ended above (e.g. ">= X" from a fix-less trailing introduced event). An
// empty constraint (match-all) is likewise treated as unbounded.
func isUnboundedAbove(r db.Range) bool {
	return !strings.Contains(r.Version.Constraint, "<")
}

// govulndbCustomRanges decodes ecosystem_specific.custom_ranges (the
// source-advisory version windows go.dev couldn't map onto Go module semver)
// into grype ranges. The custom ranges are OSV-shaped (type/events) but carry
// type ECOSYSTEM; we evaluate them with the "go" format regardless, because the
// versions being compared at match time are always Go module versions. Returns
// nil when there are no custom ranges (the affected entry then contributes no
// match, which is the correct outcome for a record that has *no* usable version
// information at all).
func govulndbCustomRanges(affected osvmodel.Affected) []db.Range {
	if affected.EcosystemSpecific == nil {
		return nil
	}
	raw, ok := affected.EcosystemSpecific["custom_ranges"]
	if !ok {
		return nil
	}

	// custom_ranges arrives as []any of map[string]any; round-trip through JSON
	// to reuse the osvmodel.Range shape and the shared range-normalization path.
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var customRanges []osvmodel.Range
	if err := json.Unmarshal(encoded, &customRanges); err != nil {
		return nil
	}

	var ranges []db.Range
	for _, r := range customRanges {
		ranges = append(ranges, getGrypeRangesFromRange(r, "go")...)
	}
	return ranges
}

func govulndbPackage(p osvmodel.Package) *db.Package {
	return &db.Package{
		Ecosystem: string(pkg.GoModulePkg),
		Name:      name.Normalize(p.Name, pkg.GoModulePkg),
	}
}

// govulndbRangeType maps an OSV range type to the grype version-format string
// for Go records. SEMVER maps to "go" so the runtime parses constraints with
// the Go-flavored comparator (it understands v0.0.0-<timestamp>-<hash>
// pseudo-versions, which generic semver does not). Other OSV types fall
// through to the default mapping; in practice govulndb only emits SEMVER.
func govulndbRangeType(t osvmodel.RangeType) string {
	if t == osvmodel.RangeSemVer {
		return "go"
	}
	return defaultRangeType(t)
}
