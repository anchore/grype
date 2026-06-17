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
	"github.com/anchore/grype/grype/db/internal/versionutil"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

// govulndbStrategy handles GO-* records from the Go vulnerability database
// (vuln.go.dev): affected version ranges for Go modules, plus the "stdlib" and
// "toolchain" pseudo-modules. Govulndb specifics:
//   - aliases hold CVEs/GHSAs directly; the schema has no `related` field.
//   - ecosystem is always "Go" → syft go-module type, reached by the matcher's
//     ecosystem-name search.
//   - range type is always SEMVER → "go" format, which parses pseudo-versions
//     (v0.0.0-<timestamp>-<commit>).
//   - ecosystem_specific.imports (per-symbol reachability) is dropped; grype
//     matches at module granularity.
//   - references pass through with their OSV type as a tag; refID stays empty
//     (the canonical advisory page lives in database_specific.url, not refs).
type govulndbStrategy struct{}

func (govulndbStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "GO-")
}

func (govulndbStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	// Withdrawn GO advisories keep their `affected` ranges but must not match.
	// Mirror github: set Status=Rejected and surface WithdrawnDate so the
	// matcher's OnlyNonWithdrawnVulnerabilities filter skips them.
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
		ranges := govulndbAffectedRanges(affected)
		if len(ranges) == 0 {
			// No usable range — e.g. a lone {introduced: "0"} with no fix and no
			// custom_ranges (GO-2024-3240). An affected package with zero ranges
			// matches every version, so skip it rather than emit a match-all. The
			// aliased GHSA carries the real bounds via the github provider.
			continue
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

// govulndbAffectedRanges builds one affected entry's ranges, handling
// ecosystem_specific.custom_ranges.
//
// go.dev writes custom_ranges when a module ships vN tags (N>1) without a /vN
// path and it can't map the advisory's versions to Go module semver. Standard
// ranges and custom_ranges then cover complementary version spaces (grafana
// puts +incompatible tags like v12.0.7 in custom_ranges; mattermost-server
// keeps tag windows in standard ranges and pseudo-version windows in custom),
// so we union them. The exception: an open-ended standard window (">= X", no
// fix) matches every later release — grafana GO-2025-4153 emits ">= a v1.9.2
// pseudo-version" and flags v11/v12 — so drop it once custom_ranges carries the
// real windows.
//
//   - bounded standard window: always kept
//   - open-ended standard window: kept only without custom_ranges
//   - custom_ranges window: always added
func govulndbAffectedRanges(affected osvmodel.Affected) []db.Range {
	custom := govulndbCustomRanges(affected)

	var ranges []db.Range
	for _, r := range affected.Ranges {
		bounded, openEnded := govulndbRanges(r, govulndbRangeType(r.Type))
		ranges = append(ranges, bounded...)
		if len(custom) == 0 {
			ranges = append(ranges, openEnded...)
		}
	}
	return append(ranges, custom...)
}

// govulndbRanges converts one OSV range's events to grype ranges, splitting
// bounded windows (introduced→fixed or introduced→last_affected) from a trailing
// open-ended window (introduced with no close, ">= X"). The caller decides
// whether to keep the open-ended one. rangeType is "go" for Go records.
func govulndbRanges(r osvmodel.Range, rangeType string) (bounded, openEnded []db.Range) {
	if len(r.Events) == 0 {
		return nil, nil
	}
	fixByVersion := extractFixAvailability(r)

	var constraint string
	and := func(c string) {
		if constraint == "" {
			constraint = c
		} else {
			constraint = versionutil.AndConstraints(constraint, c)
		}
	}

	// dupl is suppressed because Go needs its own version of the range parser, but some of the
	// core logic is necessarily the same.
	for _, e := range r.Events { // nolint:dupl
		switch {
		case e.Introduced != "" && e.Introduced != "0":
			constraint = fmt.Sprintf(">= %s", e.Introduced)
		case e.LastAffected != "":
			and(fmt.Sprintf("<= %s", e.LastAffected))
			bounded = append(bounded, db.Range{
				Version: db.Version{Type: rangeType, Constraint: normalizeConstraint(constraint, rangeType)},
			})
			constraint = ""
		case e.Fixed != "":
			var detail *db.FixDetail
			if f, ok := fixByVersion[e.Fixed]; ok {
				detail = &db.FixDetail{Available: &f}
			}
			and(fmt.Sprintf("< %s", e.Fixed))
			bounded = append(bounded, db.Range{
				Fix:     normalizeFix(e.Fixed, detail),
				Version: db.Version{Type: rangeType, Constraint: normalizeConstraint(constraint, rangeType)},
			})
			constraint = ""
		}
	}

	// A leftover lower bound: the range ended on an `introduced` with no
	// `fixed`/`last_affected` — an open-ended ">= X" window.
	if constraint != "" {
		openEnded = append(openEnded, db.Range{
			Version: db.Version{Type: rangeType, Constraint: normalizeConstraint(constraint, rangeType)},
		})
	}
	return bounded, openEnded
}

// govulndbCustomRanges decodes ecosystem_specific.custom_ranges into grype
// ranges. Entries are OSV-shaped but typed ECOSYSTEM; we compare them as "go"
// since matched versions are always Go module versions. custom_ranges is
// authoritative, so every window is kept. Returns nil when absent.
func govulndbCustomRanges(affected osvmodel.Affected) []db.Range {
	if affected.EcosystemSpecific == nil {
		return nil
	}
	raw, ok := affected.EcosystemSpecific["custom_ranges"]
	if !ok {
		return nil
	}

	// custom_ranges arrives as []any of map[string]any; round-trip through JSON
	// into the osvmodel.Range shape.
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
		bounded, openEnded := govulndbRanges(r, "go")
		ranges = append(ranges, bounded...)
		ranges = append(ranges, openEnded...)
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
