package osv

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// govulndbStrategy handles GO-* records from the Go vulnerability database
// (vuln.go.dev): affected version ranges for Go modules, plus the "stdlib" and
// "toolchain" pseudo-modules. Govulndb specifics:
//   - aliases hold CVEs/GHSAs directly; the schema has no `related` field.
//   - ecosystem is always "Go" → syft go-module type, found by the matcher's
//     ecosystem-name search.
//   - range type is always SEMVER → "go" format, which parses pseudo-versions
//     (v0.0.0-<timestamp>-<commit>).
//   - ecosystem_specific.imports (per-symbol reachability) is carried into the
//     package blob as a go-imports qualifier, so packages cataloged with symbol evidence
//     only match when at least one vulnerable symbol is present.
//   - references pass through, OSV type as tag, refID empty (canonical advisory
//     page is in database_specific.url, not refs).
//   - database_specific.review_status is carried onto the vulnerability blob so
//     UNREVIEWED records that survive to the DB are identifiable.
//
// Most third-party (and golang.org/x/*) packages have duplicate advisories grype
// gets from GHSA; the build writer patchesthe aliased GHSA records with GoVuln symbol information
// and drops the GoVuln duplicate affected packages. Only packages absent from GHSA are written under
// the GO-* record. See the writer's handleGoVulnDBEntry.
type govulndbStrategy struct{}

func (govulndbStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "GO-")
}

func (govulndbStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	affected := govulndbAffectedPackages(vuln)
	if len(affected) == 0 {
		// no affected packages: emitting just the vulnerability handle would write
		// an orphaned record that can never match a package, so skip the advisory.
		return nil, nil
	}

	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	// Withdrawn GO advisories keep their `affected` ranges but must not match.
	// Like github: Status=Rejected plus WithdrawnDate, which the matcher's
	// OnlyNonWithdrawnVulnerabilities filter skips.
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
				ID:           vuln.ID,
				Description:  vuln.Details,
				References:   govulndbReferences(vuln),
				Aliases:      vuln.Aliases,
				Severities:   severities,
				ReviewStatus: govulndbReviewStatus(vuln),
			},
		},
	}

	for _, aph := range affected {
		in = append(in, aph)
	}
	return transformers.NewEntries(in...), nil
}

// govulndbReviewStatus extracts database_specific.review_status ("REVIEWED" or
// "UNREVIEWED"). Returns "" when absent, leaving the blob field empty.
func govulndbReviewStatus(vuln unmarshal.OSVVulnerability) string {
	if vuln.DatabaseSpecific == nil {
		return ""
	}
	status, _ := vuln.DatabaseSpecific["review_status"].(string)
	return status
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
		var qualifiers *db.PackageQualifiers
		if imports := govulndbImports(affected, vuln.ID); len(imports) > 0 {
			qualifiers = &db.PackageQualifiers{GoImports: imports}
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			Package: govulndbPackage(affected.Package),
			BlobValue: &db.PackageBlob{
				CVEs:       vuln.Aliases,
				Qualifiers: qualifiers,
				Ranges:     govulndbRanges(affected.Ranges, govulndbCustomRanges(affected, vuln.ID)),
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

// govulndbRanges builds the affected ranges for one affected entry from its
// standard OSV ranges and ecosystem_specific.custom_ranges.
//
// Without custom_ranges, standard ranges pass through: bounded windows; a
// trailing open-ended ">= X" (a real unfixed vuln, e.g. GO-2024-2584's >=0.50.0);
// or a lone introduced:0, which yields no ranges so grype treats every version as
// vulnerable (GO-2024-3240). With custom_ranges, mergeWithCustom combines them;
// custom supersedes only when it yields windows, so malformed/windowless custom
// never widens matching. Conversion runs in eventsToRanges (helpers.go).
func govulndbRanges(standard, custom []osvmodel.Range) []db.Range {
	standardRanges := eventsToRanges(flattenEvents(standard), fixDates(standard), "go")
	if len(custom) == 0 {
		return standardRanges
	}

	merged := mergeWithCustom(flattenEvents(standard), flattenEvents(custom))
	customRanges := eventsToRanges(merged, fixDates(standard, custom), "go")

	// custom_ranges supersedes the standard range only when it is semantically
	// useful — when it actually yields version windows. A malformed or windowless
	// custom_ranges must not erase the standard range: an affected package with no
	// ranges matches *every* version, so dropping the standard windows here would
	// silently widen matching instead of narrowing it.
	if len(customRanges) == 0 {
		return standardRanges
	}
	return customRanges
}

// mergeWithCustom combines a standard range's events with custom_ranges' events.
// go.dev writes custom_ranges only for the "+incompatible" case (a module ships
// vN tags, N>1, without a /vN path), so the standard range is one of:
//   - bare "introduced: 0": says nothing, so use custom as-is (GO-2024-2513).
//   - open-ended floor (">= X", no fix): X is the real lower bound; graft it onto
//     custom's leading window (GO-2024-2858 → "[5.0.0-beta1,8.5.14) ||
//     [9.0.0,9.1.8)", matching the GHSA). See withFloor.
//   - bounded windows: keep and union with custom. When custom is itself a
//     bounded window they're disjoint and span different namespaces (mattermost:
//     tag windows standard, pseudo-version windows custom), so append. But when
//     custom is an open-ended floor (">= X", no fix) it is the real lower bound
//     for the standard window — a +incompatible introduced that standard SEMVER
//     records as the placeholder introduced:0 — so graft it on rather than append
//     it as a disjoint trailing window (anchore/grype#3520: docker/cli
//     GO-2026-4610 was emitting "<29.2.0+incompatible || >=19.03.0+incompatible",
//     re-matching every release after the fix). Drop the standard's own trailing
//     open-ended window either way; it over-matches later releases.
func mergeWithCustom(standardEvents, customEvents []osvmodel.Event) []osvmodel.Event {
	switch {
	case isDefaultFloorOnly(standardEvents):
		return customEvents
	case !hasUpperBound(standardEvents):
		return withFloor(customEvents, firstIntroduced(standardEvents))
	case !hasUpperBound(customEvents):
		return withFloor(boundedEvents(standardEvents), firstIntroduced(customEvents))
	default:
		return append(boundedEvents(standardEvents), customEvents...)
	}
}

// isDefaultFloorOnly reports whether events are exactly the bare "introduced: 0"
// placeholder go.dev emits when it cannot map affected versions — a standard
// range that, on its own, matches every version.
func isDefaultFloorOnly(events []osvmodel.Event) bool {
	return len(events) == 1 && events[0].Introduced == "0"
}

// hasUpperBound reports whether any event closes a window (fixed/last_affected).
// When none do, the standard range is an open-ended floor.
func hasUpperBound(events []osvmodel.Event) bool {
	for _, e := range events {
		if e.Fixed != "" || e.LastAffected != "" {
			return true
		}
	}
	return false
}

// firstIntroduced returns the first non-empty introduced version, or "".
func firstIntroduced(events []osvmodel.Event) string {
	for _, e := range events {
		if e.Introduced != "" {
			return e.Introduced
		}
	}
	return ""
}

// withFloor raises the first window's lower bound to floor, overwriting a leading
// introduced:0 with the standard range's real introduction. A floor of "0", or a
// window that already names introduced, leaves events unchanged.
func withFloor(events []osvmodel.Event, floor string) []osvmodel.Event {
	if floor == "" || floor == "0" {
		return events
	}
	out := append([]osvmodel.Event(nil), events...)
	for i := range out {
		if out[i].Introduced == "" {
			continue
		}
		if out[i].Introduced == "0" {
			out[i].Introduced = floor
		}
		break // only the first window takes the floor
	}
	return out
}

// flattenEvents concatenates the events of every range into one stream. OSV
// treats "one range with N windows" and "N ranges with one window each" as
// equivalent, so this is faithful.
func flattenEvents(ranges []osvmodel.Range) []osvmodel.Event {
	var out []osvmodel.Event
	for _, r := range ranges {
		out = append(out, r.Events...)
	}
	return out
}

// boundedEvents keeps the events up to and including the last fixed/last_affected,
// dropping a trailing `introduced` that nothing closes — the open-ended ">= X"
// window. Used in the merge, where custom_ranges supersedes such windows.
func boundedEvents(evts []osvmodel.Event) []osvmodel.Event {
	lastClose := -1
	for i, e := range evts {
		if e.Fixed != "" || e.LastAffected != "" {
			lastClose = i
		}
	}
	return evts[:lastClose+1]
}

// fixDates collects fix-availability dates (database_specific.anchore.fixes),
// keyed by fixed version, across all given range groups. The vunnel govulndb
// provider attaches these to the standard ranges; custom_ranges carry none.
func fixDates(rangeGroups ...[]osvmodel.Range) map[string]db.FixAvailability {
	out := map[string]db.FixAvailability{}
	for _, ranges := range rangeGroups {
		for _, r := range ranges {
			for v, f := range extractFixAvailability(r) {
				out[v] = f
			}
		}
	}
	return out
}

// govulndbCustomRanges decodes ecosystem_specific.custom_ranges into OSV ranges.
// They are OSV-shaped but carry type ECOSYSTEM; mapstructure reuses the `json`
// tags to avoid re-serializing. Returns nil if absent or undecodable (logged),
// so malformed custom_ranges degrades to standard-only matching instead of
// erroring.
func govulndbCustomRanges(affected osvmodel.Affected, id string) []osvmodel.Range {
	if affected.EcosystemSpecific == nil {
		return nil
	}
	raw, ok := affected.EcosystemSpecific["custom_ranges"]
	if !ok {
		return nil
	}

	var ranges []osvmodel.Range
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &ranges,
		TagName: "json",
	})
	if err != nil {
		return nil
	}
	if err := decoder.Decode(raw); err != nil {
		log.WithFields("id", id, "package", affected.Package.Name, "error", err).
			Warn("unable to decode govulndb custom_ranges; matching on standard ranges only")
		return nil
	}
	return ranges
}

// govulndbImports extracts the affected package import paths and vulnerable symbols from the
// OSV `ecosystem_specific.imports` field (see https://go.dev/security/vuln/database#schema).
// Returns nil if absent or undecodable (logged), so malformed imports degrade to module-
// granularity matching instead of erroring.
func govulndbImports(affected osvmodel.Affected, id string) []db.GoImport {
	raw, ok := affected.EcosystemSpecific["imports"]
	if !ok {
		return nil
	}

	var imports []db.GoImport
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &imports,
		TagName: "json",
	})
	if err != nil {
		return nil
	}
	if err := decoder.Decode(raw); err != nil {
		log.WithFields("id", id, "package", affected.Package.Name, "error", err).
			Warn("unable to decode govulndb imports; matching at module granularity")
		return nil
	}
	return imports
}

func govulndbPackage(p osvmodel.Package) *db.Package {
	return &db.Package{
		Ecosystem: string(pkg.GoModulePkg),
		Name:      name.Normalize(p.Name, pkg.GoModulePkg),
	}
}
