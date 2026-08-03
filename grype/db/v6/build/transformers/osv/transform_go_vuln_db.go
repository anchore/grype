package osv

import (
	"fmt"
	"maps"
	"regexp"
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
//   - ecosystem_specific.imports is carried into the package blob as a go-imports
//     qualifier, so packages cataloged with symbol evidence
//     only match when at least one vulnerable symbol is present.
//   - references pass through, OSV type as tag, refID empty (canonical advisory
//     page is in database_specific.url, not refs).
//   - overlap with GHSA-sourced advisories for the same modules is reconciled by the
//     goVulnDBMerger; see handleEntry in govulndb_merge.go.
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
				ID:          vuln.ID,
				Description: vuln.Details,
				References:  govulndbReferences(vuln),
				Aliases:     vuln.Aliases,
				Severities:  severities,
			},
		},
	}

	in = append(in, affected...)
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

func govulndbAffectedPackages(vuln unmarshal.OSVVulnerability) []any {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	// replacements carries the pseudo-version reconciliation context per package, keyed by the
	// blob pointer since sorting below reorders the handles
	replacements := make(map[*db.PackageBlob]transformers.GoVulnDBAffectedPackage)
	for _, affected := range vuln.Affected {
		var qualifiers *db.PackageQualifiers
		if imports := govulndbImports(affected, vuln.ID); len(imports) > 0 {
			qualifiers = &db.PackageQualifiers{GoImports: imports}
		}
		custom := govulndbCustomRanges(affected, vuln.ID)
		blob := &db.PackageBlob{
			CVEs:       vuln.Aliases,
			Qualifiers: qualifiers,
			Ranges:     govulndbRanges(affected.Ranges, custom),
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			Package:   govulndbPackage(affected.Package),
			BlobValue: blob,
		})
		if pseudoFix, customRanges := pseudoVersionReplacement(affected.Ranges, custom); pseudoFix != "" {
			replacements[blob] = transformers.GoVulnDBAffectedPackage{
				PseudoVersionFix: pseudoFix,
				CustomRanges:     customRanges,
			}
		}
	}
	sort.Sort(internal.ByAffectedPackage(aphs))

	out := make([]any, 0, len(aphs))
	for _, aph := range aphs {
		if wrapped, ok := replacements[aph.BlobValue]; ok {
			wrapped.Handle = aph
			out = append(out, wrapped)
			continue
		}
		out = append(out, aph)
	}
	return out
}

// goPseudoVersionPattern matches Go pseudo-version suffixes: a 14-digit commit timestamp and a
// 12-hex-digit commit hash (e.g. "0.0.0-20240708073652-5a492a3f0036"), optionally followed by
// "+incompatible".
var goPseudoVersionPattern = regexp.MustCompile(`-\d{14}-[0-9a-f]{12}(\+incompatible)?$`)

func isGoPseudoVersion(v string) bool {
	return goPseudoVersionPattern.MatchString(v)
}

// pseudoVersionReplacement recognizes the record shape where the standard range pins the fix to
// a Go pseudo-version while ecosystem_specific.custom_ranges carries the same fix in the
// module's real (tag) version
// e.g. GO-2024-3312 (lxd): standard fixed
// 0.0.0-20240708073652-5a492a3f0036, custom fixed 5.21.2. The govulndb↔GHSA merge
// uses the returned pairing to replace an aliased GHSA range still pinned to the pseudo-version
// (which can never match a real tagged release) with the custom fixed version.
//
// Deliberately strict, per the spec: exactly one standard range whose only end is a
// single pseudo-version fix, and exactly one custom range that is bounded and free of
// pseudo-versions. If there are more ranges on either side there is no way to know which
// pairs with which, so no pairing is reported.
func pseudoVersionReplacement(standard, custom []osvmodel.Range) (pseudoFix string, replacement []db.Range) {
	if len(standard) != 1 || len(custom) != 1 {
		return "", nil
	}
	var fixes []string
	for _, e := range standard[0].Events {
		if e.LastAffected != "" {
			return "", nil
		}
		if e.Fixed != "" {
			fixes = append(fixes, e.Fixed)
		}
	}
	if len(fixes) != 1 || !isGoPseudoVersion(fixes[0]) {
		return "", nil
	}
	if !hasUpperBound(custom[0].Events) {
		return "", nil
	}
	for _, e := range custom[0].Events {
		if isGoPseudoVersion(e.Introduced) || isGoPseudoVersion(e.Fixed) || isGoPseudoVersion(e.LastAffected) {
			return "", nil
		}
	}
	replacement = eventsToRanges(custom[0].Events, fixDates(custom), "go")
	if len(replacement) == 0 {
		return "", nil
	}
	return fixes[0], replacement
}

// govulndbRanges builds the affected ranges for one affected entry from its
// standard OSV ranges and ecosystem_specific.custom_ranges.
//
// Without custom_ranges, standard ranges pass through: bounded windows; a
// trailing open-ended ">= X" (a real unfixed vuln, e.g. GO-2024-2584's >=0.50.0);
// or a lone introduced:0, which yields no ranges so grype treats every version as
// vulnerable (GO-2024-3240).
func govulndbRanges(standard, custom []osvmodel.Range) []db.Range {
	standardRanges := eventsToRanges(flattenEvents(standard), fixDates(standard), "go")
	if len(custom) == 0 {
		return standardRanges
	}

	merged := mergeWithCustom(flattenEvents(standard), flattenEvents(custom))
	customRanges := eventsToRanges(merged, fixDates(standard, custom), "go")

	// custom_ranges must not erase the standard range: an affected package with no
	// ranges matches *every* version, so dropping the standard here would
	// silently widen matching instead of narrowing it.
	if len(customRanges) == 0 {
		return standardRanges
	}
	return customRanges
}

// mergeWithCustom combines a standard range's events with custom_ranges' events.
// go.dev writes custom_ranges only for the "+incompatible" case the standard range is one of:
//   - bare "introduced: 0": says nothing, so use custom as-is (GO-2024-2513).
//   - open-ended floor (">= X", no fix): X is the real lower bound; graft it onto
//     custom (GO-2024-2858 → "[5.0.0-beta1,8.5.14) ||
//     [9.0.0,9.1.8)", matching the GHSA). See withFloor.
//   - bounded: keep and union with custom.
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
// placeholder go.dev emits when it cannot map affected versions
func isDefaultFloorOnly(events []osvmodel.Event) bool {
	return len(events) == 1 && events[0].Introduced == "0"
}

// hasUpperBound reports whether any event closes a window (fixed/last_affected).
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
			maps.Copy(out, extractFixAvailability(r))
		}
	}
	return out
}

// govulndbCustomRanges decodes ecosystem_specific.custom_ranges into OSV ranges. They are
// OSV-shaped but carry type ECOSYSTEM. Nil if absent or undecodable, so malformed
// custom_ranges degrades to standard-only matching instead of erroring.
func govulndbCustomRanges(affected osvmodel.Affected, id string) []osvmodel.Range {
	var ranges []osvmodel.Range
	if !decodeEcosystemSpecific(affected, "custom_ranges", id, &ranges) {
		return nil
	}
	return ranges
}

// govulndbImports extracts the affected package import paths and vulnerable symbols from the
// OSV `ecosystem_specific.imports` field (see https://go.dev/security/vuln/database#schema).
// Nil if absent or undecodable, so malformed imports degrade to module-granularity matching
// instead of erroring.
func govulndbImports(affected osvmodel.Affected, id string) []db.GoImport {
	var imports []db.GoImport
	if !decodeEcosystemSpecific(affected, "imports", id, &imports) {
		return nil
	}
	return imports
}

// decodeEcosystemSpecific decodes one ecosystem_specific field into out (a pointer to a slice),
// reporting success. mapstructure reuses the `json` tags to avoid re-serializing. Absent or
// undecodable data returns false (logged), so callers degrade gracefully instead of erroring.
func decodeEcosystemSpecific(affected osvmodel.Affected, key, id string, out any) bool {
	raw, ok := affected.EcosystemSpecific[key]
	if !ok {
		return false
	}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  out,
		TagName: "json",
	})
	if err != nil {
		return false
	}
	if err := decoder.Decode(raw); err != nil {
		log.WithFields("id", id, "package", affected.Package.Name, "field", key, "error", err).
			Warn("unable to decode govulndb ecosystem_specific field; matching without it")
		return false
	}
	return true
}

func govulndbPackage(p osvmodel.Package) *db.Package {
	return &db.Package{
		Ecosystem: string(pkg.GoModulePkg),
		Name:      name.Normalize(p.Name, pkg.GoModulePkg),
	}
}
