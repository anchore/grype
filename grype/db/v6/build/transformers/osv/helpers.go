package osv

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/internal/versionutil"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
)

// Shared helpers used by multiple OSV strategies. Per-provider decisions live
// in transform_<provider>.go; only logic that's genuinely identical across
// strategies (range normalization, severity parsing, fix-availability decoding)
// belongs here.

// ============================================================================
// Range normalization
// ============================================================================

// OSV supports flattened ranges, so both formats below are valid:
// "ranges": [
//
//	{
//	  "type": "SEMVER",
//	  "events": [
//	    { "introduced": "12.0.0" },
//	    { "fixed": "12.18.4" }
//	  ]
//	},
//	{
//	  "type": "SEMVER",
//	  "events": [
//	    { "introduced": "14.0.0" },
//	    { "fixed": "14.11.0" }
//	  ]
//	}
//
// ]
// "ranges": [
//
//	{
//	  "type": "SEMVER",
//	  "events": [
//	    { "introduced": "12.0.0" },
//	    { "fixed": "12.18.4" },
//	    { "introduced": "14.0.0" },
//	    { "fixed": "14.11.0" }
//	  ]
//	}
//
// ]
//
// Note on git-typed ranges: this function emits range type "git" but no matcher
// in grype/version can evaluate git-ref constraints, so any range stored as
// Type: "git" is effectively unmatchable at runtime. Preserving current
// pass-through behavior — fixing requires runtime work, not transformer work.
//
// rangeType is the grype-side range-format string (e.g. "rpm", "bitnami",
// "semver") — the caller decides this per-provider, since the same OSV
// RangeType maps differently across providers. See each strategy's own
// rangeType() function in transform_<provider>.go.
func getGrypeRangesFromRange(r osvmodel.Range, rangeType string) []db.Range {
	return eventsToRanges(r.Events, extractFixAvailability(r), rangeType)
}

// eventsToRanges converts an OSV event stream into grype ranges, one per window:
// `introduced` opens a window, `fixed`/`last_affected` closes it, a trailing
// unclosed `introduced` becomes open-ended ">= X". `fixes` keys fix-availability
// dates by fixed version; `rangeType` is the caller's version format.
//
// OSV treats "one range, N windows" and "N ranges, one window each" alike, so
// callers may pre-flatten ranges into one slice.
func eventsToRanges(events []osvmodel.Event, fixes map[string]db.FixAvailability, rangeType string) []db.Range {
	var ranges []db.Range
	var constraint string

	and := func(c string) {
		if constraint == "" {
			constraint = c
		} else {
			constraint = versionutil.AndConstraints(constraint, c)
		}
	}
	emit := func(fix *db.Fix) {
		ranges = append(ranges, db.Range{
			Fix:     fix,
			Version: db.Version{Type: rangeType, Constraint: normalizeConstraint(constraint, rangeType)},
		})
		constraint = ""
	}

	for _, e := range events {
		switch {
		case e.Introduced != "" && e.Introduced != "0":
			constraint = fmt.Sprintf(">= %s", e.Introduced)
		case e.LastAffected != "":
			and(fmt.Sprintf("<= %s", e.LastAffected))
			emit(nil)
		case e.Fixed != "":
			and(fmt.Sprintf("< %s", e.Fixed))
			var detail *db.FixDetail
			if f, ok := fixes[e.Fixed]; ok {
				detail = &db.FixDetail{Available: &f}
			}
			emit(normalizeFix(e.Fixed, detail))
		}
	}
	if constraint != "" {
		emit(nil) // trailing `introduced` with no upper bound
	}
	return ranges
}

// getGrypeUnaffectedRangesFromRange inverts the OSV range events into
// "unaffected" ranges for advisory records. rangeType is the grype-side format
// string supplied by the calling strategy (see strategy rangeType() helpers).
func getGrypeUnaffectedRangesFromRange(r osvmodel.Range, rangeType string) []db.Range {
	if len(r.Events) == 0 {
		return nil
	}
	fixByVersion := extractFixAvailability(r)
	return buildUnaffectedRangesFromEvents(r.Events, fixByVersion, rangeType)
}

func normalizeConstraint(constraint string, rangeType string) string {
	// Go versions are semver-shaped (with optional "v"/"go" prefix the parser
	// strips); multi-window ranges built via versionutil.AndConstraints use
	// space-separated form which the Go constraint parser rejects. Apply the
	// same comma-separated normalization that semver/bitnami get.
	if rangeType == "semver" || rangeType == "bitnami" || rangeType == "go" {
		return versionutil.EnforceSemVerConstraint(constraint)
	}
	return constraint
}

func normalizeFix(fix string, detail *db.FixDetail) *db.Fix {
	fixedInVersion := versionutil.CleanFixedInVersion(fix)
	fixState := db.NotFixedStatus
	if len(fixedInVersion) > 0 {
		fixState = db.FixedStatus
	}
	return &db.Fix{
		State:   fixState,
		Version: fixedInVersion,
		Detail:  detail,
	}
}

// defaultRangeType is the generic OSV range-type → grype format mapping with
// no provider-specific overrides. Strategies use this as the fallback for OSV
// range types they don't have a special interpretation for.
func defaultRangeType(t osvmodel.RangeType) string {
	switch t {
	case osvmodel.RangeSemVer, osvmodel.RangeEcosystem, osvmodel.RangeGit:
		return strings.ToLower(string(t))
	default:
		return "unknown"
	}
}

// ============================================================================
// Fix-availability decoding (database_specific.anchore.fixes)
// ============================================================================

func extractFixAvailability(r osvmodel.Range) map[string]db.FixAvailability {
	fixByVersion := make(map[string]db.FixAvailability)

	dbSpecific, ok := r.DatabaseSpecific["anchore"]
	if !ok {
		return fixByVersion
	}
	anchoreInfo, ok := dbSpecific.(map[string]any)
	if !ok {
		return fixByVersion
	}
	fixes, ok := anchoreInfo["fixes"]
	if !ok {
		return fixByVersion
	}
	fixList, ok := fixes.([]any)
	if !ok {
		return fixByVersion
	}
	for _, fixEntry := range fixList {
		parseSingleFixEntry(fixEntry, fixByVersion)
	}
	return fixByVersion
}

func parseSingleFixEntry(fixEntry any, fixByVersion map[string]db.FixAvailability) {
	fixMap, ok := fixEntry.(map[string]any)
	if !ok {
		return
	}
	version, vOk := fixMap["version"].(string)
	kind, kOk := fixMap["kind"].(string)
	date, dOk := fixMap["date"].(string)
	if vOk && kOk && dOk {
		fixByVersion[version] = db.FixAvailability{
			Date: internal.ParseTime(date),
			Kind: kind,
		}
	}
}

func buildUnaffectedRangesFromEvents(events []osvmodel.Event, fixByVersion map[string]db.FixAvailability, rangeType string) []db.Range {
	var ranges []db.Range
	for _, e := range events {
		if e.Fixed != "" {
			ranges = append(ranges, createUnaffectedRange(e.Fixed, fixByVersion, rangeType))
		}
	}
	return ranges
}

func createUnaffectedRange(fixedVersion string, fixByVersion map[string]db.FixAvailability, rangeType string) db.Range {
	var detail *db.FixDetail
	if f, ok := fixByVersion[fixedVersion]; ok {
		detail = &db.FixDetail{Available: &f}
	}
	constraint := fmt.Sprintf(">= %s", fixedVersion)
	return db.Range{
		Fix: normalizeFix(fixedVersion, detail),
		Version: db.Version{
			Type:       rangeType,
			Constraint: normalizeConstraint(constraint, rangeType),
		},
	}
}

// ============================================================================
// Severity / CVSS
// ============================================================================

var cvssPattern = regexp.MustCompile(`^CVSS:(\d+\.\d+)/(.+)$`)

func extractCVSSInfo(cvss string) (string, string, error) {
	matches := cvssPattern.FindStringSubmatch(cvss)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid CVSS format")
	}
	return matches[1], matches[0], nil
}

func normalizeSeverity(severity osvmodel.Severity) (db.Severity, error) {
	switch severity.Type {
	case osvmodel.SeverityCVSSV2, osvmodel.SeverityCVSSV3, osvmodel.SeverityCVSSV4:
		version, vector, err := extractCVSSInfo(severity.Score)
		if err != nil {
			return db.Severity{}, err
		}
		return db.Severity{
			Scheme: db.SeveritySchemeCVSS,
			Value: db.CVSSSeverity{
				Vector:  vector,
				Version: version,
			},
		}, nil
	default:
		return db.Severity{
			Scheme: db.UnknownSeverityScheme,
			Value:  severity.Score,
		}, nil
	}
}

func getSeverities(vuln unmarshal.OSVVulnerability) ([]db.Severity, error) {
	var severities []db.Severity
	for _, sev := range vuln.Severity {
		severity, err := normalizeSeverity(sev)
		if err != nil {
			return nil, err
		}
		severities = append(severities, severity)
	}
	for _, affected := range vuln.Affected {
		for _, sev := range affected.Severity {
			severity, err := normalizeSeverity(sev)
			if err != nil {
				return nil, err
			}
			severities = append(severities, severity)
		}
	}
	return severities, nil
}
