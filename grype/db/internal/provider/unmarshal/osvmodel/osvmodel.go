// Package osvmodel is grype's hand-maintained, JSON-tagged Go model for the
// subset of OSV records consumed by the v6 OSV transformers. It supersedes
// the previous dependency on github.com/google/osv-scanner/pkg/models, which
// upstream stopped maintaining and which lacked the top-level Upstream field
// that Canonical (and other providers) now emit.
//
// Scope: the fields, enums, and shapes that transformers in
// grype/db/v6/build/transformers/osv actually read. Anything OSV defines but
// grype does not consume (credits, withdrawn-reason metadata, full
// database_specific schemas, etc.) is intentionally omitted. Add a field here
// only when a transformer needs to read it.
//
// Extension points (database_specific, ecosystem_specific) stay as
// map[string]any on the wire so unknown keys round-trip without code changes.
// Typed access to the grype-owned "anchore" overlay lives in this package
// (see anchore.go); per-vendor extensions belong next to the strategy that
// reads them.
//
// Source of truth: https://ossf.github.io/osv-schema/
package osvmodel

import "time"

// Vulnerability is the OSV record root. The field set is a subset of the full
// schema plus Upstream — a top-level provider extension Canonical emits and
// that osv-scanner@v1.9.2's pkg/models did not yet carry.
type Vulnerability struct {
	SchemaVersion    string         `json:"schema_version,omitempty"`
	ID               string         `json:"id"`
	Modified         time.Time      `json:"modified"`
	Published        time.Time      `json:"published,omitempty"`
	Withdrawn        time.Time      `json:"withdrawn,omitempty"`
	Aliases          []string       `json:"aliases,omitempty"`
	Related          []string       `json:"related,omitempty"`
	Upstream         []string       `json:"upstream,omitempty"`
	Summary          string         `json:"summary,omitempty"`
	Details          string         `json:"details,omitempty"`
	Affected         []Affected     `json:"affected,omitempty"`
	Severity         []Severity     `json:"severity,omitempty"`
	References       []Reference    `json:"references,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

type Affected struct {
	Package           Package        `json:"package,omitempty"`
	Severity          []Severity     `json:"severity,omitempty"`
	Ranges            []Range        `json:"ranges,omitempty"`
	Versions          []string       `json:"versions,omitempty"`
	DatabaseSpecific  map[string]any `json:"database_specific,omitempty"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific,omitempty"`
}

type Package struct {
	Ecosystem Ecosystem `json:"ecosystem"`
	Name      string    `json:"name"`
	Purl      string    `json:"purl,omitempty"`
}

type Range struct {
	Type             RangeType      `json:"type"`
	Events           []Event        `json:"events"`
	Repo             string         `json:"repo,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Severity struct {
	Type  SeverityType `json:"type"`
	Score string       `json:"score"`
}

type Reference struct {
	Type ReferenceType `json:"type"`
	URL  string        `json:"url"`
}

// Ecosystem stays an open string type: the OSV schema admits provider-defined
// values ("Ubuntu:24.04:LTS", "Root:Alpine:3.18", "AlmaLinux:9", ...) so a
// closed enum would force every new ecosystem to land here before a
// transformer could read it.
type Ecosystem string

// RangeType is enumerated — OSV defines a closed set and transformers switch
// on it. Unknown values still round-trip as their string form, so an upstream
// addition does not silently coerce into a known type.
type RangeType string

const (
	RangeSemVer    RangeType = "SEMVER"
	RangeEcosystem RangeType = "ECOSYSTEM"
	RangeGit       RangeType = "GIT"
)

type SeverityType string

const (
	SeverityCVSSV2 SeverityType = "CVSS_V2"
	SeverityCVSSV3 SeverityType = "CVSS_V3"
	SeverityCVSSV4 SeverityType = "CVSS_V4"
)

// ReferenceType is a typed alias rather than an enum: only the variants
// transformers branch on are named (currently just ADVISORY). Other values
// still round-trip via the string form; add a constant when a strategy needs
// to test for one.
type ReferenceType string

const ReferenceAdvisory ReferenceType = "ADVISORY"
