package bitnami

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcher exercises the bitnami matcher against a curated fixture of
// real BIT-* records across three components (spark, apache, node) covering
// the three OSV range shapes bitnami actually emits:
//
//   - Simple [introduced=0, fixed)              — BIT-spark-2023-22946
//   - Multiple disjoint introduced/fixed windows — BIT-spark-2022-31777, BIT-node-2020-8201
//   - introduced + last_affected (inclusive)     — BIT-apache-2020-11984
//
// Spark 3.2.4 is the canonical version used by the bitnami quality gate
// (ghcr.io/anchore/test-images/bitnami/spark:3.2.4-debian-11-r8); it lands
// in the safe gap of BIT-spark-2022-31777 but is still vulnerable to
// BIT-spark-2023-22946, giving a TP/FP mix on real-world inputs.
//
// The redis case is a cross-contamination check: the fixture contains no
// redis records, so the matcher must produce zero matches even though other
// components in the same DB do match.
//
// Matches are reported under the BIT-* record ID (the OSV record's primary
// id) with the CVE recorded as an alias on the vulnerability blob.
func TestMatcher(t *testing.T) {
	tests := []struct {
		name     string
		pkgName  string
		version  string
		expected []string // expected BIT-* IDs in matches; nil/empty asserts IsEmpty
	}{
		{
			name:     "spark 3.2.1 below all fixes — TP on both spark CVEs",
			pkgName:  "spark",
			version:  "3.2.1",
			expected: []string{"BIT-spark-2022-31777", "BIT-spark-2023-22946"},
		},
		{
			name:     "spark 3.2.4 (quality-gate version) — safe gap of 31777, still vulnerable to 22946",
			pkgName:  "spark",
			version:  "3.2.4",
			expected: []string{"BIT-spark-2023-22946"},
		},
		{
			name:     "spark 3.3.0 — second vulnerable window of 31777, still below 22946 fix",
			pkgName:  "spark",
			version:  "3.3.0",
			expected: []string{"BIT-spark-2022-31777", "BIT-spark-2023-22946"},
		},
		{
			name:     "spark 3.4.1 — above all spark fixes",
			pkgName:  "spark",
			version:  "3.4.1",
			expected: nil,
		},
		{
			name:     "apache 2.4.40 — inside last_affected window of 11984; above 11985 fix",
			pkgName:  "apache",
			version:  "2.4.40",
			expected: []string{"BIT-apache-2020-11984"},
		},
		{
			name:     "apache 2.4.10 — in 11985 window; below 11984 floor (2.4.32)",
			pkgName:  "apache",
			version:  "2.4.10",
			expected: []string{"BIT-apache-2020-11985"},
		},
		{
			name:     "apache 2.4.50 — above both apache fixes",
			pkgName:  "apache",
			version:  "2.4.50",
			expected: nil,
		},
		{
			name:     "node 12.18.0 — in 12.x vulnerable window of 8201",
			pkgName:  "node",
			version:  "12.18.0",
			expected: []string{"BIT-node-2020-8201"},
		},
		{
			name:     "node 12.18.4 at fix — no match",
			pkgName:  "node",
			version:  "12.18.4",
			expected: nil,
		},
		{
			name:     "redis 7.0.0 — no redis records in fixture, no cross-contamination",
			pkgName:  "redis",
			version:  "7.0.0",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbtest.DBs(t, "bitnami").Run(func(t *testing.T, db *dbtest.DB) {
				matcher := &Matcher{}

				p := dbtest.NewPackage(tt.pkgName, tt.version, syftPkg.BitnamiPkg).
					WithPURL("pkg:bitnami/" + tt.pkgName + "@" + tt.version).
					Build()

				findings := db.Match(t, matcher, p)

				if len(tt.expected) == 0 {
					findings.IsEmpty()
					return
				}

				for _, id := range tt.expected {
					findings.SelectMatch(id).
						SelectDetailByType(match.ExactDirectMatch).
						AsEcosystemSearch()
				}
			})
		})
	}
}
