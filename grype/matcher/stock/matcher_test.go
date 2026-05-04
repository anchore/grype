package stock

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcher_JVMPackage exercises the stock matcher's CPE-based path
// against an Oracle Java SE binary package. The fixture carries the real
// NVD CVE-2024-20919 record, whose multi-branch JVM range covers
// java_se 1.8.0_400 (and its JEP-223 form 8.0.400). The detailed
// JVM-format constraint edge cases (pre-/post-JEP-223 comparisons,
// pre-release suffixes, etc.) live in grype/version/jvm_version_test.go;
// this test guarantees the stock matcher correctly hands a JVM CPE off
// to that constraint logic and emits a CPEMatch detail.
func TestMatcher_JVMPackage(t *testing.T) {
	dbtest.DBs(t, "oracle-java-se").
		SelectOnly("CVE-2024-20919").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := NewStockMatcher(MatcherConfig{UseCPEs: true})

			p := dbtest.NewPackage("java_se", "1.8.0_400", syftPkg.BinaryPkg).Build()
			p.CPEs = []cpe.CPE{
				cpe.Must("cpe:2.3:a:oracle:java_se:1.8.0:update400:*:*:*:*:*:*", cpe.DeclaredSource),
			}

			db.Match(t, matcher, p).
				SelectMatch("CVE-2024-20919").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
		})
}
