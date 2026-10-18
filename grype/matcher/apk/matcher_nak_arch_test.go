package apk

import (
	"testing"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// CGA-sub0-0000-0003 in the chainguard-subpackages fixture is a false positive for "foo" on x86_64 only.

// NAK entries respect the architecture qualifier: an x86_64 false positive does not clear an aarch64 package
func TestMatcherApk_ArchFilter_NakDoesNotApplyToOtherArch(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0003").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("foo", "1.2.3-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.ChainguardRolling).
				WithMetadata(pkg.ApkMetadata{Arch: "aarch64"}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()
			findings.Ignores().IsEmpty()
		})
}
