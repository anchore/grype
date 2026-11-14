package apk

import (
	"testing"

	"github.com/anchore/grype/grype/internal/ignorereasons"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The chainguard-resolved-and-open fixture holds Chainguard OSV entries for the package "bar", one entry per
// advisory. Chainguard's OSV feed publishes each advisory as its own entry, so one package can carry a resolved
// entry (a false positive or a fix) about one of its files and an open entry about another file, both for the
// same vulnerability.

func barPackage(id pkg.ID) pkg.Package {
	return dbtest.NewPackage("bar", "1.0.0-r2", syftPkg.ApkPkg).
		WithID(id).
		WithDistro(dbtest.ChainguardRolling).
		WithMetadata(pkg.ApkMetadata{Arch: "x86_64"}).
		Build()
}

// an open entry keeps the findings on files the package owns when a false positive for the same vulnerability
// exists on the package: no ignore is built for that vulnerability
func TestMatcherApk_OpenEntryKeepsOwnedFindingsOverFalsePositive(t *testing.T) {
	dbtest.DBs(t, "chainguard-resolved-and-open").
		SelectOnly("chainguard:rolling/CGA-res0-0000-0001", "chainguard:rolling/CGA-res0-0000-0002").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			findings := db.Match(t, &matcher, barPackage(pkg.ID("bar-fp-and-open")))
			findings.SelectMatch("CGA-res0-0000-0002").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
			findings.Ignores().IsEmpty()
		})
}

// an open entry keeps the findings on files the package owns when a fix for the same vulnerability exists on
// the package
func TestMatcherApk_OpenEntryKeepsOwnedFindingsOverFix(t *testing.T) {
	dbtest.DBs(t, "chainguard-resolved-and-open").
		SelectOnly("chainguard:rolling/CGA-res0-0000-0004", "chainguard:rolling/CGA-res0-0000-0005").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			findings := db.Match(t, &matcher, barPackage(pkg.ID("bar-fixed-and-open")))
			findings.SelectMatch("CGA-res0-0000-0005").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
			findings.Ignores().IsEmpty()
		})
}

// with no open entry for the vulnerability, a false positive still clears the files the package owns
func TestMatcherApk_FalsePositiveAloneStillClearsOwnedFindings(t *testing.T) {
	dbtest.DBs(t, "chainguard-resolved-and-open").
		SelectOnly("chainguard:rolling/CGA-res0-0000-0003").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("bar-fp-only")
			findings := db.Match(t, &matcher, barPackage(pkgID))
			findings.DoesNotHaveAnyVulnerabilities("CGA-res0-0000-0003", "CVE-2026-42003")
			ignores := findings.Ignores()
			ignores.SelectRelatedPackageIgnores(ignorereasons.DistroNAK, "CGA-res0-0000-0003", "CVE-2026-42003").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
			ignores.SelectRelatedPackageIgnores(ignorereasons.DistroFixed, "CGA-res0-0000-0003", "CVE-2026-42003").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}
