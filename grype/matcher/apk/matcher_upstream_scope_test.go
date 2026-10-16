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

// The chainguard-subpackages fixture holds Chainguard OSV entries for the origin package "foo", most of them
// marked database_specific.chainguard.applies_to_subpackages=false, plus one unmarked entry for "bar" and
// one entry filed against the subpackage "foo-docs" itself. The NVD entries describe the "foo" CPE.

func subpackage(name, version, origin string) *dbtest.PackageBuilder {
	return dbtest.NewPackage(name, version, syftPkg.ApkPkg).
		WithDistro(dbtest.ChainguardRolling).
		WithMetadata(pkg.ApkMetadata{Arch: "x86_64"}).
		WithUpstream(origin, "")
}

// an open entry scoped to the origin package does not reach a subpackage that names it as origin
func TestMatcherApk_UpstreamScope_OpenEntryDoesNotReachSubpackage(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0001").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := subpackage("foo-docs", "1.2.3-r0", "foo").Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()
			findings.Ignores().IsEmpty()
		})
}

// the same entry still matches the origin package it names
func TestMatcherApk_UpstreamScope_OpenEntryStillMatchesOrigin(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0001").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("foo", "1.2.3-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.ChainguardRolling).
				WithMetadata(pkg.ApkMetadata{Arch: "x86_64"}).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CGA-sub0-0000-0001").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// an entry without the field keeps today's behaviour: it reaches the subpackage through the origin search
func TestMatcherApk_UpstreamScope_UnscopedEntryStillReachesSubpackage(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0004").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := subpackage("bar-docs", "1.2.3-r0", "bar").Build()

			db.Match(t, &matcher, p).
				SelectMatch("CGA-sub0-0000-0004").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
}

// a fixed entry scoped to the origin package does not clear files the subpackage owns
func TestMatcherApk_UpstreamScope_FixedEntryProducesNoIgnoreOnSubpackage(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0007").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := subpackage("foo-docs", "1.2.3-r2", "foo").Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()
			findings.Ignores().IsEmpty()
		})
}

// the same fixed entry still clears the files the origin package owns
func TestMatcherApk_UpstreamScope_FixedEntryStillProducesIgnoreOnOrigin(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0007").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("foo-past-fix")
			p := dbtest.NewPackage("foo", "1.2.3-r2", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.ChainguardRolling).
				WithMetadata(pkg.ApkMetadata{Arch: "x86_64"}).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnores(ignorereasons.DistroFixed, "CGA-sub0-0000-0007", "CVE-2026-41007").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// a false-positive entry scoped to the origin package produces no NAK ignore on the subpackage
func TestMatcherApk_UpstreamScope_NakProducesNoIgnoreOnSubpackage(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0003").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := subpackage("foo-docs", "1.2.3-r0", "foo").Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()
			findings.Ignores().IsEmpty()
		})
}

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

// NVD is still searched by the origin package's name: with no Chainguard entry, the match is reported
func TestMatcherApk_UpstreamScope_NvdByOriginNameStillReported(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CVE-2026-41006").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := subpackage("foo-docs", "1.2.3-r0", "foo").
				WithCPE("cpe:2.3:a:foo:foo-docs:1.2.3:*:*:*:*:*:*:*").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2026-41006").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
		})
}

// with no entry of its own, the subpackage's NVD match is settled by the origin package's scoped fix
func TestMatcherApk_UpstreamScope_NvdSettledByOriginFix(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0002", "CVE-2026-41002").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := subpackage("foo-docs", "1.2.3-r2", "foo").
				WithCPE("cpe:2.3:a:foo:foo-docs:1.2.3:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			findings.DoesNotHaveAnyVulnerabilities("CVE-2026-41002", "CGA-sub0-0000-0002")
			findings.Ignores().IsEmpty()
		})
}

// with no entry of its own, the subpackage's NVD match is settled by the origin package's scoped false positive
func TestMatcherApk_UpstreamScope_NvdSettledByOriginNak(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0003", "CVE-2026-41003").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := subpackage("foo-docs", "1.2.3-r0", "foo").
				WithCPE("cpe:2.3:a:foo:foo-docs:1.2.3:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			findings.DoesNotHaveAnyVulnerabilities("CVE-2026-41003", "CGA-sub0-0000-0003")
			findings.Ignores().IsEmpty()
		})
}

// the subpackage's own fixed entry settles the NVD match and clears the files the subpackage owns
func TestMatcherApk_UpstreamScope_NvdSettledBySubpackageOwnFix(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0005", "CVE-2026-41005").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("foo-docs-own-fix")
			p := subpackage("foo-docs", "1.2.3-r2", "foo").
				WithID(pkgID).
				WithCPE("cpe:2.3:a:foo:foo-docs:1.2.3:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			findings.DoesNotHaveAnyVulnerabilities("CVE-2026-41005", "CGA-sub0-0000-0005")
			findings.Ignores().
				SelectRelatedPackageIgnores(ignorereasons.DistroFixed, "CGA-sub0-0000-0005", "CVE-2026-41005").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}
