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

// The chainguard-subpackages fixture holds Chainguard OSV entries for the origin package "foo",
// one for "bar", and one filed against the subpackage "foo-docs" itself. Every entry carries an
// architecture, as every Chainguard OSV entry does. Some also set
// database_specific.chainguard.applies_to_subpackages=false (from anchore/grype#3797); grype does
// not read it, the arch-qualified row is what scopes an entry to one binary apk. The NVD entries
// describe the "foo" CPE.

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
				SelectMatch("CVE-2026-41001").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// every Chainguard OSV entry names one binary apk and carries its arch, so even one without
// applies_to_subpackages stays with that apk rather than reaching subpackages through the origin
// (anchore/grype#3797 kept these reaching; the arch-qualified row is the scope here)
func TestMatcherApk_UpstreamScope_ArchQualifiedEntryDoesNotReachSubpackage(t *testing.T) {
	dbtest.DBs(t, "chainguard-subpackages").
		SelectOnly("CGA-sub0-0000-0004").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := subpackage("bar-docs", "1.2.3-r0", "bar").Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()
			findings.Ignores().IsEmpty()
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
				SelectRelatedPackageIgnores(ignorereasons.DistroFixed, "CVE-2026-41007").
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
				SelectRelatedPackageIgnores(ignorereasons.DistroFixed, "CVE-2026-41005").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// secdb rows carry no arch, so the "src" origin marker leaves their fan-out exactly as it was:
// a subpackage with a real arch still gets the origin's matches, fixes and NAKs
func TestMatcherApk_UpstreamScope_SecdbRowsStillReachSubpackage(t *testing.T) {
	x86 := pkg.ApkMetadata{Arch: "x86_64"}

	t.Run("match", func(t *testing.T) {
		dbtest.DBs(t, "alpine318").
			SelectOnly("3.18/CVE-2024-0727").
			Run(func(t *testing.T, db *dbtest.DB) {
				p := dbtest.NewPackage("libssl3", "3.1.4-r0", syftPkg.ApkPkg).
					WithDistro(dbtest.Alpine318).
					WithMetadata(x86).
					WithUpstream("openssl", "").
					Build()

				db.Match(t, &Matcher{}, p).
					SelectMatch("CVE-2024-0727").
					SelectDetailByType(match.ExactIndirectMatch).
					AsDistroSearch()
			})
	})

	t.Run("fix", func(t *testing.T) {
		dbtest.DBs(t, "alpine318").
			SelectOnly("3.18/CVE-2024-0727").
			Run(func(t *testing.T, db *dbtest.DB) {
				pkgID := pkg.ID("libssl3-fixed")
				p := dbtest.NewPackage("libssl3", "3.1.4-r5", syftPkg.ApkPkg).
					WithID(pkgID).
					WithDistro(dbtest.Alpine318).
					WithMetadata(x86).
					WithUpstream("openssl", "3.1.4-r5").
					Build()

				db.Match(t, &Matcher{}, p).Ignores().
					SelectRelatedPackageIgnore(ignorereasons.DistroFixed, "CVE-2024-0727").
					ForPackage(pkgID).
					WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
			})
	})

	t.Run("nak", func(t *testing.T) {
		dbtest.DBs(t, "alpine318").
			SelectOnly("3.18/CVE-2019-6470").
			Run(func(t *testing.T, db *dbtest.DB) {
				pkgID := pkg.ID("bind-tools-pkg")
				p := dbtest.NewPackage("bind-tools", "9.16.0-r0", syftPkg.ApkPkg).
					WithID(pkgID).
					WithDistro(dbtest.Alpine318).
					WithMetadata(x86).
					WithUpstream("bind", "").
					Build()

				ignores := db.Match(t, &Matcher{}, p).Ignores()
				ignores.SelectRelatedPackageIgnore(ignorereasons.DistroNAK, "CVE-2019-6470").
					ForPackage(pkgID).
					WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
				ignores.SelectRelatedPackageIgnore(ignorereasons.DistroFixed, "CVE-2019-6470").
					ForPackage(pkgID).
					WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
			})
	})
}
