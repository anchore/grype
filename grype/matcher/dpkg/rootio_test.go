package dpkg

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherDpkg_RootIO_Ubuntu drives rootio matching against a DB that
// mixes rootio NAK records and the matching Ubuntu 22.04 disclosures.
// Each scenario exercises one of the load-bearing properties of the design:
//
//  1. The PackageSearchNames fanout finds upstream disclosures stored under
//     the bare name (e.g. "gnupg2") when a rootio-prefixed package
//     (e.g. "rootio-gnupg2") gets scanned. The match comes back as
//     ExactIndirectMatch because the cataloged name and the searched name
//     differ — the same shape syft uses for binary→source indirection.
//
//  2. A rootio NAK keyed under the rootio-prefixed name suppresses the
//     upstream disclosure when the scanned version satisfies the rootio
//     fix range. result.Set.Remove subtracts by ID + alias identity, so
//     the cross-name suppression works even though the NAK and the
//     disclosure are stored under different package names. The suppression
//     emits two ignores per CVE (alias unwind): the rootio record ID
//     (ROOT-OS-UBUNTU-2204-CVE-*) and the upstream CVE alias.
//
//  3. A non-rootio package scan never sees the rootio NAK — rootio packages
//     have both a name prefix and a version suffix, so a regular upstream
//     package fails IsRootIOPackage and PackageSearchNames returns only the
//     bare name. The NAK keyed under the rootio-prefixed name stays out of
//     reach.
//
// The fixture combines rootio fix records and Ubuntu 22.04 disclosures for
// four CVEs across four packages (gnupg2, patch, binutils, libgcrypt20),
// extracted from real vunnel data via the dbtest manager.
func TestMatcherDpkg_RootIO_Ubuntu(t *testing.T) {
	tests := []struct {
		name       string
		pkgName    string
		pkgVersion string

		// expectCVE is the CVE the matcher should flag. Empty means no match.
		expectCVE  string
		expectType match.Type // ignored when expectCVE is empty

		// expectFixedCVEs lists the CVE IDs that should surface as
		// DistroPackageFixed ignores. The rootio NAK alias-unwinds into
		// both the ROOT-OS-* record ID and the upstream CVE, so the
		// rootio-suppressed cases list both.
		expectFixedCVEs []string
	}{
		{
			// gnupg2: Ubuntu fix at 2.2.27-3ubuntu2.5; rootio fix at
			// 2.2.27-3ubuntu2.4.root.io.1. A rootio package below both fixes
			// hits the upstream disclosure via the bare-name search.
			name:       "rootio-gnupg2 below all fixes: upstream disclosure flags it",
			pkgName:    "rootio-gnupg2",
			pkgVersion: "2.2.27-3ubuntu2.3",
			expectCVE:  "CVE-2025-68973",
			expectType: match.ExactIndirectMatch,
		},
		{
			// At the rootio fix, the NAK lands in the unaffected set and
			// shares the CVE alias with the upstream disclosure. The matcher
			// subtracts the disclosure and emits two DistroPackageFixed
			// ignores: the ROOT-OS-* record and the aliased CVE.
			name:            "rootio-gnupg2 at rootio fix: NAK suppresses upstream disclosure",
			pkgName:         "rootio-gnupg2",
			pkgVersion:      "2.2.27-3ubuntu2.4.root.io.1",
			expectFixedCVEs: []string{"CVE-2025-68973", "ROOT-OS-UBUNTU-2204-CVE-2025-68973"},
		},
		{
			// Above the rootio fix but still below the upstream fix
			// (2.2.27-3ubuntu2.4.root.io.5 < 2.2.27-3ubuntu2.5 per dpkg
			// ordering). The upstream disclosure would flag this version on
			// its own, but the NAK suppresses it — same alias-unwind as the
			// at-fix case.
			name:            "rootio-gnupg2 between rootio fix and upstream fix: NAK still suppresses",
			pkgName:         "rootio-gnupg2",
			pkgVersion:      "2.2.27-3ubuntu2.4.root.io.5",
			expectFixedCVEs: []string{"CVE-2025-68973", "ROOT-OS-UBUNTU-2204-CVE-2025-68973"},
		},
		{
			// A regular gnupg2 below the upstream fix matches the upstream
			// disclosure directly (no rootio fanout, no NAK).
			name:       "regular gnupg2 below upstream fix: direct upstream match",
			pkgName:    "gnupg2",
			pkgVersion: "2.2.27-3ubuntu2.3",
			expectCVE:  "CVE-2025-68973",
			expectType: match.ExactDirectMatch,
		},
		{
			// Regular gnupg2 at the upstream fix is patched per Ubuntu's
			// own data. The matcher records a standard DistroPackageFixed
			// ignore (no rootio involvement at all).
			name:            "regular gnupg2 at upstream fix: distro-fixed by Ubuntu",
			pkgName:         "gnupg2",
			pkgVersion:      "2.2.27-3ubuntu2.5",
			expectFixedCVEs: []string{"CVE-2025-68973"},
		},
		{
			// patch: Ubuntu disclosure for CVE-2018-6952 with rootio fix at
			// 2.7.6-7build2.root.io.1. Below the rootio fix, the upstream
			// disclosure flags the rootio package.
			name:       "rootio-patch below rootio fix: upstream disclosure flags it",
			pkgName:    "rootio-patch",
			pkgVersion: "2.7.6-7build2",
			expectCVE:  "CVE-2018-6952",
			expectType: match.ExactIndirectMatch,
		},
		{
			name:            "rootio-patch at rootio fix: NAK suppresses",
			pkgName:         "rootio-patch",
			pkgVersion:      "2.7.6-7build2.root.io.1",
			expectFixedCVEs: []string{"CVE-2018-6952", "ROOT-OS-UBUNTU-2204-CVE-2018-6952"},
		},
		{
			// libgcrypt20: same shape as the others.
			name:       "rootio-libgcrypt20 below rootio fix: upstream disclosure flags it",
			pkgName:    "rootio-libgcrypt20",
			pkgVersion: "1.9.4-3ubuntu3",
			expectCVE:  "CVE-2024-2236",
			expectType: match.ExactIndirectMatch,
		},
		{
			name:            "rootio-libgcrypt20 at rootio fix: NAK suppresses",
			pkgName:         "rootio-libgcrypt20",
			pkgVersion:      "1.9.4-3ubuntu3.root.io.2",
			expectFixedCVEs: []string{"CVE-2024-2236", "ROOT-OS-UBUNTU-2204-CVE-2024-2236"},
		},
		{
			// binutils: 2.38-4ubuntu2.12.root.io.1 is the rootio fix.
			// Below that, upstream flags it.
			name:       "rootio-binutils below rootio fix: upstream disclosure flags it",
			pkgName:    "rootio-binutils",
			pkgVersion: "2.38-4ubuntu2.11",
			expectCVE:  "CVE-2025-1180",
			expectType: match.ExactIndirectMatch,
		},
		{
			name:            "rootio-binutils at rootio fix: NAK suppresses",
			pkgName:         "rootio-binutils",
			pkgVersion:      "2.38-4ubuntu2.12.root.io.1",
			expectFixedCVEs: []string{"CVE-2025-1180", "ROOT-OS-UBUNTU-2204-CVE-2025-1180"},
		},
		{
			// An entirely unrelated package gets nothing — no rootio
			// contamination spills into other names.
			name:       "unrelated package: nothing",
			pkgName:    "libreoffice",
			pkgVersion: "1:7.3.7-0ubuntu0.22.04.1",
		},
	}

	dbtest.DBs(t, "rootio-ubuntu-2204").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewDpkgMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				pkgID := pkg.ID(tt.pkgName + "@" + tt.pkgVersion)
				p := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.DebPkg).
					WithID(pkgID).
					WithDistro(dbtest.Ubuntu2204).
					Build()

				findings := db.Match(t, matcher, p)

				if tt.expectCVE == "" && len(tt.expectFixedCVEs) == 0 {
					findings.IsEmpty()
					return
				}

				if tt.expectCVE != "" {
					findings.SelectMatch(tt.expectCVE).
						SelectDetailByType(tt.expectType).
						AsDistroSearch()
				}

				if len(tt.expectFixedCVEs) > 0 {
					findings.Ignores().
						SelectRelatedPackageIgnores("DistroPackageFixed", tt.expectFixedCVEs...).
						ForPackage(pkgID)
				}
			})
		}
	})
}

// TestMatcherDpkg_RootIO_Debian exercises the same mechanism against the
// Debian 12 namespace. Two CVEs cover the load-bearing scenarios: rootio
// publishes fixes for postgresql-15 and jq that suppress the upstream
// Debian disclosures via the bare-name fanout + NAK identity match.
func TestMatcherDpkg_RootIO_Debian(t *testing.T) {
	tests := []struct {
		name            string
		pkgName         string
		pkgVersion      string
		expectCVE       string
		expectType      match.Type
		expectFixedCVEs []string
	}{
		{
			// postgresql-15: Debian fix at 15.15-0+deb12u1, rootio fix at
			// 15.14-0+deb12u1.root.io.6 (rootio shipped a backport on the
			// 15.14 line before Debian's 15.15 release).
			name:       "rootio-postgresql-15 below rootio fix: upstream flags it",
			pkgName:    "rootio-postgresql-15",
			pkgVersion: "15.14-0+deb12u1",
			expectCVE:  "CVE-2025-12817",
			expectType: match.ExactIndirectMatch,
		},
		{
			name:            "rootio-postgresql-15 at rootio fix: NAK suppresses",
			pkgName:         "rootio-postgresql-15",
			pkgVersion:      "15.14-0+deb12u1.root.io.6",
			expectFixedCVEs: []string{"CVE-2025-12817", "ROOT-OS-DEBIAN-12-CVE-2025-12817"},
		},
		{
			// jq: Debian fix at 1.6-2.1+deb12u1, rootio fix at
			// 1.6-2.1.root.io.2. The two appendices are independent forks
			// of the same 1.6-2.1 base. At any version below both, the
			// upstream Debian disclosure flags the rootio package.
			name:       "rootio-jq below all fixes: upstream flags it",
			pkgName:    "rootio-jq",
			pkgVersion: "1.6-2.1",
			expectCVE:  "CVE-2025-48060",
			expectType: match.ExactIndirectMatch,
		},
		{
			// Regular jq at the Debian fix version: distro-fixed by Debian
			// directly; no rootio involvement at all.
			name:            "regular jq at Debian fix: distro-fixed by Debian",
			pkgName:         "jq",
			pkgVersion:      "1.6-2.1+deb12u1",
			expectFixedCVEs: []string{"CVE-2025-48060"},
		},
		{
			name:       "regular postgresql-15 below Debian fix: direct upstream match",
			pkgName:    "postgresql-15",
			pkgVersion: "15.13",
			expectCVE:  "CVE-2025-12817",
			expectType: match.ExactDirectMatch,
		},
	}

	dbtest.DBs(t, "rootio-debian-12").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewDpkgMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				pkgID := pkg.ID(tt.pkgName + "@" + tt.pkgVersion)
				p := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.DebPkg).
					WithID(pkgID).
					WithDistro(dbtest.Debian12).
					Build()

				findings := db.Match(t, matcher, p)

				if tt.expectCVE == "" && len(tt.expectFixedCVEs) == 0 {
					findings.IsEmpty()
					return
				}

				if tt.expectCVE != "" {
					findings.SelectMatch(tt.expectCVE).
						SelectDetailByType(tt.expectType).
						AsDistroSearch()
				}

				if len(tt.expectFixedCVEs) > 0 {
					findings.Ignores().
						SelectRelatedPackageIgnores("DistroPackageFixed", tt.expectFixedCVEs...).
						ForPackage(pkgID)
				}
			})
		}
	})
}
