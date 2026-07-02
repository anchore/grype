package dpkg

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// newESMDistro builds an Ubuntu Pro/ESM distro (channel "esm") from a version like "16.04".
func newESMDistro(version string) *distro.Distro {
	return distro.New(distro.Ubuntu, version+"+esm", "")
}

// real values pulled from the ubuntu-esm fixture (see file header for source URLs).
const (
	pkgWayland          = "wayland"
	cveWayland          = "CVE-2021-3782"
	verWaylandXenial    = "1.11.0-2"
	esmFixWaylandXenial = "1.12.0-1~ubuntu16.04.3+esm1"
)

// The ubuntu-esm fixture carries real Ubuntu Pro/ESM records (verified against ubuntu.com/security):
//
//   - wayland CVE-2021-3782: on 16.04 (xenial) the base pocket has NO fix (Version "None", won't-fix) and the
//     only fix is esm-infra 1.12.0-1~ubuntu16.04.3+esm1; on 20.04 (focal) it is fixed in the standard pocket at
//     1.18.0-1ubuntu0.1 (no +esm record). Source: https://ubuntu.com/security/cves/CVE-2021-3782.json
//   - openssh CVE-2025-61985: on 20.04 (focal) the base pocket has no fix and esm-infra fixes it at
//     1:8.2p1-4ubuntu0.13+esm1 (epoch form). Source: https://ubuntu.com/security/cves/CVE-2025-61985.json
//
// These exercise the §5 matcher scenarios: ESM-only fix surfaced when the channel is on, base won't-fix reported
// when the channel is off, base standard-pocket fix still resolving with the channel on, epoch/tilde dpkg ordering,
// and source-package indirection.

//nolint:funlen
func TestUbuntuESM_VulnerableCases(t *testing.T) {
	tests := []struct {
		name         string
		pkgName      string
		pkgVersion   string
		upstreamName string
		upstreamVer  string
		d            *distro.Distro
		expectCVE    string
		expectType   match.Type
		expectState  vulnerability.FixState
		expectFixes  []string
	}{
		{
			// ESM-only fix, channel ON, installed below the esm fix -> vulnerable with the ESM fix surfaced.
			name:        "esm-only fix surfaced when installed below it",
			pkgName:     pkgWayland,
			pkgVersion:  verWaylandXenial,
			d:           newESMDistro("16.04"),
			expectCVE:   cveWayland,
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateFixed,
			expectFixes: []string{esmFixWaylandXenial},
		},
		{
			// epoch form (openssh) - dpkg comparator handles the "1:" epoch; installed below the esm fix -> vulnerable.
			name:        "esm-only fix surfaced for epoch version form",
			pkgName:     "openssh",
			pkgVersion:  "1:8.2p1-4ubuntu0.12",
			d:           newESMDistro("20.04"),
			expectCVE:   "CVE-2025-61985",
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateFixed,
			expectFixes: []string{"1:8.2p1-4ubuntu0.13+esm1"},
		},
		{
			// source-package indirection: a binary package resolves the CVE via its upstream source "wayland".
			name:         "esm fix reached by source indirection",
			pkgName:      "libwayland-client0",
			pkgVersion:   verWaylandXenial,
			upstreamName: pkgWayland,
			upstreamVer:  verWaylandXenial,
			d:            newESMDistro("16.04"),
			expectCVE:    cveWayland,
			expectType:   match.ExactIndirectMatch,
			expectState:  vulnerability.FixStateFixed,
			expectFixes:  []string{esmFixWaylandXenial},
		},
		{
			// ESM-only fix, channel OFF (no esm channel on the distro) -> base won't-fix disclosure stands, reported
			// vulnerable. This is the worst-false-negative guard: a Pro-only fix must NOT be treated as fixed for a
			// non-Pro user.
			name:        "channel off leaves base wont-fix visible",
			pkgName:     pkgWayland,
			pkgVersion:  verWaylandXenial,
			d:           dbtest.Ubuntu1804, // placeholder, overridden below to base 16.04
			expectCVE:   cveWayland,
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateNotFixed, // base "None" record surfaces as not-fixed on the standard path
		},
		{
			// base standard-pocket fix, channel ON, installed below the base fix -> vulnerable via the base fix (no
			// +esm record involved). Proves the esm channel does not interfere with normal base resolution.
			name:        "base standard-pocket fix still resolves with channel on",
			pkgName:     pkgWayland,
			pkgVersion:  "1.17.0-1ubuntu1",
			d:           newESMDistro("20.04"),
			expectCVE:   cveWayland,
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateFixed,
			expectFixes: []string{"1.18.0-1ubuntu0.1"},
		},
	}

	dbtest.DBs(t, "ubuntu-esm").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewDpkgMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				d := tt.d
				if tt.name == "channel off leaves base wont-fix visible" {
					d = distro.New(distro.Ubuntu, "16.04", "") // base distro, NO esm channel -> standard path
				}

				b := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.DebPkg).WithDistro(d)
				if tt.upstreamName != "" {
					b = b.WithUpstream(tt.upstreamName, tt.upstreamVer)
				}
				p := b.Build()

				findings := db.Match(t, matcher, p)

				// we intentionally assert on match presence, type, and the surfaced fix only (not every detail).
				sf := findings.SkipCompleteness().SelectMatch(tt.expectCVE)
				sf.HasMatchType(tt.expectType)
				sf.HasFix(tt.expectState, tt.expectFixes...)
			})
		}
	})
}

// TestUbuntuESM_FixedCases verifies that a package at or past the ESM fix is resolved (not vulnerable) and produces a
// "Distro Not Vulnerable" ignore.
func TestUbuntuESM_FixedCases(t *testing.T) {
	tests := []struct {
		name        string
		pkgName     string
		pkgVersion  string
		d           *distro.Distro
		expectCVE   string
		expectEmpty bool // base fix removes the disclosure entirely: no match AND no ignore (mirrors the EUS path)
	}{
		{
			// installed exactly at the esm fix -> resolved: the base won't-fix disclosure is removed by the esm
			// resolution, producing a "Distro Not Vulnerable" ignore.
			name:       "at esm fix is resolved with an ignore",
			pkgName:    pkgWayland,
			pkgVersion: esmFixWaylandXenial,
			d:          newESMDistro("16.04"),
			expectCVE:  cveWayland,
		},
		{
			// installed at the base standard-pocket fix (channel on) -> the base disclosure itself reports not
			// vulnerable, so the two-pass search returns nothing at all (no leakage from esm).
			name:        "at base standard-pocket fix yields nothing",
			pkgName:     pkgWayland,
			pkgVersion:  "1.18.0-1ubuntu0.1",
			d:           newESMDistro("20.04"),
			expectEmpty: true,
		},
	}

	dbtest.DBs(t, "ubuntu-esm").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewDpkgMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.DebPkg).WithDistro(tt.d).Build()

				findings := db.Match(t, matcher, p)
				if tt.expectEmpty {
					findings.IsEmpty()
					return
				}
				findings.Ignores().
					SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, tt.expectCVE)
			})
		}
	})
}
