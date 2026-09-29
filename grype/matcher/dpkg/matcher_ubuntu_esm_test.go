package dpkg

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// newESMDistro builds an Ubuntu Pro/ESM distro (channel "esm") from a version like "16.04".
func newESMDistro(version string) *distro.Distro {
	return distro.New(distro.Ubuntu, version+"+esm", "")
}

func TestShouldUseUbuntuESMMatching(t *testing.T) {
	withChannels := func(d *distro.Distro, channels ...string) *distro.Distro {
		d.Channels = channels
		return d
	}

	tests := []struct {
		name string
		d    *distro.Distro
		want bool
	}{
		{name: "nil distro", d: nil, want: false},
		{name: "ubuntu with esm channel", d: newESMDistro("16.04"), want: true},
		{name: "ubuntu without channels", d: distro.New(distro.Ubuntu, "16.04", ""), want: false},
		{
			// channel matching is case-insensitive (channels can arrive in any case)
			name: "ubuntu with mixed-case ESM channel",
			d:    withChannels(distro.New(distro.Ubuntu, "16.04", ""), "ESM"),
			want: true,
		},
		{
			// a non-esm channel on Ubuntu must not trigger ESM matching
			name: "ubuntu with non-esm channel",
			d:    withChannels(distro.New(distro.Ubuntu, "16.04", ""), "fips"),
			want: false,
		},
		{
			// esm should be detected even alongside other channels
			name: "ubuntu with esm among multiple channels",
			d:    withChannels(distro.New(distro.Ubuntu, "16.04", ""), "fips", "esm"),
			want: true,
		},
		{
			// an esm channel only makes sense on Ubuntu; guard against it leaking onto other distros
			name: "non-ubuntu with esm channel",
			d:    withChannels(distro.New(distro.Debian, "12", ""), "esm"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldUseUbuntuESMMatching(tt.d); got != tt.want {
				t.Errorf("shouldUseUbuntuESMMatching() = %v, want %v", got, tt.want)
			}
		})
	}
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
		{
			// channel ON but ESM has published no fix (base pocket "None", no +esm record) -> still vulnerable via the
			// ESM path, reported not-fixed. This exercises the ESM merge producing a wont-fix/not-fixed outcome (the
			// common "Pro subscription active but package still exposed" case), distinct from the channel-off path.
			name:        "channel on with no esm fix stays vulnerable",
			pkgName:     "curl",
			pkgVersion:  "7.47.0-1ubuntu2",
			d:           newESMDistro("16.04"),
			expectCVE:   "CVE-2016-9586",
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateNotFixed,
		},
		{
			// installed version is MISSING the epoch that the ESM fix carries ("1:"). Under the default (zero-epoch)
			// strategy the missing epoch is treated as 0, so 0:...0.12 < 1:...0.13+esm1 -> vulnerable with the esm fix
			// surfaced. Guards the dpkg epoch-normalization path that the matcher threads MissingEpochStrategy for.
			name:        "esm fix surfaced when installed version omits the epoch",
			pkgName:     "openssh",
			pkgVersion:  "8.2p1-4ubuntu0.12", // note: no "1:" epoch prefix
			d:           newESMDistro("20.04"),
			expectCVE:   "CVE-2025-61985",
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateFixed,
			expectFixes: []string{"1:8.2p1-4ubuntu0.13+esm1"},
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
		name         string
		pkgName      string
		pkgVersion   string
		upstreamName string
		upstreamVer  string
		d            *distro.Distro
		expectCVE    string
		expectEmpty  bool // base fix removes the disclosure entirely: no match AND no ignore (mirrors the EUS path)
	}{
		{
			// installed exactly at the esm fix -> resolved: the base won't-fix disclosure is removed by the esm
			// resolution, producing a "Distro Not Vulnerable" ignore keyed to the scanned package.
			name:       "at esm fix is resolved with an ignore",
			pkgName:    pkgWayland,
			pkgVersion: esmFixWaylandXenial,
			d:          newESMDistro("16.04"),
			expectCVE:  cveWayland,
		},
		{
			// same resolution reached through source indirection: the binary is at the esm fix via its upstream
			// source, so the disclosure resolves and the ignore is keyed to the scanned binary package.
			name:         "at esm fix via source indirection is resolved with an ignore",
			pkgName:      "libwayland-client0",
			pkgVersion:   esmFixWaylandXenial,
			upstreamName: pkgWayland,
			upstreamVer:  esmFixWaylandXenial,
			d:            newESMDistro("16.04"),
			expectCVE:    cveWayland,
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
				pkgID := pkg.ID(tt.name)
				b := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.DebPkg).WithID(pkgID).WithDistro(tt.d)
				if tt.upstreamName != "" {
					b = b.WithUpstream(tt.upstreamName, tt.upstreamVer)
				}
				p := b.Build()

				findings := db.Match(t, matcher, p)
				if tt.expectEmpty {
					findings.IsEmpty()
					return
				}
				// the ownership ignore must be keyed to the scanned package (not the upstream source)
				findings.Ignores().
					SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, tt.expectCVE).
					ForPackage(pkgID)
			})
		}
	})
}

// TestUbuntuESM_MultipleCVEsPerPackage verifies that a single package resolving multiple ESM CVEs surfaces every one,
// each with its own fix version. Exercises the Set/Merge fan-out over vulnerability IDs in the ESM path.
func TestUbuntuESM_MultipleCVEsPerPackage(t *testing.T) {
	dbtest.DBs(t, "ubuntu-esm").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewDpkgMatcher(MatcherConfig{})

		// openssh on 20.04+esm carries two ESM-only CVEs fixed at different point releases; installed below both.
		p := dbtest.NewPackage("openssh", "1:8.2p1-4ubuntu0.12", syftPkg.DebPkg).
			WithDistro(newESMDistro("20.04")).
			Build()

		findings := db.Match(t, matcher, p)
		findings.SkipCompleteness().OnlyHasVulnerabilities("CVE-2025-61985", "CVE-2023-38408")

		findings.SkipCompleteness().SelectMatch("CVE-2025-61985").
			HasFix(vulnerability.FixStateFixed, "1:8.2p1-4ubuntu0.13+esm1")
		findings.SkipCompleteness().SelectMatch("CVE-2023-38408").
			HasFix(vulnerability.FixStateFixed, "1:8.2p1-4ubuntu0.20+esm1")
	})
}

// TestUbuntuESM_MissingEpochStrategy asserts how the ESM path treats MissingEpochStrategy when the installed version
// omits the epoch that the ESM fix carries. The installed build equals the fix build "1:8.2p1-4ubuntu0.13+esm1" but
// lacks the "1:" prefix, so the two strategies must diverge:
//   - zero: missing epoch is treated as 0, so 0:... < 1:... -> still vulnerable (correct by definition).
//   - auto: missing epoch adopts the constraint's epoch, so 1:... == 1:... -> resolved, not vulnerable.
//
// NOTE: the auto case currently FAILS. The ESM two-pass search resolves fixes by comparing against the fix version
// (neededFixes -> version.Is, and result filtering -> search.ByFixedVersion), both of which use a plain Compare that
// ignores MissingEpochStrategy. Only constraint.Satisfied honors it, and the base disclosure here is an
// always-vulnerable "None" row, so the constraint check never resolves it (the RHEL EUS path has the same gap). This
// test intentionally asserts the correct behavior so it stays red until fix-version comparison honors the strategy.
func TestUbuntuESM_MissingEpochStrategy(t *testing.T) {
	const (
		cve = "CVE-2025-61985"
		// installed at the same build as the fix "1:8.2p1-4ubuntu0.13+esm1" but with no epoch prefix
		installedNoEpoch = "8.2p1-4ubuntu0.13+esm1"
	)

	tests := []struct {
		strategy      version.MissingEpochStrategy
		expectResolve bool // true: installed is the fixed build, must not be reported
	}{
		{strategy: version.MissingEpochStrategyZero, expectResolve: false},
		{strategy: version.MissingEpochStrategyAuto, expectResolve: true},
	}

	for _, tt := range tests {
		t.Run(string(tt.strategy), func(t *testing.T) {
			dbtest.DBs(t, "ubuntu-esm").Run(func(t *testing.T, db *dbtest.DB) {
				matcher := NewDpkgMatcher(MatcherConfig{MissingEpochStrategy: tt.strategy})
				p := dbtest.NewPackage("openssh", installedNoEpoch, syftPkg.DebPkg).
					WithDistro(newESMDistro("20.04")).
					Build()

				findings := db.Match(t, matcher, p)
				if tt.expectResolve {
					// installed is the fixed build: no match, and a "Distro Not Vulnerable" ignore is emitted instead
					findings.SkipCompleteness().DoesNotHaveAnyVulnerabilities(cve)
					findings.Ignores().
						SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, cve)
				} else {
					findings.SkipCompleteness().SelectMatch(cve)
				}
			})
		})
	}
}
