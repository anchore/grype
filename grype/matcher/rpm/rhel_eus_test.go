package rpm

import (
	"errors"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestExtractRHELVersionFromRelease(t *testing.T) {
	tests := []struct {
		name      string
		release   string
		wantMajor int
		wantMinor int
		wantFound bool
	}{
		{
			name:      "el9_5 pattern",
			release:   "503.11.1.el9_5",
			wantMajor: 9,
			wantMinor: 5,
			wantFound: true,
		},
		{
			name:      "el8_10 pattern (double digit minor)",
			release:   "82.el8_10.2",
			wantMajor: 8,
			wantMinor: 10,
			wantFound: true,
		},
		{
			name:      "el7 pattern (no minor version treated as 0)",
			release:   "1.el7",
			wantMajor: 7,
			wantMinor: 0,
			wantFound: true,
		},
		{
			name:      "el9 pattern (no minor version treated as 0)",
			release:   "427.79.1.el9",
			wantMajor: 9,
			wantMinor: 0,
			wantFound: true,
		},
		{
			name:      "el9_4 pattern",
			release:   "427.79.1.el9_4",
			wantMajor: 9,
			wantMinor: 4,
			wantFound: true,
		},
		{
			name:      "no el pattern",
			release:   "1.0.0",
			wantMajor: 0,
			wantMinor: 0,
			wantFound: false,
		},
		{
			name:      "empty string",
			release:   "",
			wantMajor: 0,
			wantMinor: 0,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMajor, gotMinor, gotFound := extractRHELVersionFromRelease(tt.release)
			assert.Equal(t, tt.wantMajor, gotMajor, "major version mismatch")
			assert.Equal(t, tt.wantMinor, gotMinor, "minor version mismatch")
			assert.Equal(t, tt.wantFound, gotFound, "found mismatch")
		})
	}
}

func TestExtractReleaseFromRPMVersion(t *testing.T) {
	tests := []struct {
		name       string
		rpmVersion string
		want       string
	}{
		{
			name:       "version with hyphen",
			rpmVersion: "5.14.0-503.11.1.el9_5",
			want:       "503.11.1.el9_5",
		},
		{
			name:       "version with epoch and hyphen",
			rpmVersion: "0:5.14.0-503.11.1.el9_5",
			want:       "503.11.1.el9_5",
		},
		{
			name:       "version without hyphen",
			rpmVersion: "1.0.0",
			want:       "1.0.0",
		},
		{
			name:       "version with epoch but no hyphen",
			rpmVersion: "1:2.3.4",
			want:       "2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractReleaseFromRPMVersion(tt.rpmVersion)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsFixReachableForEUS(t *testing.T) {
	tests := []struct {
		name       string
		fixVersion string
		eusDistro  *distro.Distro
		want       bool
	}{
		{
			name:       "nil distro - always reachable",
			fixVersion: "5.14.0-503.11.1.el9_5",
			eusDistro:  nil,
			want:       true,
		},
		{
			name:       "el9_5 fix NOT reachable from 9.4 EUS",
			fixVersion: "5.14.0-503.11.1.el9_5",
			eusDistro:  newEUSDistro("9.4"),
			want:       false,
		},
		{
			name:       "el9_4 fix IS reachable from 9.4 EUS (same minor)",
			fixVersion: "5.14.0-427.80.1.el9_4",
			eusDistro:  newEUSDistro("9.4"),
			want:       true,
		},
		{
			// This is the key test case: mainline 9.2 fixes ARE reachable from 9.4 EUS
			// because EUS 9.4 includes all mainline fixes up to 9.4
			name:       "el9_2 mainline fix IS reachable from 9.4 EUS (lower minor version)",
			fixVersion: "5.14.0-100.el9_2",
			eusDistro:  newEUSDistro("9.4"),
			want:       true,
		},
		{
			name:       "el9 base fix IS reachable from 9.4 EUS (no minor version in fix)",
			fixVersion: "5.14.0-100.el9",
			eusDistro:  newEUSDistro("9.4"),
			want:       true,
		},
		{
			name:       "el8 fix NOT reachable from el9 (different major)",
			fixVersion: "4.18.0-100.el8_10",
			eusDistro:  newEUSDistro("9.4"),
			want:       false,
		},
		{
			name:       "no el pattern - fail open (assume reachable)",
			fixVersion: "1.0.0-1",
			eusDistro:  newEUSDistro("9.4"),
			want:       true,
		},
		{
			name:       "distro without version - fail open",
			fixVersion: "5.14.0-503.11.1.el9_5",
			eusDistro:  newEUSDistro(""),
			want:       true,
		},
		{
			// "9+eus" (no minor) is treated as "9.0+eus", so el9_1 fixes are NOT reachable
			name:       "distro with major only treated as .0 - el9_1 fix NOT reachable from 9+eus",
			fixVersion: "5.14.0-100.el9_1",
			eusDistro:  distro.New(distro.RedHat, "9+eus", ""),
			want:       false,
		},
		{
			// "9+eus" (no minor) is treated as "9.0+eus", so el9_0 fixes ARE reachable
			name:       "distro with major only treated as .0 - el9_0 fix IS reachable from 9+eus",
			fixVersion: "5.14.0-100.el9_0",
			eusDistro:  distro.New(distro.RedHat, "9+eus", ""),
			want:       true,
		},
		{
			// "9+eus" (no minor) is treated as "9.0+eus", so base el9 fixes ARE reachable
			name:       "distro with major only treated as .0 - el9 base fix IS reachable from 9+eus",
			fixVersion: "5.14.0-100.el9",
			eusDistro:  distro.New(distro.RedHat, "9+eus", ""),
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFixReachableForEUS(tt.fixVersion, tt.eusDistro)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveEUSDisclosures(t *testing.T) {
	tests := []struct {
		name            string
		packageVersion  string
		disclosures     []result.Result
		advisoryOverlay []result.Result
		want            []result.Result
	}{
		{
			name:           "disclosure with fix version - package version is vulnerable",
			packageVersion: "1.0.0", // vulnerable since 1.0.0 < 1.5.0
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.6.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{"1.6.0"}, // important! this is the fix version that we should not consider
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed, // important!
								Versions: []string{"1.5.0"},           // important!
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.CombineConstraints(
								version.MustGetConstraint("< 1.6.0", version.RpmFormat), // from disclosure
								version.MustGetConstraint("< 1.5.0", version.RpmFormat), // from advisory
							),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed, // important! from advisory
								Versions: []string{"1.5.0"},           // important! from advisory, not the disclosure
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "vulnerability not fixed - package version not vulnerable",
			packageVersion: "2.0.0", // not vulnerable since 2.0.0 > 1.5.0
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0"},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{},
		},
		{
			name:           "multiple advisories with multiple fix versions",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{ // advisory does not apply!
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 0.9", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"0.9"},
							},
						},
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0", "1.4.2"},
							},
						},
						{ // duplicate advisory should already be counted from the first one
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0", "1.4.2"},
							},
						},
						{ // duplicate advisory, with a different fix version
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.4.3"},
							},
						},
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"2.0.0"},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.CombineConstraints( // important! we are combining the constraints
								version.MustGetConstraint("< 1.5.0", version.RpmFormat),
								version.MustGetConstraint("< 2.0.0", version.RpmFormat),
								version.MustGetConstraint("< 1.4.2", version.RpmFormat),
								version.MustGetConstraint("< 1.4.3", version.RpmFormat),
							),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.4.2", "1.4.3", "1.5.0", "2.0.0"}, // important! we have all fixes for advisories that apply
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "advisory with wont-fix state - disclosure should be kept with patched fix state",
			packageVersion: "1.0.0", // vulnerable since 1.0.0 < 2.0.0
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown, // important! the disclosure doesn't have good fix info
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateWontFix, // important! we want the match to reflect this property
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateWontFix,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "advisory with unknown fix state - disclosure should be kept",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{ // ultimately, this advisory does not apply...
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 3.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown, // important!
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat), // from the disclosure (nothing from the resolution since there was no fix information)
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "empty fix versions are filtered out",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"", "1.5.0", ""}, // important!
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0"}, // note: empty versions are filtered out
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "constraint satisfaction error - advisory skipped",
			packageVersion: "W:1.2.3-456", // intentionally invalid epoch (will fail to parse)
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0"},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{},
		},
		{
			name:           "no advisory overlay, disclosure has nil constraint - remove disclosure",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: nil, // important! we're never vulnerable!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{ // does not apply
					ID:              "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{},
					Details:         []match.Detail{},
				},
			},
			want: []result.Result{},
		},
		{
			name:           "no advisory overlay, disclosure has empty constraint - keep disclosure",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("", version.RpmFormat), // important! we're always vulnerable
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{ // does not apply
					ID:              "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{},
					Details:         []match.Detail{},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("", version.RpmFormat), // important! shows "none (rpm)"
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "no advisory overlay, disclosure does not apply - remove all",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 0.9", version.RpmFormat), // important! we're not vulnerable!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{ // does not apply
					ID:              "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{},
					Details:         []match.Detail{},
				},
			},
			want: []result.Result{},
		},
		{
			name:           "advisory with no fixes - disclosure is preserved",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateWontFix,
								Versions: []string{"1.5.0"}, // important: this is a wont-fix advisory so this should not be incorporated (an inconsistent advisory)
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateWontFix, // wont-fix state is preserved
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v *version.Version
			v = version.New(tt.packageVersion, version.RpmFormat)
			if v.Validate() != nil {
				v = nil
			}

			resolver := mergeEUSAdvisoriesIntoMainDisclosures(v, nil)

			got := resolver(tt.disclosures, tt.advisoryOverlay)

			opts := cmp.Options{
				cmpopts.IgnoreUnexported(result.Result{}),
				cmpopts.IgnoreUnexported(version.Version{}),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("mergeEUSAdvisoriesIntoMainDisclosures() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRedhatEUSMatches(t *testing.T) {
	testPkg1 := pkg.Package{
		ID:      pkg.ID("test-pkg-id"),
		Name:    "test-pkg",
		Version: "1.0.0",
		Type:    syftPkg.RpmPkg,
		Distro:  newEUSDistro("9.4"),
	}

	tests := []struct {
		name            string
		catalogPkg      pkg.Package
		searchPkg       *pkg.Package
		disclosureVulns []vulnerability.Vulnerability
		resolutionVulns []vulnerability.Vulnerability
		disclosureError error
		resolutionError error
		want            []match.Match
		wantErr         require.ErrorAssertionFunc
	}{
		{
			name:            "empty set of disclosures and advisories",
			catalogPkg:      testPkg1,
			disclosureVulns: []vulnerability.Vulnerability{},
			resolutionVulns: []vulnerability.Vulnerability{},
			want:            nil,
		},
		{
			name:       "successful EUS match with fix - direct match",
			catalogPkg: testPkg1,
			disclosureVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // same as searched package = direct match
					Constraint:  version.MustGetConstraint("< 1.5.0", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
			},
			resolutionVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // same as searched package = direct match
					Constraint:  version.MustGetConstraint("< 1.5.0", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"1.5.0"},
					},
				},
			},
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2021-1",
							Namespace: "namespace",
						},
						PackageName: "test-pkg",
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateFixed,
							Versions: []string{"1.5.0"},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("test-pkg-id"),
						Name:    "test-pkg",
						Version: "1.0.0",
						Type:    syftPkg.RpmPkg,
						Distro:  newEUSDistro("9.4"),
					},
					Details: []match.Detail{
						{
							Type: match.ExactDirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4",
								},
								Package: match.PackageParameter{
									Name:    "test-pkg",
									Version: "1.0.0",
								},
								Namespace: "namespace",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1",
								VersionConstraint: "< 1.5.0 (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
						{
							Type: match.ExactDirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4+eus",
								},
								Package: match.PackageParameter{
									Name:    "test-pkg",
									Version: "1.0.0",
								},
								Namespace: "namespace",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1",
								VersionConstraint: "< 1.5.0 (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
					},
				},
			},
		},
		{
			name:       "successful EUS match with fix - indirect match",
			catalogPkg: testPkg1,
			searchPkg: &pkg.Package{
				ID:      pkg.ID("indirect-test-pkg-id"),
				Name:    "indirect-test-pkg", // important! this will be detected as an indirect match
				Version: "1.0.0",
				Type:    syftPkg.RpmPkg,
				Distro:  newEUSDistro("9.4"),
			},
			disclosureVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "indirect-test-pkg", // setup to match search package name
					Constraint:  version.MustGetConstraint("< 1.5.0", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
			},
			resolutionVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "indirect-test-pkg", // setup to match search package name
					Constraint:  version.MustGetConstraint("< 1.5.0", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"1.5.0"},
					},
				},
			},
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2021-1",
							Namespace: "namespace",
						},
						PackageName: "indirect-test-pkg",
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateFixed,
							Versions: []string{"1.5.0"},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("test-pkg-id"),
						Name:    "test-pkg",
						Version: "1.0.0",
						Type:    syftPkg.RpmPkg,
						Distro:  newEUSDistro("9.4"),
					},
					Details: []match.Detail{
						{
							Type: match.ExactIndirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4",
								},
								Package: match.PackageParameter{
									Name:    "indirect-test-pkg", // important! we used the indirect package as input
									Version: "1.0.0",
								},
								Namespace: "namespace",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1",
								VersionConstraint: "< 1.5.0 (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
						{
							Type: match.ExactIndirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4+eus",
								},
								Package: match.PackageParameter{
									Name:    "indirect-test-pkg", // important! we used the indirect package as input
									Version: "1.0.0",
								},
								Namespace: "namespace",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1",
								VersionConstraint: "< 1.5.0 (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
					},
				},
			},
		},
		{
			name:       "valid disclosures found but no resolutions",
			catalogPkg: testPkg1,
			disclosureVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg",                                       // direct match
					Constraint:  version.MustGetConstraint("", version.RpmFormat), // no constraint, so always vulnerable
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
			},
			resolutionVulns: []vulnerability.Vulnerability{},
			want: []match.Match{ // keep the original disclosure as a match
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2021-1",
							Namespace: "namespace",
						},
						PackageName: "test-pkg",
						Constraint:  version.MustGetConstraint("", version.RpmFormat),
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateUnknown,
							Versions: []string{},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("test-pkg-id"),
						Name:    "test-pkg",
						Version: "1.0.0",
						Type:    syftPkg.RpmPkg,
						Distro:  newEUSDistro("9.4"),
					},
					Details: []match.Detail{
						{
							Type: match.ExactDirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4",
								},
								Package: match.PackageParameter{
									Name:    "test-pkg",
									Version: "1.0.0",
								},
								Namespace: "namespace",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1",
								VersionConstraint: "none (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
					},
				},
			},
		},
		{
			name: "vulnerability resolved by EUS advisory",
			catalogPkg: pkg.Package{
				ID:      pkg.ID("test-pkg-id"),
				Name:    "test-pkg",
				Version: "2.0.0", // version higher than fix, so resolved
				Type:    syftPkg.RpmPkg,
				Distro:  newEUSDistro("9.4"),
			},
			disclosureVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
			},
			resolutionVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Constraint:  version.MustGetConstraint("< 1.5.0", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"1.5.0"},
					},
				},
			},
			want: []match.Match{}, // vulnerability is resolved because package version 2.0.0 > 1.5.0
		},
		{
			name:       "multiple valid disclosures with mixed resolutions",
			catalogPkg: testPkg1,
			disclosureVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Constraint:  version.MustGetConstraint("", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-2",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Constraint:  version.MustGetConstraint("", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-3",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Constraint:  nil,        // no constraint, so we assume we're never vulnerable to this
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
			},
			resolutionVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Constraint:  version.MustGetConstraint("< 1.5.0", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"1.5.0"},
					},
				},
			},
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2021-1",
							Namespace: "namespace",
						},
						PackageName: "test-pkg",
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateFixed,
							Versions: []string{"1.5.0"},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("test-pkg-id"),
						Name:    "test-pkg",
						Version: "1.0.0",
						Type:    syftPkg.RpmPkg,
						Distro:  newEUSDistro("9.4"),
					},
					Details: []match.Detail{
						{
							Type: match.ExactDirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4",
								},
								Package: match.PackageParameter{
									Name:    "test-pkg",
									Version: "1.0.0",
								},
								Namespace: "namespace",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1",
								VersionConstraint: "< 1.5.0 (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
						{
							Type: match.ExactDirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4+eus",
								},
								Package: match.PackageParameter{
									Name:    "test-pkg",
									Version: "1.0.0",
								},
								Namespace: "namespace",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1",
								VersionConstraint: "< 1.5.0 (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
						{
							Type: match.ExactDirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4",
								},
								Package: match.PackageParameter{
									Name:    "test-pkg",
									Version: "1.0.0",
								},
								Namespace: "namespace",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1",
								VersionConstraint: "none (rpm)", // important! this is the disclosure with no constraint
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
					},
				},
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2021-2",
							Namespace: "namespace",
						},
						PackageName: "test-pkg",
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateUnknown,
							Versions: []string{},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("test-pkg-id"),
						Name:    "test-pkg",
						Version: "1.0.0",
						Type:    syftPkg.RpmPkg,
						Distro:  newEUSDistro("9.4"),
					},
					Details: []match.Detail{
						{
							Type: match.ExactDirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4",
								},
								Package: match.PackageParameter{
									Name:    "test-pkg",
									Version: "1.0.0",
								},
								Namespace: "namespace",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-2",
								VersionConstraint: "none (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
					},
				},
			},
		},
		{
			name:       "multiple advisories with mixed fix state relative to search package",
			catalogPkg: testPkg1,
			disclosureVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Constraint:  version.MustGetConstraint("", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
			},
			resolutionVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Constraint:  version.MustGetConstraint("< 1.5.0", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"1.5.0"},
					},
				},
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Constraint:  version.MustGetConstraint("< 1.0.0", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"1.0.0"},
					},
				},
			},
			want: []match.Match{},
		},
		{
			name:            "error fetching disclosures",
			catalogPkg:      testPkg1,
			disclosureVulns: []vulnerability.Vulnerability{},
			resolutionVulns: []vulnerability.Vulnerability{},
			disclosureError: errors.New("disclosure error"),
			want:            nil,
			wantErr:         require.Error,
		},
		{
			// This test case demonstrates issue #2847: when a user is on RHEL 9.4+eus and
			// the only available fix is for RHEL 9.5 (indicated by el9_5 in the fix version),
			// the vulnerability should NOT be reported as "Fixed" when using --only-fixed,
			// because the EUS user cannot upgrade to RHEL 9.5.
			name: "fix version for higher minor version should not be considered fixed for EUS - issue 2847",
			catalogPkg: pkg.Package{
				ID:      pkg.ID("kernel-id"),
				Name:    "kernel",
				Version: "5.14.0-427.79.1.el9_4", // user's current version on RHEL 9.4 EUS
				Type:    syftPkg.RpmPkg,
				Distro:  newEUSDistro("9.4"),
			},
			disclosureVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2020-10135",
						Namespace: "redhat:distro:redhat:9",
					},
					PackageName: "kernel",
					Constraint:  version.MustGetConstraint("< 5.14.0-503.11.1.el9_5", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
			},
			resolutionVulns: []vulnerability.Vulnerability{
				{
					// This fix is for RHEL 9.5 (indicated by el9_5 in the version),
					// which is NOT available to RHEL 9.4 EUS users
					Reference: vulnerability.Reference{
						ID:        "CVE-2020-10135",
						Namespace: "redhat:distro:redhat:9",
					},
					PackageName: "kernel",
					Constraint:  version.MustGetConstraint("< 5.14.0-503.11.1.el9_5", version.RpmFormat),
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateFixed,
						Versions: []string{"5.14.0-503.11.1.el9_5"}, // note: el9_5 indicates RHEL 9.5
					},
				},
			},
			// Expected behavior: since the fix requires upgrading to RHEL 9.5 and the user
			// is on RHEL 9.4 EUS (can't upgrade to 9.5), the fix should NOT be considered
			// valid and the FixState should be NotFixed (not Fixed).
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2020-10135",
							Namespace: "redhat:distro:redhat:9",
						},
						PackageName: "kernel",
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateNotFixed, // fix exists but not reachable for EUS 9.4
							Versions: []string{},                     // no valid fixes for EUS 9.4
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("kernel-id"),
						Name:    "kernel",
						Version: "5.14.0-427.79.1.el9_4",
						Type:    syftPkg.RpmPkg,
						Distro:  newEUSDistro("9.4"),
					},
					Details: []match.Detail{
						{
							Type: match.ExactDirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4",
								},
								Package: match.PackageParameter{
									Name:    "kernel",
									Version: "5.14.0-427.79.1.el9_4",
								},
								Namespace: "redhat:distro:redhat:9",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2020-10135",
								VersionConstraint: "< 5.14.0-503.11.1.el9_5 (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
						{
							Type: match.ExactDirectMatch,
							SearchedBy: match.DistroParameters{
								Distro: match.DistroIdentification{
									Type:    "redhat",
									Version: "9.4+eus",
								},
								Package: match.PackageParameter{
									Name:    "kernel",
									Version: "5.14.0-427.79.1.el9_4",
								},
								Namespace: "redhat:distro:redhat:9",
							},
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2020-10135",
								VersionConstraint: "< 5.14.0-503.11.1.el9_5 (rpm)",
							},
							Matcher:    match.RpmMatcher,
							Confidence: 1,
						},
					},
				},
			},
		},
		{
			name:       "error fetching resolutions",
			catalogPkg: testPkg1,
			disclosureVulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1",
						Namespace: "namespace",
					},
					PackageName: "test-pkg", // direct match
					Fix: vulnerability.Fix{
						State:    vulnerability.FixStateUnknown,
						Versions: []string{},
					},
				},
			},
			resolutionVulns: []vulnerability.Vulnerability{},
			resolutionError: errors.New("resolution error"),
			want:            nil,
			wantErr:         require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			if tt.searchPkg == nil {
				tt.searchPkg = &tt.catalogPkg
			}

			vulnProvider := newMockVulnProvider()
			vulnProvider.setDisclosureVulns(tt.disclosureVulns)
			vulnProvider.setResolutionVulns(tt.resolutionVulns)
			vulnProvider.setDisclosureError(tt.disclosureError)
			vulnProvider.setResolutionError(tt.resolutionError)

			resultProvider := result.NewProvider(vulnProvider, tt.catalogPkg, match.RpmMatcher)

			got, err := redhatEUSMatches(resultProvider, *tt.searchPkg, "zero")
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			// need stable results for comparison
			sort.Sort(match.ByElements(got))

			opts := cmp.Options{
				cmpopts.IgnoreUnexported(version.Version{}),
				cmpopts.IgnoreUnexported(distro.Distro{}),
				cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
				cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("redhatEUSMatches() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func strRef(s string) *string {
	return &s
}

func intRef(s int) *int {
	return &s
}

// Mock vulnerability provider for testing
type mockVulnProvider struct {
	// cheaply get a working interface that will panic when functionality is not overridden
	vulnerability.Provider

	disclosureVulns []vulnerability.Vulnerability
	resolutionVulns []vulnerability.Vulnerability
	disclosureError error
	resolutionError error
	callCount       int
}

func newMockVulnProvider() *mockVulnProvider {
	return &mockVulnProvider{}
}

func (m *mockVulnProvider) setDisclosureVulns(vulns []vulnerability.Vulnerability) {
	m.disclosureVulns = vulns
}

func (m *mockVulnProvider) setResolutionVulns(vulns []vulnerability.Vulnerability) {
	m.resolutionVulns = vulns
}

func (m *mockVulnProvider) setDisclosureError(err error) {
	m.disclosureError = err
}

func (m *mockVulnProvider) setResolutionError(err error) {
	m.resolutionError = err
}

func (m *mockVulnProvider) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	m.callCount++

	// heuristic: first call is for disclosures (base distro), second is for resolutions (base + eus distro)
	if m.callCount == 1 {
		if m.disclosureError != nil {
			return nil, m.disclosureError
		}
		return m.disclosureVulns, nil
	}

	if m.resolutionError != nil {
		return nil, m.resolutionError
	}
	return m.resolutionVulns, nil
}

func channels(s ...string) []string {
	return s
}

// newEUSDistro creates a properly initialized RHEL EUS distro using distro.New().
// This ensures MajorVersion()/MinorVersion() work correctly.
// Pass version like "9.4" (the "+eus" channel suffix is added automatically).
// Pass empty string for a distro without a version.
func newEUSDistro(version string) *distro.Distro {
	if version == "" {
		// For empty version, we need to set channels manually since "+eus" alone
		// doesn't parse well
		d := distro.New(distro.RedHat, "", "")
		d.Channels = []string{"eus"}
		return d
	}
	return distro.New(distro.RedHat, version+"+eus", "")
}
