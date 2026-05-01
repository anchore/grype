package rpm

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
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

// TestResolveEUSDisclosures exercises mergeEUSAdvisoriesIntoMainDisclosures, a
// pure data-merging helper that combines a base RHEL disclosure with an EUS
// advisory overlay. The function operates on result.Result inputs (not the
// DB), so synthetic inputs are appropriate here - these tests verify each
// branch of the merge logic independent of any real-world data shape.
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
							Constraint: version.CombineConstraints(
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
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
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
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
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
							Constraint: version.MustGetConstraint("< 3.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
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
								Versions: []string{"", "1.5.0", ""},
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

// EUS findings consistently produce three details per match: a base-distro
// lookup against the EUS-overlay fix, a +eus-distro lookup against the same
// EUS-overlay fix, and a base-distro lookup against the mainline RHEL fix.
// These constants name the constraint strings that disambiguate them - tests
// use them with SelectDetailByDistro to assert each detail explicitly.
const (
	eus94CVE20240340OverlayConstraint   = "< 0:5.14.0-427.68.1.el9_4 (rpm)"
	eus94CVE20240340MainlineConstraint  = "< 0:5.14.0-503.11.1.el9_5 (rpm)"
	eus94CVE202147527OverlayConstraint  = "< 0:5.14.0-427.81.1.el9_4 (rpm)"
	eus94CVE202147527MainlineConstraint = "none (unknown)" // no mainline fix
)

// assertEUSTriplet asserts the three-detail shape of an EUS match: one detail
// at the base distro searched against the EUS-overlay fix constraint, one at
// the +eus distro for the same overlay fix, and one at the base distro
// searched against the mainline RHEL fix constraint. All three details should
// have the same match type. Each call to SelectDetailByDistro both selects
// (using the constraint to disambiguate) and marks the detail as completed,
// so the FindingsAssertion's completeness check passes for the match.
func assertEUSTriplet(t *testing.T, sf *dbtest.SingleFindingAssertion, baseVersion, overlayConstraint, mainlineConstraint string, mt match.Type) {
	t.Helper()
	sf.SelectDetailByDistro("redhat", baseVersion, overlayConstraint).HasMatchType(mt)
	sf.SelectDetailByDistro("redhat", baseVersion+"+eus", overlayConstraint).HasMatchType(mt)
	sf.SelectDetailByDistro("redhat", baseVersion, mainlineConstraint).HasMatchType(mt)
}

// TestRedhatEUSMatches_VulnerableOnEUS verifies that a kernel package below the
// EUS fix version produces a match using real RHEL EUS data.
func TestRedhatEUSMatches_VulnerableOnEUS(t *testing.T) {
	dbtest.DBs(t, "rhel9-eus").
		SelectOnly("CVE-2024-0340").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// EUS 9.4 fix is 5.14.0-427.68.1.el9_4; 100 < 427 → vulnerable
			p := dbtest.NewPackage("kernel", "0:5.14.0-100.el9_4", syftPkg.RpmPkg).
				WithDistro(newEUSDistro("9.4")).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			findings := db.Match(t, &matcher, p).
				HasCount(1).
				ContainsVulnerabilities("CVE-2024-0340")
			findings.Ignores().IsEmpty()

			sf := findings.SelectMatch("CVE-2024-0340")
			// fix info should reflect the EUS-reachable fix, not the mainline one
			sf.HasFix(vulnerability.FixStateFixed, "0:5.14.0-427.68.1.el9_4")
			assertEUSTriplet(t, sf, "9.4",
				eus94CVE20240340OverlayConstraint,
				eus94CVE20240340MainlineConstraint,
				match.ExactDirectMatch)
		})
}

// TestRedhatEUSMatches_IndirectMatchBySource verifies that a binary RPM
// (kernel-tools) reaches an EUS-tracked CVE through its upstream source RPM
// (kernel). CVE-2024-0340's FixedIn has only "kernel" (the source); the binary
// must match via upstream, producing an ExactIndirectMatch on each of the
// three EUS-triplet details.
func TestRedhatEUSMatches_IndirectMatchBySource(t *testing.T) {
	dbtest.DBs(t, "rhel9-eus").
		SelectOnly("CVE-2024-0340").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("kernel-tools", "0:5.14.0-100.el9_4", syftPkg.RpmPkg).
				WithDistro(newEUSDistro("9.4")).
				WithUpstream("kernel", "0:5.14.0-100.el9_4").
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			findings := db.Match(t, &matcher, p).
				HasCount(1).
				ContainsVulnerabilities("CVE-2024-0340")
			findings.Ignores().IsEmpty()

			sf := findings.SelectMatch("CVE-2024-0340")
			assertEUSTriplet(t, sf, "9.4",
				eus94CVE20240340OverlayConstraint,
				eus94CVE20240340MainlineConstraint,
				match.ExactIndirectMatch)
		})
}

// TestRedhatEUSMatches_FixedOnEUS verifies that a package at the EUS fix
// version is not vulnerable - the EUS resolution overrides the broader RHEL
// disclosure.
func TestRedhatEUSMatches_FixedOnEUS(t *testing.T) {
	dbtest.DBs(t, "rhel9-eus").
		SelectOnly("CVE-2024-0340").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("kernel", "0:5.14.0-427.68.1.el9_4", syftPkg.RpmPkg).
				WithDistro(newEUSDistro("9.4")).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

// TestRedhatEUSMatches_BetweenEUSAndMainFix verifies that a package below the
// mainline fix but at-or-past the EUS fix is treated as resolved (the EUS
// resolution wins because the user is on EUS).
func TestRedhatEUSMatches_BetweenEUSAndMainFix(t *testing.T) {
	dbtest.DBs(t, "rhel9-eus").
		SelectOnly("CVE-2024-0340").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// 450 > EUS fix 427.68 but < main fix 503.11 → resolved per EUS
			p := dbtest.NewPackage("kernel", "0:5.14.0-450.el9_4", syftPkg.RpmPkg).
				WithDistro(newEUSDistro("9.4")).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

// TestRedhatEUSMatches_MultipleCVEsAllVulnerable verifies that when multiple
// EUS-tracked CVEs all apply (pkg below all fixes), the matcher reports them
// all as matches with no ignores. Uses the rhel9-eus fixture in full (no
// SelectOnly), which contains CVE-2024-0340 (EUS fix at 427.68) and
// CVE-2021-47527 (Version "None"). Pkg at 300 < 427 → both apply.
func TestRedhatEUSMatches_MultipleCVEsAllVulnerable(t *testing.T) {
	dbtest.DBs(t, "rhel9-eus").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		p := dbtest.NewPackage("kernel", "0:5.14.0-300.el9_4", syftPkg.RpmPkg).
			WithDistro(newEUSDistro("9.4")).
			WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
			Build()

		findings := db.Match(t, &matcher, p).
			OnlyHasVulnerabilities("CVE-2024-0340", "CVE-2021-47527")
		findings.Ignores().IsEmpty()

		assertEUSTriplet(t, findings.SelectMatch("CVE-2024-0340"), "9.4",
			eus94CVE20240340OverlayConstraint,
			eus94CVE20240340MainlineConstraint,
			match.ExactDirectMatch)
		assertEUSTriplet(t, findings.SelectMatch("CVE-2021-47527"), "9.4",
			eus94CVE202147527OverlayConstraint,
			eus94CVE202147527MainlineConstraint,
			match.ExactDirectMatch)
	})
}

// TestRedhatEUSMatches_MultipleCVEsAllIgnored verifies that when a package is
// past all EUS fixes for the CVEs it would otherwise be susceptible to, every
// CVE becomes a "Distro Not Vulnerable" ignore. Pkg at 500 > EUS fix 427.68
// for CVE-2024-0340; CVE-2021-47527 has no fix recorded (Version "None") and
// flows through the same not-vulnerable path once disclosures are filtered.
func TestRedhatEUSMatches_MultipleCVEsAllIgnored(t *testing.T) {
	dbtest.DBs(t, "rhel9-eus").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		pkgID := pkg.ID("kernel-past-fixes")
		p := dbtest.NewPackage("kernel", "0:5.14.0-500.el9_4", syftPkg.RpmPkg).
			WithID(pkgID).
			WithDistro(newEUSDistro("9.4")).
			WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
			Build()

		findings := db.Match(t, &matcher, p)
		findings.IsEmpty()
		// both EUS CVEs should produce ignores against this package
		igs := findings.Ignores().HasCount(2)
		igs.SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2024-0340").
			ForPackage(pkgID)
		igs.SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2021-47527").
			ForPackage(pkgID)
	})
}

// TestRedhatEUSIgnoreFilters_FixedProducesIgnore verifies that an EUS-fixed
// package produces a "Distro Not Vulnerable" IgnoreRelatedPackage filter.
func TestRedhatEUSIgnoreFilters_FixedProducesIgnore(t *testing.T) {
	dbtest.DBs(t, "rhel9-eus").
		SelectOnly("CVE-2024-0340").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("kernel-eus-fixed")
			p := dbtest.NewPackage("kernel", "0:5.14.0-427.68.1.el9_4", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(newEUSDistro("9.4")).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()
			findings.Ignores().
				HasCount(1).
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2024-0340").
				ForPackage(pkgID)
		})
}

// TestRedhatEUSIgnoreFilters_VulnerablePackageNoIgnores verifies that a
// still-vulnerable EUS package produces a match and no ignore filters.
func TestRedhatEUSIgnoreFilters_VulnerablePackageNoIgnores(t *testing.T) {
	dbtest.DBs(t, "rhel9-eus").
		SelectOnly("CVE-2024-0340").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("kernel", "0:5.14.0-200.el9_4", syftPkg.RpmPkg).
				WithDistro(newEUSDistro("9.4")).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			findings := db.Match(t, &matcher, p).
				HasCount(1).
				ContainsVulnerabilities("CVE-2024-0340")
			findings.Ignores().IsEmpty()

			assertEUSTriplet(t, findings.SelectMatch("CVE-2024-0340"), "9.4",
				eus94CVE20240340OverlayConstraint,
				eus94CVE20240340MainlineConstraint,
				match.ExactDirectMatch)
		})
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
