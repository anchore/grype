package dpkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// TestResolveESMDisclosures exercises mergeESMAdvisoriesIntoMainDisclosures, the pure data-merging helper that fuses a
// base Ubuntu disclosure with its ESM (+esm) advisory overlay. It is the dpkg twin of the rpm package's
// TestResolveEUSDisclosures. The function operates on result.Result inputs (not the DB), so synthetic inputs are
// appropriate here - these tests verify each branch of the merge logic independent of any real-world data shape.
func TestResolveESMDisclosures(t *testing.T) {
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
							Constraint: version.MustGetConstraint("< 1.6.0", version.DebFormat), // important!
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
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat), // important!
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
								version.MustGetConstraint("< 1.6.0", version.DebFormat), // from disclosure
								version.MustGetConstraint("< 1.5.0", version.DebFormat), // from advisory
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
			name:           "vulnerability fixed - package version not vulnerable",
			packageVersion: "2.0.0", // not vulnerable since 2.0.0 > 1.5.0
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat), // important!
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
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat), // important!
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
			name:           "multiple advisories with multiple fix versions - only applicable fixes kept and deduped",
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
						{ // advisory does not apply (fix below installed version)!
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 0.9", version.DebFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"0.9"},
							},
						},
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0", "1.4.2"},
							},
						},
						{ // duplicate advisory should already be counted from the first one
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0", "1.4.2"},
							},
						},
						{ // duplicate advisory, with a different fix version
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.4.3"},
							},
						},
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.DebFormat),
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
								version.MustGetConstraint("< 1.5.0", version.DebFormat),
								version.MustGetConstraint("< 2.0.0", version.DebFormat),
								version.MustGetConstraint("< 1.4.2", version.DebFormat),
								version.MustGetConstraint("< 1.4.3", version.DebFormat),
							),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.4.2", "1.4.3", "1.5.0", "2.0.0"}, // important! all fixes for advisories that apply
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "advisory with wont-fix state - disclosure kept with patched fix state",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.DebFormat),
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
							Constraint: version.MustGetConstraint("< 2.0.0", version.DebFormat),
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
							Constraint: version.MustGetConstraint("< 2.0.0", version.DebFormat),
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
			name:           "advisory with unknown fix state - disclosure kept",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.DebFormat),
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
							Constraint: version.MustGetConstraint("< 3.0.0", version.DebFormat),
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
							Constraint: version.MustGetConstraint("< 2.0.0", version.DebFormat), // from the disclosure (no fix info from the overlay)
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
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat),
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
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat),
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
			packageVersion: "W:1.2.3-456", // intentionally invalid epoch (will fail to parse) -> nil version
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat),
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
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat),
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
							Constraint: version.MustGetConstraint("", version.DebFormat), // important! we're always vulnerable
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
							Constraint: version.MustGetConstraint("", version.DebFormat), // important! shows "none (dpkg)"
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
							Constraint: version.MustGetConstraint("< 0.9", version.DebFormat), // important! we're not vulnerable!
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
			name:           "wont-fix advisory carrying a fix version - fix not incorporated, disclosure preserved",
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
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateWontFix,
								Versions: []string{"1.5.0"}, // important: wont-fix advisory, so this fix should not be incorporated (inconsistent advisory)
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
							Constraint: version.MustGetConstraint("< 1.5.0", version.DebFormat),
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
			v := version.New(tt.packageVersion, version.DebFormat)
			if v.Validate() != nil {
				v = nil
			}

			resolver := mergeESMAdvisoriesIntoMainDisclosures(v)

			got := resolver(tt.disclosures, tt.advisoryOverlay)

			opts := cmp.Options{
				cmpopts.IgnoreUnexported(result.Result{}),
				cmpopts.IgnoreUnexported(version.Version{}),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("mergeESMAdvisoriesIntoMainDisclosures() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
