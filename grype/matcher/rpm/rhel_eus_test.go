package rpm

import (
	"errors"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestResolveEUSDisclosures(t *testing.T) {
	tests := []struct {
		name                     string
		packageVersion           string
		resolutionsAsDisclosures bool
		disclosures              []result.Result
		advisoryOverlay          []result.Result
		want                     []result.Result
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

			resolver := mergeEUSAdvisoriesIntoMainDisclosures(v, tt.resolutionsAsDisclosures)

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
		Distro: &distro.Distro{
			Type:     distro.RedHat,
			Version:  "9.4",
			Channels: channels("eus"),
		},
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
						Distro: &distro.Distro{
							Type:     distro.RedHat,
							Version:  "9.4",
							Channels: channels("eus"),
						},
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
				Distro: &distro.Distro{
					Type:     distro.RedHat,
					Version:  "9.4",
					Channels: channels("eus"),
				},
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
						Distro: &distro.Distro{
							Type:     distro.RedHat,
							Version:  "9.4",
							Channels: channels("eus"),
						},
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
						Distro: &distro.Distro{
							Type:     distro.RedHat,
							Version:  "9.4",
							Channels: channels("eus"),
						},
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
				Distro: &distro.Distro{
					Type:     distro.RedHat,
					Version:  "9.4",
					Channels: channels("eus"),
				},
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
						Distro: &distro.Distro{
							Type:     distro.RedHat,
							Version:  "9.4",
							Channels: channels("eus"),
						},
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
						Distro: &distro.Distro{
							Type:     distro.RedHat,
							Version:  "9.4",
							Channels: channels("eus"),
						},
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
