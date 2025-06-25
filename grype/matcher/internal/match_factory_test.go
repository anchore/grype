package internal

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/file"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestBuildFixConstraint(t *testing.T) {
	tests := []struct {
		name              string
		vulnerability     vulnerability.Vulnerability
		wantConstraintStr string
		wantErr           require.BoolAssertionFunc
	}{
		{
			name: "single fix version",
			vulnerability: vulnerability.Vulnerability{
				Fix: vulnerability.Fix{
					Versions: []string{"1.2.3"},
				},
				Constraint: version.MustGetConstraint("< 1.0.0", version.SemanticFormat),
			},
			wantConstraintStr: "< 1.2.3 (semantic)",
			wantErr:           require.False,
		},
		{
			name: "multiple fix versions",
			vulnerability: vulnerability.Vulnerability{
				Fix: vulnerability.Fix{
					Versions: []string{"1.2.3", "2.0.0"},
				},
				Constraint: version.MustGetConstraint("< 1.0.0", version.SemanticFormat),
			},
			wantConstraintStr: "< 1.2.3 || < 2.0.0 (semantic)",
			wantErr:           require.False,
		},
		{
			name: "no fix versions returns nil constraint",
			vulnerability: vulnerability.Vulnerability{
				Fix: vulnerability.Fix{
					Versions: nil,
				},
				Constraint: version.MustGetConstraint("< 1.0.0", version.SemanticFormat),
			},
			wantConstraintStr: "",
			wantErr:           require.False,
		},
		{
			name: "empty fix versions returns nil constraint",
			vulnerability: vulnerability.Vulnerability{
				Fix: vulnerability.Fix{
					Versions: []string{},
				},
				Constraint: version.MustGetConstraint("< 1.0.0", version.SemanticFormat),
			},
			wantConstraintStr: "",
			wantErr:           require.False,
		},
		{
			name: "rpm format constraint",
			vulnerability: vulnerability.Vulnerability{
				Fix: vulnerability.Fix{
					Versions: []string{"1.2.3-4.el8"},
				},
				Constraint: version.MustGetConstraint("< 1.0.0", version.RpmFormat),
			},
			wantConstraintStr: "< 1.2.3-4.el8 (rpm)",
			wantErr:           require.False,
		},
		{
			name: "deb format constraint",
			vulnerability: vulnerability.Vulnerability{
				Fix: vulnerability.Fix{
					Versions: []string{"1.2.3-1ubuntu1"},
				},
				Constraint: version.MustGetConstraint("< 1.0.0", version.DebFormat),
			},
			wantConstraintStr: "< 1.2.3-1ubuntu1 (deb)",
			wantErr:           require.False,
		},
		{
			name: "apk format constraint",
			vulnerability: vulnerability.Vulnerability{
				Fix: vulnerability.Fix{
					Versions: []string{"1.2.3-r0"},
				},
				Constraint: version.MustGetConstraint("< 1.0.0", version.ApkFormat),
			},
			wantConstraintStr: "< 1.2.3-r0 (apk)",
			wantErr:           require.False,
		},
		{
			name: "python format constraint",
			vulnerability: vulnerability.Vulnerability{
				Fix: vulnerability.Fix{
					Versions: []string{"1.2.3"},
				},
				Constraint: version.MustGetConstraint("< 1.0.0", version.PythonFormat),
			},
			wantConstraintStr: "< 1.2.3 (python)",
			wantErr:           require.False,
		},
		{
			name: "three fix versions with OR logic (honor input order)",
			vulnerability: vulnerability.Vulnerability{
				Fix: vulnerability.Fix{
					Versions: []string{"3.1.1", "1.2.3", "2.0.0"},
				},
				Constraint: version.MustGetConstraint("< 1.0.0", version.SemanticFormat),
			},
			wantConstraintStr: "< 3.1.1 || < 1.2.3 || < 2.0.0 (semantic)",
			wantErr:           require.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := buildFixConstraint(tt.vulnerability)

			if tt.wantConstraintStr == "" {
				if !assert.Nil(t, constraint) {
					t.Errorf("expected nil constraint, got: %v", constraint)
				}
				return
			}

			require.NotNil(t, constraint)
			require.Equal(t, tt.wantConstraintStr, constraint.String())
			require.Equal(t, tt.vulnerability.Constraint.Format(), constraint.Format())
		})
	}
}

func TestBuildFixConstraint_InvalidConstraintFormat(t *testing.T) {
	// create a vulnerability with an invalid constraint format that would cause GetConstraint to fail
	v := vulnerability.Vulnerability{
		Fix: vulnerability.Fix{
			Versions: []string{"invalid version format >>><<<<"},
		},
		Constraint: version.MustGetConstraint("< 1.0.0", version.SemanticFormat),
	}

	// buildFixConstraint should return nil when constraint parsing fails
	constraint := buildFixConstraint(v)
	require.Nil(t, constraint)
}

func TestMatchFactory_Matches(t *testing.T) {
	d := distro.New(distro.Debian, "11", "")
	namespace := "debian:distro:debian:11"
	curl7680Pkg := pkg.Package{
		Name:    "curl",
		Version: "7.68.0",
		Type:    syftPkg.DebPkg,
	}

	curl7900Fix := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2021-1234",
			Namespace: namespace,
		},
		PackageName: "curl",
		Constraint:  version.MustGetConstraint("dont care", version.DebFormat), // we only need the version format here
		Fix: vulnerability.Fix{
			Versions: []string{"7.90.0"},
			State:    vulnerability.FixStateFixed,
		},
	}

	searchedByCurl7680 := match.DistroParameters{
		Distro: match.DistroIdentification{
			Type:    d.Type.String(),
			Version: d.Version,
		},
		Package: match.PackageParameter{
			Name:    curl7680Pkg.Name,
			Version: curl7680Pkg.Version,
		},
		Namespace: namespace,
	}

	curlDirectMatchPrototype := MatchDetailPrototype{
		RefPackage: nil,
		Matcher:    match.DpkgMatcher,
		SearchedBy: match.DistroParameters{
			Distro: match.DistroIdentification{
				Type:    d.Type.String(),
				Version: d.Version,
			},
			Package: match.PackageParameter{
				Name:    "curl",
				Version: "7.68.0",
			},
			Namespace: namespace,
		},
	}

	distroFoundGenerator := func(v vulnerability.Vulnerability) any {
		return match.DistroResult{
			VulnerabilityID:   v.ID,
			VersionConstraint: v.Constraint.String(),
		}
	}

	tests := []struct {
		name             string
		pkg              pkg.Package
		disclosureConfig DisclosureConfig
		disclosures      []vulnerability.Vulnerability
		resolutions      []vulnerability.Vulnerability
		wantMatches      []match.Match
		wantErr          require.ErrorAssertionFunc
	}{
		{
			name: "disclosure only - no resolutions",
			pkg:  curl7680Pkg,
			disclosureConfig: DisclosureConfig{
				KeepFixVersions:      false,
				FoundGenerator:       distroFoundGenerator,
				MatchDetailPrototype: curlDirectMatchPrototype,
			},
			disclosures: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1234",
						Namespace: namespace,
					},
					PackageName: "curl",
					Constraint:  version.MustGetConstraint("< 7.90.0", version.DebFormat),
				},
			},
			resolutions: nil,
			wantMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2021-1234",
							Namespace: namespace,
						},
						PackageName: "curl",
						Constraint:  version.MustGetConstraint("< 7.90.0", version.DebFormat), // important! from the disclosure directly
					},
					Package: curl7680Pkg,
					Details: []match.Detail{
						{
							Type:       match.ExactDirectMatch,
							Matcher:    match.DpkgMatcher,
							Confidence: 1.0,
							SearchedBy: searchedByCurl7680,
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1234",
								VersionConstraint: "< 7.90.0 (deb)",
							},
						},
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "disclosure paired with resolution",
			pkg:  curl7680Pkg,
			disclosureConfig: DisclosureConfig{
				KeepFixVersions:      false,
				FoundGenerator:       distroFoundGenerator,
				MatchDetailPrototype: curlDirectMatchPrototype,
			},
			disclosures: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-1234",
						Namespace: namespace,
					},
					PackageName: "curl",
					Constraint:  version.MustGetConstraint("< from disclosure", version.DebFormat), // we need to track that the constraint is from the disclosure
				},
			},
			resolutions: []vulnerability.Vulnerability{
				curl7900Fix,
			},
			wantMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2021-1234",
							Namespace: namespace,
						},
						Fix: vulnerability.Fix{
							Versions: []string{"7.90.0"},
							State:    vulnerability.FixStateFixed,
						},
						PackageName: "curl",
						Constraint:  version.MustGetConstraint("< 7.90.0", version.DebFormat), // built from the fix versions
					},
					Package: curl7680Pkg,
					Details: []match.Detail{
						{
							Type:       match.ExactDirectMatch,
							Matcher:    match.DpkgMatcher,
							Confidence: 1.0,
							SearchedBy: searchedByCurl7680,
							Found: match.DistroResult{
								VulnerabilityID:   "CVE-2021-1234",
								VersionConstraint: "< from disclosure (deb)",
							},
						},
					},
				},
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewMatchFactory(tt.pkg)

			// add disclosures
			if len(tt.disclosures) > 0 {
				factory.AddVulnsAsDisclosures(tt.disclosureConfig, tt.disclosures...)
			}

			// add resolutions
			if len(tt.resolutions) > 0 {
				factory.AddVulnsAsResolutions(tt.resolutions...)
			}

			// get matches
			matches, err := factory.Matches()
			tt.wantErr(t, err)

			// compare matches
			opts := []cmp.Option{
				cmpopts.IgnoreUnexported(file.LocationSet{}),
				cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
			}

			if diff := cmp.Diff(tt.wantMatches, matches, opts...); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
