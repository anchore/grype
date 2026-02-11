package nvd

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/nvd"
)

func newUniquePkgTrackerFromSlice(candidates []pkgCandidate) uniquePkgTracker {
	set := newUniquePkgTracker()
	for _, c := range candidates {
		set[c] = nil
	}
	return set
}

func TestFindUniquePkgs(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		nodes    []nvd.Node
		operator *nvd.Operator
		expected uniquePkgTracker
	}{
		{
			name: "simple-match",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendor:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendor",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name: "skip-hw",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:h:vendor:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice([]pkgCandidate{}),
		},
		{
			name: "skip-os-by-default",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:o:vendor:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice([]pkgCandidate{}),
		},
		{
			name: "include-os-explicitly",
			config: Config{
				CPEParts: strset.New("a", "o"),
			},
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:o:vendor:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice([]pkgCandidate{
				{
					Product:        "product",
					Vendor:         "vendor",
					TargetSoftware: "target",
				},
			}),
		},
		{
			name: "duplicate-by-product",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendor:productA:3.3.3:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
						{
							Criteria:   "cpe:2.3:a:vendor:productB:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "productA",
						Vendor:         "vendor",
						TargetSoftware: "target",
					},
					{
						Product:        "productB",
						Vendor:         "vendor",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name: "duplicate-by-target",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendor:product:3.3.3:*:*:*:*:targetA:*:*",
							Vulnerable: true,
						},
						{
							Criteria:   "cpe:2.3:a:vendor:product:2.2.0:*:*:*:*:targetB:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendor",
						TargetSoftware: "targetA",
					},
					{
						Product:        "product",
						Vendor:         "vendor",
						TargetSoftware: "targetB",
					},
				}),
		},
		{
			name: "duplicate-by-vendor",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendorA:product:3.3.3:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
						{
							Criteria:   "cpe:2.3:a:vendorB:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendorA",
						TargetSoftware: "target",
					},
					{
						Product:        "product",
						Vendor:         "vendorB",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name: "de-duplicate-case",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendor:product:3.3.3:A:B:C:D:target:E:F",
							Vulnerable: true,
						},
						{
							Criteria:   "cpe:2.3:a:vendor:product:2.2.0:Q:R:S:T:target:U:V",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendor",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name: "duplicate-from-nested-nodes",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendorB:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendorA:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendorA",
						TargetSoftware: "target",
					},
					{
						Product:        "product",
						Vendor:         "vendorB",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name:     "cpe with multiple platforms",
			operator: opRef(nvd.And),
			nodes: []nvd.Node{
				{
					Negate:   boolRef(false),
					Operator: nvd.Or,
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:        "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
							MatchCriteriaID: "902B8056-9E37-443B-8905-8AA93E2447FB",
							Vulnerable:      false,
						},
						{
							Criteria:        "cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*",
							MatchCriteriaID: "3D94DA3B-FA74-4526-A0A0-A872684598C6",
							Vulnerable:      false,
						},
						{
							Criteria:        "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
							MatchCriteriaID: "DEECE5FC-CACF-4496-A3E7-164736409252",
							Vulnerable:      false,
						},
						{
							Criteria:        "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
							MatchCriteriaID: "07B237A9-69A3-4A9C-9DA0-4E06BD37AE73",
							Vulnerable:      false,
						},
						{
							Criteria:        "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
							MatchCriteriaID: "FA6FEEC2-9F11-4643-8827-749718254FED",
							Vulnerable:      false,
						},
					},
				},
				{
					Negate:   boolRef(false),
					Operator: nvd.Or,
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:        "cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*",
							MatchCriteriaID: "5EBE5E1C-C881-4A76-9E36-4FB7C48427E6",
							Vulnerable:      true,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice([]pkgCandidate{
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
				},
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*",
				},
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
				},
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
				},
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
				},
			}),
		},
		{
			name:     "single platform CPE as first element",
			operator: opRef(nvd.And),
			nodes: []nvd.Node{
				{
					Negate:   boolRef(false),
					Operator: nvd.Or,
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:        "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
							MatchCriteriaID: "902B8056-9E37-443B-8905-8AA93E2447FB",
							Vulnerable:      false,
						},
					},
				},
				{
					Negate:   boolRef(false),
					Operator: nvd.Or,
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:              "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   strRef("1.22.2"),
							VersionStartIncluding: strRef("1.22"),
							MatchCriteriaID:       "5EBE5E1C-C881-4A76-9E36-4FB7C48427E6",
							Vulnerable:            true,
						},
						{
							Criteria:            "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*",
							VersionEndExcluding: strRef("1.21.8"),
							MatchCriteriaID:     "5EBE5E1C-C881-4A76-9E36-4FB7C48427E6",
							Vulnerable:          true,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice([]pkgCandidate{
				{
					Product:        "go",
					Vendor:         "golang",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
				},
			}),
		},
		{
			name:     "single platform CPE as last element",
			operator: opRef(nvd.And),
			nodes: []nvd.Node{
				{
					Negate:   boolRef(false),
					Operator: nvd.Or,
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:              "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*",
							VersionEndExcluding:   strRef("1.22.2"),
							VersionStartIncluding: strRef("1.22"),
							MatchCriteriaID:       "5EBE5E1C-C881-4A76-9E36-4FB7C48427E6",
							Vulnerable:            true,
						},
						{
							Criteria:            "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*",
							VersionEndExcluding: strRef("1.21.8"),
							MatchCriteriaID:     "5EBE5E1C-C881-4A76-9E36-4FB7C48427E6",
							Vulnerable:          true,
						},
					},
				},
				{
					Negate:   boolRef(false),
					Operator: nvd.Or,
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:        "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
							MatchCriteriaID: "902B8056-9E37-443B-8905-8AA93E2447FB",
							Vulnerable:      false,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice([]pkgCandidate{
				{
					Product:        "go",
					Vendor:         "golang",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
				},
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.config == (Config{}) {
				test.config = defaultConfig()
			}
			actual := findUniquePkgs(test.config, nvd.Configuration{Nodes: test.nodes, Operator: test.operator})
			missing, extra := test.expected.Diff(actual)
			if len(missing) != 0 {
				for _, c := range missing {
					t.Errorf("missing candidate: %+v", c)
				}
			}

			if len(extra) != 0 {
				for _, c := range extra {
					t.Errorf("extra candidate: %+v", c)
				}
			}
		})
	}
}

func strRef(s string) *string {
	return &s
}

func TestBuildConstraints(t *testing.T) {
	tests := []struct {
		name     string
		matches  []nvd.CpeMatch
		expected string
	}{
		{
			name: "Equals",
			matches: []nvd.CpeMatch{
				{
					Criteria: "cpe:2.3:a:vendor:product:2.2.0:*:*:*:*:target:*:*",
				},
			},
			expected: "= 2.2.0",
		},
		{
			name: "VersionEndExcluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:            "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionEndExcluding: strRef("2.3.0"),
				},
			},
			expected: "< 2.3.0",
		},
		{
			name: "VersionEndIncluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:            "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionEndIncluding: strRef("2.3.0"),
				},
			},
			expected: "<= 2.3.0",
		},
		{
			name: "VersionStartExcluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartExcluding: strRef("2.3.0"),
				},
			},
			expected: "> 2.3.0",
		},
		{
			name: "VersionStartIncluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
				},
			},
			expected: ">= 2.3.0",
		},
		{
			name: "Version Range",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndIncluding:   strRef("2.5.0"),
				},
			},
			expected: ">= 2.3.0, <= 2.5.0",
		},
		{
			name: "Multiple Version Ranges",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndIncluding:   strRef("2.5.0"),
				},
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartExcluding: strRef("3.3.0"),
					VersionEndExcluding:   strRef("3.5.0"),
				},
			},
			expected: ">= 2.3.0, <= 2.5.0 || > 3.3.0, < 3.5.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := buildConstraints(test.matches)

			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(actual, test.expected, true)
				t.Errorf("Expected: %q", test.expected)
				t.Errorf("Got     : %q", actual)
				t.Errorf("Diff    : %q", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func Test_UniquePackageTrackerHandlesOnlyPlatformDiff(t *testing.T) {
	candidates := []pkgCandidate{
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
		},
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*",
		},
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
		},
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
		},
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
		},
	}
	cpeMatch := nvd.CpeMatch{
		Criteria:        "cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*",
		MatchCriteriaID: "5EBE5E1C-C881-4A76-9E36-4FB7C48427E6",
	}
	applicationNode := nvd.CpeMatch{
		Criteria:        "cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*",
		MatchCriteriaID: "some-uuid",
		Vulnerable:      true,
	}
	tracker := newUniquePkgTracker()
	for _, c := range candidates {
		candidate, err := newPkgCandidate(defaultConfig(), applicationNode, c.PlatformCPE)
		require.NoError(t, err)
		tracker.Add(*candidate, cpeMatch)
	}
	assert.Len(t, tracker, len(candidates))
}

func TestPlatformPackageCandidates(t *testing.T) {
	type testCase struct {
		name        string
		config      Config
		state       nvd.Configuration
		wantChanged bool
		wantSet     uniquePkgTracker
	}
	tests := []testCase{
		{
			name: "application X platform",
			state: nvd.Configuration{
				Negate: nil,
				Nodes: []nvd.Node{
					{
						CpeMatch: []nvd.CpeMatch{
							{
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:some-vendor:some-app:*:*:*:*:*:*:*:*",
							},
							{
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:some-vendor:other-app:*:*:*:*:*:*:*:*",
							},
						},
						Negate:   nil,
						Operator: nvd.Or,
					},
					{
						CpeMatch: []nvd.CpeMatch{
							{
								Vulnerable: false,
								Criteria:   "cpe:2.3:o:some-vendor:some-platform:*:*:*:*:*:*:*:*",
							},
							{
								Vulnerable: false,
								Criteria:   "cpe:2.3:o:some-vendor:other-platform:*:*:*:*:*:*:*:*",
							},
						},
						Negate:   nil,
						Operator: nvd.Or,
					},
				},
				Operator: opRef(nvd.And),
			},
			wantChanged: true,
			wantSet: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					mustNewPackage(t, nvd.CpeMatch{
						Vulnerable: true,
						Criteria:   "cpe:2.3:a:some-vendor:some-app:*:*:*:*:*:*:*:*",
					}, "cpe:2.3:o:some-vendor:some-platform:*:*:*:*:*:*:*:*"),
					mustNewPackage(t, nvd.CpeMatch{
						Vulnerable: true,
						Criteria:   "cpe:2.3:a:some-vendor:other-app:*:*:*:*:*:*:*:*",
					}, "cpe:2.3:o:some-vendor:some-platform:*:*:*:*:*:*:*:*"),
					mustNewPackage(t, nvd.CpeMatch{
						Vulnerable: true,
						Criteria:   "cpe:2.3:a:some-vendor:some-app:*:*:*:*:*:*:*:*",
					}, "cpe:2.3:o:some-vendor:other-platform:*:*:*:*:*:*:*:*"),
					mustNewPackage(t, nvd.CpeMatch{
						Vulnerable: true,
						Criteria:   "cpe:2.3:a:some-vendor:other-app:*:*:*:*:*:*:*:*",
					}, "cpe:2.3:o:some-vendor:other-platform:*:*:*:*:*:*:*:*"),
				},
			),
		},
		{
			name: "top-level OR is excluded",
			state: nvd.Configuration{
				Operator: opRef(nvd.Or),
			},
			wantChanged: false,
			wantSet:     newUniquePkgTracker(),
		},
		{
			name: "top-level nil op is excluded",
			state: nvd.Configuration{
				Operator: nil,
			},
			wantChanged: false,
		},
		{
			name: "single hardware node results in exclusion",
			state: nvd.Configuration{
				Negate: nil,
				Nodes: []nvd.Node{
					{
						CpeMatch: []nvd.CpeMatch{
							{
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:some-vendor:some-app:*:*:*:*:*:*:*:*",
							},
							{
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:some-vendor:other-app:*:*:*:*:*:*:*:*",
							},
						},
						Negate:   nil,
						Operator: nvd.Or,
					},
					{
						CpeMatch: []nvd.CpeMatch{
							{
								Vulnerable: false,
								Criteria:   "cpe:2.3:o:some-vendor:some-platform:*:*:*:*:*:*:*:*",
							},
							{
								Vulnerable: false,
								Criteria:   "cpe:2.3:h:some-vendor:some-device:*:*:*:*:*:*:*:*",
							},
						},
						Negate:   nil,
						Operator: nvd.Or,
					},
				},
				Operator: opRef(nvd.And),
			},
			wantChanged: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config == (Config{}) {
				tc.config = defaultConfig()
			}
			set := newUniquePkgTracker()
			result := platformPackageCandidates(tc.config, set, tc.state)
			assert.Equal(t, result, tc.wantChanged)
			if tc.wantSet == nil {
				tc.wantSet = newUniquePkgTracker()
			}
			if diff := cmp.Diff(tc.wantSet.All(), set.All()); diff != "" {
				t.Errorf("unexpected diff (-want +got)\n%s", diff)
			}
		})

	}
}

func opRef(op nvd.Operator) *nvd.Operator {
	return &op
}

func boolRef(b bool) *bool {
	return &b
}

func mustNewPackage(t *testing.T, match nvd.CpeMatch, platformCPE string, cfg ...Config) pkgCandidate {
	var tCfg *Config
	switch len(cfg) {
	case 0:
		c := defaultConfig()
		tCfg = &c
	case 1:
		tCfg = &cfg[0]
	default:
		t.Fatalf("too many configs provided")
	}
	p, err := newPkgCandidate(*tCfg, match, platformCPE)
	require.NoError(t, err)
	return *p
}
