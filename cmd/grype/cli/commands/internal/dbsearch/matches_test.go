package dbsearch

import (
	"testing"

	"github.com/stretchr/testify/assert"

	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestGetFixStateFromBlob(t *testing.T) {
	tests := []struct {
		name     string
		blob     *v6.PackageBlob
		expected string
	}{
		{
			name:     "nil blob returns unknown",
			blob:     nil,
			expected: "unknown",
		},
		{
			name:     "empty blob returns unknown",
			blob:     &v6.PackageBlob{},
			expected: "unknown",
		},
		{
			name: "blob with fixed status",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State:   v6.FixedStatus,
							Version: "1.2.3",
						},
					},
				},
			},
			expected: "fixed",
		},
		{
			name: "blob with not-fixed status",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotFixedStatus,
						},
					},
				},
			},
			expected: "not-fixed",
		},
		{
			name: "blob with wont-fix status",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.WontFixStatus,
						},
					},
				},
			},
			expected: "wont-fix",
		},
		{
			name: "blob with no fix returns unknown",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: nil,
					},
				},
			},
			expected: "unknown",
		},
		{
			name: "blob with mixed statuses prefers fixed",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotFixedStatus,
						},
					},
					{
						Fix: &v6.Fix{
							State:   v6.FixedStatus,
							Version: "2.0.0",
						},
					},
				},
			},
			expected: "fixed",
		},
		{
			name: "blob with wont-fix and not-fixed prefers wont-fix",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotFixedStatus,
						},
					},
					{
						Fix: &v6.Fix{
							State: v6.WontFixStatus,
						},
					},
				},
			},
			expected: "wont-fix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFixStateFromBlob(tt.blob)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterByFixedState(t *testing.T) {
	tests := []struct {
		name         string
		packages     []affectedPackageWithDecorations
		fixedStates  []string
		expectedLen  int
		expectedStrs []string
	}{
		{
			name:         "empty fixed states returns all packages",
			packages:     makeTestPackages(3),
			fixedStates:  []string{},
			expectedLen:  3,
			expectedStrs: nil,
		},
		{
			name: "filter by fixed state",
			packages: []affectedPackageWithDecorations{
				makePackageWithFixState(v6.FixedStatus),
				makePackageWithFixState(v6.NotFixedStatus),
				makePackageWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"fixed"},
			expectedLen:  1,
			expectedStrs: []string{"fixed"},
		},
		{
			name: "filter by multiple states",
			packages: []affectedPackageWithDecorations{
				makePackageWithFixState(v6.FixedStatus),
				makePackageWithFixState(v6.NotFixedStatus),
				makePackageWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"fixed", "wont-fix"},
			expectedLen:  2,
			expectedStrs: []string{"fixed", "wont-fix"},
		},
		{
			name: "filter with no matches",
			packages: []affectedPackageWithDecorations{
				makePackageWithFixState(v6.NotFixedStatus),
				makePackageWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"fixed"},
			expectedLen:  0,
			expectedStrs: nil,
		},
		{
			name: "packages with nil blob are filtered out",
			packages: []affectedPackageWithDecorations{
				makePackageWithFixState(v6.FixedStatus),
				{AffectedPackageHandle: v6.AffectedPackageHandle{BlobValue: nil}},
			},
			fixedStates:  []string{"fixed", "unknown"},
			expectedLen:  1,
			expectedStrs: []string{"fixed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterByFixedState(tt.packages, tt.fixedStates)
			assert.Equal(t, tt.expectedLen, len(result))

			if tt.expectedStrs != nil {
				var resultStates []string
				for _, pkg := range result {
					resultStates = append(resultStates, getFixStateFromBlob(pkg.BlobValue))
				}
				assert.ElementsMatch(t, tt.expectedStrs, resultStates)
			}
		})
	}
}

func TestFilterCPEsByFixedState(t *testing.T) {
	tests := []struct {
		name         string
		cpes         []affectedCPEWithDecorations
		fixedStates  []string
		expectedLen  int
		expectedStrs []string
	}{
		{
			name:         "empty fixed states returns all CPEs",
			cpes:         makeTestCPEs(3),
			fixedStates:  []string{},
			expectedLen:  3,
			expectedStrs: nil,
		},
		{
			name: "filter by fixed state",
			cpes: []affectedCPEWithDecorations{
				makeCPEWithFixState(v6.FixedStatus),
				makeCPEWithFixState(v6.NotFixedStatus),
				makeCPEWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"fixed"},
			expectedLen:  1,
			expectedStrs: []string{"fixed"},
		},
		{
			name: "filter by multiple states",
			cpes: []affectedCPEWithDecorations{
				makeCPEWithFixState(v6.FixedStatus),
				makeCPEWithFixState(v6.NotFixedStatus),
				makeCPEWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"not-fixed", "wont-fix"},
			expectedLen:  2,
			expectedStrs: []string{"not-fixed", "wont-fix"},
		},
		{
			name: "CPEs with nil blob are filtered out",
			cpes: []affectedCPEWithDecorations{
				makeCPEWithFixState(v6.FixedStatus),
				{AffectedCPEHandle: v6.AffectedCPEHandle{BlobValue: nil}},
			},
			fixedStates:  []string{"fixed", "unknown"},
			expectedLen:  1,
			expectedStrs: []string{"fixed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterCPEsByFixedState(tt.cpes, tt.fixedStates)
			assert.Equal(t, tt.expectedLen, len(result))

			if tt.expectedStrs != nil {
				var resultStates []string
				for _, cpe := range result {
					resultStates = append(resultStates, getFixStateFromBlob(cpe.BlobValue))
				}
				assert.ElementsMatch(t, tt.expectedStrs, resultStates)
			}
		})
	}
}

func makeTestPackages(count int) []affectedPackageWithDecorations {
	packages := make([]affectedPackageWithDecorations, count)
	for i := 0; i < count; i++ {
		packages[i] = affectedPackageWithDecorations{
			AffectedPackageHandle: v6.AffectedPackageHandle{
				BlobValue: &v6.PackageBlob{},
			},
		}
	}
	return packages
}

func makePackageWithFixState(state v6.FixStatus) affectedPackageWithDecorations {
	return affectedPackageWithDecorations{
		AffectedPackageHandle: v6.AffectedPackageHandle{
			BlobValue: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State:   state,
							Version: "1.0.0",
						},
					},
				},
			},
		},
	}
}

func makeTestCPEs(count int) []affectedCPEWithDecorations {
	cpes := make([]affectedCPEWithDecorations, count)
	for i := 0; i < count; i++ {
		cpes[i] = affectedCPEWithDecorations{
			AffectedCPEHandle: v6.AffectedCPEHandle{
				BlobValue: &v6.PackageBlob{},
			},
		}
	}
	return cpes
}

func makeCPEWithFixState(state v6.FixStatus) affectedCPEWithDecorations {
	return affectedCPEWithDecorations{
		AffectedCPEHandle: v6.AffectedCPEHandle{
			BlobValue: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State:   state,
							Version: "1.0.0",
						},
					},
				},
			},
		},
	}
}
