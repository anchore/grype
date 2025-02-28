package models

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSortMatches(t *testing.T) {
	matches := []Match{
		{
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-1111",
					Severity: "medium",
				},
			},
			Artifact: Package{
				Name:    "package-b",
				Version: "1.2.0",
				Type:    "npm",
			},
		},
		{
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-2222",
					Severity: "critical",
				},
			},
			Artifact: Package{
				Name:    "package-a",
				Version: "2.0.0",
				Type:    "docker",
			},
		},
		{
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-3333",
					Severity: "high",
				},
			},
			Artifact: Package{
				Name:    "package-a",
				Version: "1.0.0",
				Type:    "npm",
			},
		},
		{
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-4444",
					Severity: "low",
				},
			},
			Artifact: Package{
				Name:    "package-c",
				Version: "3.1.0",
				Type:    "gem",
			},
		},
		{
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-5555",
					Severity: "critical",
				},
			},
			Artifact: Package{
				Name:    "package-a",
				Version: "1.0.0",
				Type:    "docker",
			},
		},
	}

	t.Run("SortByPackage", func(t *testing.T) {
		testMatches := deepCopyMatches(matches)
		SortMatches(testMatches, SortByPackage)

		expected := []Match{
			// package-a with 1.0.0 version, docker type first (alphabetical)
			matches[4], // package-a, 1.0.0, docker, critical
			matches[2], // package-a, 1.0.0, npm, high
			matches[1], // package-a, 2.0.0, docker, critical
			matches[0], // package-b, 1.2.0, npm, medium
			matches[3], // package-c, 3.1.0, gem, low
		}

		if diff := cmp.Diff(expected, testMatches); diff != "" {
			t.Errorf("SortByPackage mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("UnknownStrategy", func(t *testing.T) {
		testMatches := deepCopyMatches(matches)
		// should use default (package) strategy for unknown strategy names
		SortMatches(testMatches, "unknown")

		expected := []Match{
			matches[4], // package-a, 1.0.0, docker
			matches[2], // package-a, 1.0.0, npm
			matches[1], // package-a, 2.0.0, docker
			matches[0], // package-b, 1.2.0, npm
			matches[3], // package-c, 3.1.0, gem
		}

		if diff := cmp.Diff(expected, testMatches); diff != "" {
			t.Errorf("Unknown strategy mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("EmptySlice", func(t *testing.T) {
		matches := []Match{}
		// should not panic on empty slice
		SortMatches(matches, SortByPackage)

		expected := []Match{}
		if diff := cmp.Diff(expected, matches); diff != "" {
			t.Errorf("Empty slice mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SingleItem", func(t *testing.T) {
		matches := []Match{
			{
				Vulnerability: Vulnerability{
					VulnerabilityMetadata: VulnerabilityMetadata{
						ID:       "CVE-2023-1111",
						Severity: "medium",
					},
				},
				Artifact: Package{
					Name:    "package-a",
					Version: "1.0.0",
				},
			},
		}
		expected := deepCopyMatches(matches)
		// should not change anything with a single item
		SortMatches(matches, SortByPackage)

		if diff := cmp.Diff(expected, matches); diff != "" {
			t.Errorf("Single item mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NilValues", func(t *testing.T) {
		matches := []Match{
			{
				Vulnerability: Vulnerability{
					VulnerabilityMetadata: VulnerabilityMetadata{
						ID:       "CVE-2023-1111",
						Severity: "",
					},
				},
				Artifact: Package{
					Name:    "",
					Version: "",
				},
			},
			{
				Vulnerability: Vulnerability{
					VulnerabilityMetadata: VulnerabilityMetadata{
						ID:       "CVE-2023-2222",
						Severity: "low",
					},
				},
				Artifact: Package{
					Name:    "package-a",
					Version: "1.0.0",
				},
			},
		}

		expected := []Match{
			matches[0], // empty name comes first alphabetically
			matches[1], // "package-a"
		}

		// should handle empty strings properly
		SortMatches(matches, SortByPackage)

		if diff := cmp.Diff(expected, matches); diff != "" {
			t.Errorf("Nil values mismatch (-want +got):\n%s", diff)
		}
	})
}

func deepCopyMatches(matches []Match) []Match {
	result := make([]Match, len(matches))
	copy(result, matches)
	return result
}
