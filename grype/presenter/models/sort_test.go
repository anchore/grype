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
					ID:          "CVE-2023-1111",
					Severity:    "medium",
					ThreatScore: 6.5,
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
					ID:          "CVE-2023-2222",
					Severity:    "critical",
					ThreatScore: 9.8,
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
					ID:          "CVE-2023-3333",
					Severity:    "high",
					ThreatScore: 8.2,
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
					ID:          "CVE-2023-4444",
					Severity:    "low",
					ThreatScore: 3.7,
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
					ID:          "CVE-2023-5555",
					Severity:    "critical",
					ThreatScore: 9.5,
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

	t.Run("SortByVulnerability", func(t *testing.T) {
		testMatches := deepCopyMatches(matches)
		SortMatches(testMatches, SortByVulnerability)

		expected := []Match{
			matches[0], // CVE-2023-1111
			matches[1], // CVE-2023-2222
			matches[2], // CVE-2023-3333
			matches[3], // CVE-2023-4444
			matches[4], // CVE-2023-5555
		}

		if diff := cmp.Diff(expected, testMatches); diff != "" {
			t.Errorf("SortByVulnerability mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SortBySeverity", func(t *testing.T) {
		testMatches := deepCopyMatches(matches)
		SortMatches(testMatches, SortBySeverity)

		expected := []Match{
			matches[1], // critical severity, CVE-2023-2222
			matches[4], // critical severity, CVE-2023-5555
			matches[2], // high severity
			matches[0], // medium severity
			matches[3], // low severity
		}

		if diff := cmp.Diff(expected, testMatches); diff != "" {
			t.Errorf("SortBySeverity mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SortByThreat", func(t *testing.T) {
		testMatches := deepCopyMatches(matches)
		SortMatches(testMatches, SortByThreat)

		expected := []Match{
			matches[1], // threat 9.8
			matches[4], // threat 9.5
			matches[2], // threat 8.2
			matches[0], // threat 6.5
			matches[3], // threat 3.7
		}

		if diff := cmp.Diff(expected, testMatches); diff != "" {
			t.Errorf("SortByThreat mismatch (-want +got):\n%s", diff)
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
