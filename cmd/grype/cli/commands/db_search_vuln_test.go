package commands

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestGetOSVersions(t *testing.T) {
	tests := []struct {
		name     string
		input    []dbsearch.OperatingSystem
		expected []string
	}{
		{
			name:     "empty list",
			input:    []dbsearch.OperatingSystem{},
			expected: nil,
		},
		{
			name: "single os",
			input: []dbsearch.OperatingSystem{
				{
					Name:    "debian",
					Version: "11",
				},
			},
			expected: []string{"11"},
		},
		{
			name: "multiple os",
			input: []dbsearch.OperatingSystem{
				{
					Name:    "ubuntu",
					Version: "16.04",
				},
				{
					Name:    "ubuntu",
					Version: "22.04",
				},
				{
					Name:    "ubuntu",
					Version: "24.04",
				},
			},
			expected: []string{"16.04", "22.04", "24.04"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := getOSVersions(tt.input)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestGetPrimaryReference(t *testing.T) {
	tests := []struct {
		name     string
		input    []v6.Reference
		expected string
	}{
		{
			name:     "empty list",
			input:    []v6.Reference{},
			expected: "",
		},
		{
			name: "single reference",
			input: []v6.Reference{
				{
					URL:  "https://example.com/vuln/123",
					Tags: []string{"primary"},
				},
			},
			expected: "https://example.com/vuln/123",
		},
		{
			name: "multiple references",
			input: []v6.Reference{
				{
					URL:  "https://example.com/vuln/123",
					Tags: []string{"primary"},
				},
				{
					URL:  "https://example.com/advisory/123",
					Tags: []string{"secondary"},
				},
			},
			expected: "https://example.com/vuln/123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := getPrimaryReference(tt.input)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestGetDate(t *testing.T) {
	tests := []struct {
		name     string
		input    *time.Time
		expected string
	}{
		{
			name:     "nil time",
			input:    nil,
			expected: "",
		},
		{
			name:     "zero time",
			input:    &time.Time{},
			expected: "",
		},
		{
			name:     "valid time",
			input:    timePtr(time.Date(2023, 5, 15, 0, 0, 0, 0, time.UTC)),
			expected: "2023-05-15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := getDate(tt.input)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
