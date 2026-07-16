package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func TestGrypePostLoadMinSeverity(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected vulnerability.Severity
		wantErr  string
	}{
		{name: "unset"},
		{name: "negligible", value: "negligible", expected: vulnerability.NegligibleSeverity},
		{name: "low", value: "low", expected: vulnerability.LowSeverity},
		{name: "medium", value: "medium", expected: vulnerability.MediumSeverity},
		{name: "high", value: "high", expected: vulnerability.HighSeverity},
		{name: "critical", value: "critical", expected: vulnerability.CriticalSeverity},
		{name: "mixed case", value: "MeDiUm", expected: vulnerability.MediumSeverity},
		{name: "uppercase", value: "HIGH", expected: vulnerability.HighSeverity},
		{name: "unknown", value: "unknown", wantErr: "bad --min-severity value 'unknown'"},
		{name: "invalid", value: "important", wantErr: "bad --min-severity value 'important'"},
		{name: "whitespace is invalid", value: " high ", wantErr: "bad --min-severity value ' high '"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Grype{MinSeverity: tt.value}

			err := opts.PostLoad()
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			threshold := opts.MinSeverityThreshold()
			if tt.value == "" {
				assert.Nil(t, threshold)
			} else {
				require.NotNil(t, threshold)
				assert.Equal(t, tt.expected, *threshold)
			}
		})
	}
}

func Test_flatten(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "single value",
			input:    []string{"docker"},
			expected: []string{"docker"},
		},
		{
			name:     "comma-separated values",
			input:    []string{"docker,registry"},
			expected: []string{"docker", "registry"},
		},
		{
			name:     "multiple entries with commas",
			input:    []string{"docker,registry", "podman"},
			expected: []string{"docker", "registry", "podman"}, // preserves order
		},
		{
			name:     "whitespace trimming",
			input:    []string{" docker , registry "},
			expected: []string{"docker", "registry"},
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flatten(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
