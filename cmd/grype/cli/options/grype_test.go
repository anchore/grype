package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func Test_Grype_PostLoad_failOn(t *testing.T) {
	risk := func(r float64) *float64 { return &r }

	tests := []struct {
		name         string
		failOn       string
		wantErr      require.ErrorAssertionFunc
		wantSeverity vulnerability.Severity
		wantRisk     *float64
	}{
		{
			name:         "unset",
			failOn:       "",
			wantSeverity: vulnerability.UnknownSeverity,
		},
		{
			name:         "severity",
			failOn:       "high",
			wantSeverity: vulnerability.HighSeverity,
		},
		{
			name:         "severity is case insensitive",
			failOn:       "Critical",
			wantSeverity: vulnerability.CriticalSeverity,
		},
		{
			name:     "risk with equals separator",
			failOn:   "risk=8",
			wantRisk: risk(8),
		},
		{
			name:     "risk with dash separator",
			failOn:   "risk-8",
			wantRisk: risk(8),
		},
		{
			name:     "risk accepts decimals",
			failOn:   "risk=7.5",
			wantRisk: risk(7.5),
		},
		{
			name:     "risk is case insensitive",
			failOn:   "RISK=10",
			wantRisk: risk(10),
		},
		{
			name:     "risk of zero",
			failOn:   "risk=0",
			wantRisk: risk(0),
		},
		{
			name:    "unknown value",
			failOn:  "bogus",
			wantErr: require.Error,
		},
		{
			name:    "risk without a threshold",
			failOn:  "risk",
			wantErr: require.Error,
		},
		{
			name:    "risk without a separator",
			failOn:  "risk8",
			wantErr: require.Error,
		},
		{
			name:    "risk with an empty threshold",
			failOn:  "risk=",
			wantErr: require.Error,
		},
		{
			name:    "risk with a non-numeric threshold",
			failOn:  "risk=high",
			wantErr: require.Error,
		},
		{
			name:    "negative risk",
			failOn:  "risk=-1",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			o := &Grype{FailOn: tt.failOn}
			err := o.PostLoad()
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.wantSeverity, *o.FailOnSeverity())
			assert.Equal(t, tt.wantRisk, o.FailOnRisk())
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
