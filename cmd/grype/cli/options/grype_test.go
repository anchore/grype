package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func Test_Grype_PostLoad_failOn(t *testing.T) {
	tests := []struct {
		name               string
		failOn             string
		wantErr            require.ErrorAssertionFunc
		wantSeverity       vulnerability.Severity
		wantNoVexStatement bool
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
			name:               "no-vex-statement",
			failOn:             "no-vex-statement",
			wantNoVexStatement: true,
		},
		{
			name:               "no-vex-statement is case insensitive",
			failOn:             "NO-VEX-STATEMENT",
			wantNoVexStatement: true,
		},
		{
			name:    "unknown value",
			failOn:  "bogus",
			wantErr: require.Error,
		},
		{
			name:    "partial no-vex-statement value",
			failOn:  "no-vex",
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
			assert.Equal(t, tt.wantNoVexStatement, o.FailOnNoVexStatement())
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
