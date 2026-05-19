package commands

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSkipPhases(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		wantPhases []string
		wantErr   bool
	}{
		{
			name:       "empty",
			input:      nil,
			wantPhases: nil,
		},
		{
			name:       "single comma-separated entry",
			input:      []string{"pull,validate,package"},
			wantPhases: []string{skipPhasePull, skipPhaseValidate, skipPhasePackage},
		},
		{
			name:       "multiple --skip occurrences",
			input:      []string{"pull", "write"},
			wantPhases: []string{skipPhasePull, skipPhaseWrite},
		},
		{
			name:       "mixed case and whitespace tolerated",
			input:      []string{" PULL , Validate "},
			wantPhases: []string{skipPhasePull, skipPhaseValidate},
		},
		{
			name:    "rejects unknown phase",
			input:   []string{"foobar"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSkipPhases(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if len(tt.wantPhases) == 0 {
				assert.Equal(t, 0, got.Size())
				return
			}
			for _, p := range tt.wantPhases {
				assert.True(t, got.Has(p), "expected %q in skip set; got %s", p, strings.Join(got.List(), ","))
			}
			assert.Equal(t, len(tt.wantPhases), got.Size())
		})
	}
}

func TestValidateCPEParts(t *testing.T) {
	require.NoError(t, validateCPEParts([]string{"a", "h", "o"}))
	require.Error(t, validateCPEParts(nil))
	require.Error(t, validateCPEParts([]string{}))
	require.Error(t, validateCPEParts([]string{"a", "x"}))
}
