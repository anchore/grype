package search

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func Test_ByFunc(t *testing.T) {
	tests := []struct {
		name    string
		fn      func(vulnerability.Vulnerability) (bool, error)
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
	}{
		{
			name: "match",
			fn: func(v vulnerability.Vulnerability) (bool, error) {
				return true, nil
			},
			input:   vulnerability.Vulnerability{},
			matches: true,
		},
		{
			name: "not match",
			fn: func(v vulnerability.Vulnerability) (bool, error) {
				return false, nil
			},
			input:   vulnerability.Vulnerability{},
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByFunc(tt.fn)
			matches, err := constraint.MatchesVulnerability(tt.input)
			wantErr := require.NoError
			if tt.wantErr != nil {
				wantErr = tt.wantErr
			}
			wantErr(t, err)
			require.Equal(t, tt.matches, matches)
		})
	}
}
