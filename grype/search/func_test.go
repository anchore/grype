package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func Test_ByFunc(t *testing.T) {
	tests := []struct {
		name    string
		fn      func(vulnerability.Vulnerability) (bool, string, error)
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
		reason  string
	}{
		{
			name: "match",
			fn: func(v vulnerability.Vulnerability) (bool, string, error) {
				return true, "", nil
			},
			input:   vulnerability.Vulnerability{},
			matches: true,
		},
		{
			name: "not match",
			fn: func(v vulnerability.Vulnerability) (bool, string, error) {
				return false, "reason!", nil
			},
			input:   vulnerability.Vulnerability{},
			matches: false,
			reason:  "reason!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByFunc(tt.fn)
			matches, reason, err := constraint.MatchesVulnerability(tt.input)
			wantErr := require.NoError
			if tt.wantErr != nil {
				wantErr = tt.wantErr
			}
			wantErr(t, err)
			assert.Equal(t, tt.matches, matches)
			assert.Equal(t, tt.reason, reason)
		})
	}
}
