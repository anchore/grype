package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

func Test_ByVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
		reason  string
	}{
		{
			name:    "match",
			version: "1.0",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 2.0", version.SemanticFormat),
			},
			matches: true,
		},
		{
			name:    "not match",
			version: "2.0",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 2.0", version.SemanticFormat),
			},
			matches: false,
			reason:  "", // we don't expect a reason to be raised up at this level
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := version.New(tt.version, version.SemanticFormat)
			constraint := ByVersion(*v)
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

func Test_ByConstraintFunc(t *testing.T) {
	tests := []struct {
		name           string
		constraintFunc func(version.Constraint) (bool, error)
		input          vulnerability.Vulnerability
		wantErr        require.ErrorAssertionFunc
		matches        bool
		reason         string
	}{
		{
			name: "match",
			constraintFunc: func(version.Constraint) (bool, error) {
				return true, nil
			},
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 2.0", version.SemanticFormat),
			},
			matches: true,
		},
		{
			name: "not match",
			constraintFunc: func(version.Constraint) (bool, error) {
				return false, nil
			},
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 2.0", version.SemanticFormat),
			},
			matches: false,
			reason:  "", // we don't expect a reason to be raised up at this level
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByConstraintFunc(tt.constraintFunc)
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
