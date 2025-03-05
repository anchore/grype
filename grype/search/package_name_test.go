package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func Test_ByPackageName(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		input       vulnerability.Vulnerability
		wantErr     require.ErrorAssertionFunc
		matches     bool
		reason      string
	}{
		{
			name:        "match",
			packageName: "some-name",
			input: vulnerability.Vulnerability{
				PackageName: "some-name",
			},
			matches: true,
		},
		{
			name:        "match case insensitive",
			packageName: "some-name",
			input: vulnerability.Vulnerability{
				PackageName: "SomE-NaMe",
			},
			matches: true,
		},
		{
			name:        "not match",
			packageName: "some-name",
			input: vulnerability.Vulnerability{
				PackageName: "other-name",
			},
			matches: false,
			reason:  `vulnerability package name "other-name" does not match expected package name "some-name"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByPackageName(tt.packageName)
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
