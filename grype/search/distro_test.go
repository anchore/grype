package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/vulnerability"
)

func Test_ByDistro(t *testing.T) {
	deb8, err := distro.New(distro.Debian, "8", "")
	require.NoError(t, err)

	tests := []struct {
		name    string
		distro  distro.Distro
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
		reason  string
	}{
		{
			name:   "match",
			distro: *deb8,
			input: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					Namespace: "debian:distro:debian:8",
				},
			},
			matches: true,
		},
		{
			name:   "not match",
			distro: *deb8,
			input: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					Namespace: "debian:distro:ubuntu:8",
				},
			},
			matches: false,
			reason:  `does not match any known distro: "debian 8"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByDistro(tt.distro)
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
