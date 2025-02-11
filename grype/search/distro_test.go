package search

import (
	"testing"

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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByDistro(tt.distro)
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
