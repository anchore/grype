package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/vulnerability"
)

func Test_ByDistro(t *testing.T) {
	deb8 := distro.New(distro.Debian, "8", "")

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

func Test_ByExactDistro(t *testing.T) {
	alma8 := distro.New(distro.AlmaLinux, "8", "")
	rhel8 := distro.New(distro.RedHat, "8", "")

	tests := []struct {
		name    string
		distro  distro.Distro
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
		reason  string
	}{
		{
			name:   "exact match - AlmaLinux",
			distro: *alma8,
			input: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					Namespace: "almalinux:distro:almalinux:8",
				},
			},
			matches: true,
		},
		{
			name:   "no alias mapping - AlmaLinux vs RHEL",
			distro: *alma8,
			input: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					Namespace: "redhat:distro:redhat:8",
				},
			},
			matches: false,
			reason:  `does not match any known distro: "almalinux 8"`,
		},
		{
			name:   "exact match - RHEL",
			distro: *rhel8,
			input: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					Namespace: "redhat:distro:redhat:8",
				},
			},
			matches: true,
		},
		{
			name:   "no alias mapping - RHEL vs AlmaLinux",
			distro: *rhel8,
			input: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					Namespace: "almalinux:distro:almalinux:8",
				},
			},
			matches: false,
			reason:  `does not match any known distro: "rhel 8"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByExactDistro(tt.distro)
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

func Test_ByDistro_vs_ByExactDistro_AliasMapping(t *testing.T) {
	alma8 := distro.New(distro.AlmaLinux, "8", "")

	rhelVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			Namespace: "redhat:distro:redhat:8",
		},
	}

	// Test that ByDistro applies alias mapping (AlmaLinux -> RHEL)
	regularConstraint := ByDistro(*alma8)
	matches, _, err := regularConstraint.MatchesVulnerability(rhelVuln)
	require.NoError(t, err)
	assert.True(t, matches, "ByDistro should match RHEL vulns for AlmaLinux due to alias mapping")

	// Test that ByExactDistro does NOT apply alias mapping
	exactConstraint := ByExactDistro(*alma8)
	matches, _, err = exactConstraint.MatchesVulnerability(rhelVuln)
	require.NoError(t, err)
	assert.False(t, matches, "ByExactDistro should NOT match RHEL vulns for AlmaLinux (no alias mapping)")
}
