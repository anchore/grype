package internal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/grype/grype/pkg/qualifier/architecture"
	"github.com/anchore/grype/grype/pkg/qualifier/rpmmodularity"
	"github.com/anchore/grype/grype/vulnerability"
)

func TestSourceOrUnspecifiedArch(t *testing.T) {
	tests := []struct {
		name       string
		qualifiers []qualifier.Qualifier
		want       bool
	}{
		{
			name:       "no qualifiers passes through (old DBs / non-CSAF providers)",
			qualifiers: nil,
			want:       true,
		},
		{
			name:       "architecture=src passes",
			qualifiers: []qualifier.Qualifier{architecture.New(architecture.ArchSource)},
			want:       true,
		},
		{
			name:       "architecture=binary-no-arch-specified is rejected",
			qualifiers: []qualifier.Qualifier{architecture.New(architecture.ArchBinaryNoArchSpecified)},
			want:       false,
		},
		{
			name:       "literal arch like x86_64 is rejected (extension point for future arch-scoped advisories)",
			qualifiers: []qualifier.Qualifier{architecture.New("x86_64")},
			want:       false,
		},
		{
			name:       "architecture=binary-no-arch-specified is rejected even alongside other qualifiers",
			qualifiers: []qualifier.Qualifier{rpmmodularity.New(""), architecture.New(architecture.ArchBinaryNoArchSpecified)},
			want:       false,
		},
		{
			name:       "unrelated qualifiers do not interfere",
			qualifiers: []qualifier.Qualifier{rpmmodularity.New("nodejs:18")},
			want:       true,
		},
		{
			name:       "empty architecture value passes (treated like unspecified)",
			qualifiers: []qualifier.Qualifier{architecture.New("")},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := vulnerability.Vulnerability{
				PackageQualifiers: tt.qualifiers,
			}
			matched, _, err := SourceOrUnspecifiedArch().MatchesVulnerability(vuln)
			require.NoError(t, err)
			require.Equal(t, tt.want, matched)
		})
	}
}
