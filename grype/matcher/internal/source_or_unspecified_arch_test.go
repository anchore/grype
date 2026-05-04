package internal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/grype/grype/pkg/qualifier/rpmarch"
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
			name:       "rpmarch=src passes",
			qualifiers: []qualifier.Qualifier{rpmarch.New(rpmarch.ArchSource)},
			want:       true,
		},
		{
			name:       "rpmarch=binary-no-arch-specified is rejected",
			qualifiers: []qualifier.Qualifier{rpmarch.New(rpmarch.ArchBinaryNoArchSpecified)},
			want:       false,
		},
		{
			name:       "literal arch like x86_64 is rejected (extension point for future arch-scoped advisories)",
			qualifiers: []qualifier.Qualifier{rpmarch.New("x86_64")},
			want:       false,
		},
		{
			name:       "rpmarch=binary-no-arch-specified is rejected even alongside other qualifiers",
			qualifiers: []qualifier.Qualifier{rpmmodularity.New(""), rpmarch.New(rpmarch.ArchBinaryNoArchSpecified)},
			want:       false,
		},
		{
			name:       "unrelated qualifiers do not interfere",
			qualifiers: []qualifier.Qualifier{rpmmodularity.New("nodejs:18")},
			want:       true,
		},
		{
			name:       "empty rpmarch value passes (treated like unspecified)",
			qualifiers: []qualifier.Qualifier{rpmarch.New("")},
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
