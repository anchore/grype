package search

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

func Test_ByCPE(t *testing.T) {
	tests := []struct {
		name    string
		cpe     cpe.CPE
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
	}{
		{
			name: "match",
			cpe:  cpe.Must("cpe:2.3:a:a-vendor:a-product:*:*:*:*:*:*:*:*", ""),
			input: vulnerability.Vulnerability{
				CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:a-vendor:a-product:*:*:*:*:*:*:*:*", "")},
			},
			matches: true,
		},
		{
			name: "not match",
			cpe:  cpe.Must("cpe:2.3:a:a-vendor:b-product:*:*:*:*:*:*:*:*", ""),
			input: vulnerability.Vulnerability{
				CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:a-vendor:a-product:*:*:*:*:*:*:*:*", "")},
			},
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByCPE(tt.cpe)
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
