package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func Test_ByLanguage(t *testing.T) {
	tests := []struct {
		name    string
		lang    syftPkg.Language
		pkgType syftPkg.Type
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
		reason  string
	}{
		{
			name:    "match",
			lang:    syftPkg.Java,
			pkgType: syftPkg.JavaPkg,
			input: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					Namespace: "github:language:java",
				},
			},
			matches: true,
		},
		{
			name:    "not match",
			lang:    syftPkg.Java,
			pkgType: syftPkg.JavaPkg,
			input: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					Namespace: "github:language:javascript",
				},
			},
			matches: false,
			reason:  `vulnerability language "javascript" does not match package language "java"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByEcosystem(tt.lang, tt.pkgType)
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
