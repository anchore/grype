package search

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func Test_ByArchitecture(t *testing.T) {
	// an alias table that folds a spelling the built-in defaults don't know about ("em64t") and
	// omits the built-in amd64 fold
	custom := map[string]string{"em64t": "x86_64"}

	tests := []struct {
		name    string
		arch    string
		aliases map[string]string
		input   vulnerability.Vulnerability
		matches bool
	}{
		{
			name:    "same arch",
			arch:    "x86_64",
			input:   vulnerability.Vulnerability{Arch: "x86_64"},
			matches: true,
		},
		{
			name:    "same arch, different case",
			arch:    "X86_64",
			input:   vulnerability.Vulnerability{Arch: "x86_64"},
			matches: true,
		},
		{
			// spellings of the same CPU architecture are folded through the default aliases
			name:    "same arch, different spelling",
			arch:    "amd64",
			input:   vulnerability.Vulnerability{Arch: "x86_64"},
			matches: true,
		},
		{
			name:    "same arch, spelling folded by the provided aliases",
			arch:    "em64t",
			aliases: custom,
			input:   vulnerability.Vulnerability{Arch: "x86_64"},
			matches: true,
		},
		{
			name:    "provided aliases replace the defaults",
			arch:    "amd64",
			aliases: custom,
			input:   vulnerability.Vulnerability{Arch: "x86_64"},
			matches: false,
		},
		{
			name:    "different arch",
			arch:    "aarch64",
			input:   vulnerability.Vulnerability{Arch: "x86_64"},
			matches: false,
		},
		{
			name:    "different arch, unaffected",
			arch:    "aarch64",
			input:   vulnerability.Vulnerability{Arch: "x86_64", Unaffected: true},
			matches: false,
		},
		{
			name:    "vulnerability without arch",
			arch:    "aarch64",
			input:   vulnerability.Vulnerability{},
			matches: true,
		},
		{
			name:    "package without arch",
			arch:    "",
			input:   vulnerability.Vulnerability{Arch: "x86_64"},
			matches: true,
		},
		{
			name:    "package without arch, unaffected",
			arch:    "",
			input:   vulnerability.Vulnerability{Arch: "x86_64", Unaffected: true},
			matches: true,
		},
		{
			name:    "source package, binary-no-arch unaffected",
			arch:    "src",
			input:   vulnerability.Vulnerability{Arch: "binary-no-arch-specified", Unaffected: true},
			matches: false,
		},
		{
			name:    "source package, src unaffected",
			arch:    "src",
			input:   vulnerability.Vulnerability{Arch: "src", Unaffected: true},
			matches: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria := ByArchitecture(tt.arch).(*ArchitectureCriteria)
			criteria.aliases = tt.aliases
			matches, reason, err := criteria.MatchesVulnerability(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.matches, matches)
			if matches {
				require.Empty(t, reason)
			} else {
				require.NotEmpty(t, reason)
			}
		})
	}
}
