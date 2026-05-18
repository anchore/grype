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

func Test_ByPackageNamePrefix(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		input   vulnerability.Vulnerability
		matches bool
		reason  string
	}{
		{
			name:   "advisory pinned at sub-import-path matches module prefix",
			prefix: "golang.org/x/crypto",
			input: vulnerability.Vulnerability{
				PackageName: "golang.org/x/crypto/ssh",
			},
			matches: true,
		},
		{
			name:   "case-insensitive prefix match",
			prefix: "Golang.org/X/Crypto",
			input: vulnerability.Vulnerability{
				PackageName: "golang.org/x/crypto/ssh",
			},
			matches: true,
		},
		{
			name:   "deeper sub-path matches",
			prefix: "golang.org/x/crypto",
			input: vulnerability.Vulnerability{
				PackageName: "golang.org/x/crypto/ssh/internal/buffer",
			},
			matches: true,
		},
		{
			name:   "exact name does not match prefix (must be strictly under)",
			prefix: "golang.org/x/crypto",
			input: vulnerability.Vulnerability{
				PackageName: "golang.org/x/crypto",
			},
			matches: false,
			reason:  `vulnerability package name "golang.org/x/crypto" does not start with expected prefix "golang.org/x/crypto/"`,
		},
		{
			name:   "sibling with shared substring but no segment break does not match",
			prefix: "golang.org/x/crypto",
			input: vulnerability.Vulnerability{
				PackageName: "golang.org/x/cryptographer",
			},
			matches: false,
			reason:  `vulnerability package name "golang.org/x/cryptographer" does not start with expected prefix "golang.org/x/crypto/"`,
		},
		{
			name:   "unrelated module does not match",
			prefix: "golang.org/x/crypto",
			input: vulnerability.Vulnerability{
				PackageName: "github.com/foo/bar",
			},
			matches: false,
			reason:  `vulnerability package name "github.com/foo/bar" does not start with expected prefix "golang.org/x/crypto/"`,
		},
		{
			name:   "empty prefix never matches",
			prefix: "",
			input: vulnerability.Vulnerability{
				PackageName: "anything",
			},
			matches: false,
			reason:  "empty package name prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByPackageNamePrefix(tt.prefix)
			matches, reason, err := constraint.MatchesVulnerability(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.matches, matches)
			assert.Equal(t, tt.reason, reason)
		})
	}
}
