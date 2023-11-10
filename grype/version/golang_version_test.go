package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hashiVer "github.com/anchore/go-version"
)

func TestNewGolangVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected golangVersion
		wantErr  bool
	}{
		{
			name:  "normal semantic version",
			input: "v1.8.0",
			expected: golangVersion{
				raw:    "v1.8.0",
				semVer: hashiVer.Must(hashiVer.NewSemver("1.8.0")),
			},
		},
		{
			name:  "v0.0.0 date and hash version",
			input: "v0.0.0-20180116102854-5a71ef0e047d",
			expected: golangVersion{
				raw:       "v0.0.0-20180116102854-5a71ef0e047d",
				timestamp: "20180116102854",
				commitSHA: "5a71ef0e047d",
			},
		},
		{
			name:  "semver with +incompatible",
			input: "v24.0.7+incompatible",
			expected: golangVersion{
				raw:              "v24.0.7+incompatible",
				semVer:           hashiVer.Must(hashiVer.NewSemver("24.0.7")),
				incompatibleFlag: true,
			},
		},
		{
			name:    "invalid input",
			input:   "some nonsense",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := newGolangVersion(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			assert.Equal(t, tc.expected, *v)
		})
	}
}
