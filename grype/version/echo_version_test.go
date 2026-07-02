package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEchoVersion_Compare(t *testing.T) {
	tests := []struct {
		v1   string
		v2   string
		want int
	}{
		// SemVer ties broken by the +echo.N build number (no suffix = 0)
		{"3.1.9+echo.1", "3.1.9", 1},
		{"3.1.9+echo.2", "3.1.9+echo.1", 1},
		{"3.1.9+echo.10", "3.1.9+echo.2", 1},
		{"3.1.9+echo.1", "3.1.9+echo.1", 0},
		// base SemVer ordering is untouched
		{"3.1.10", "3.1.9+echo.99", 1},
		{"3.1.9+echo.1", "3.1.10", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		// an echo build of a prerelease stays below the final release
		{"19.0.0-next.3+echo.1", "19.0.0-next.3", 1},
		{"19.0.0-next.3+echo.1", "19.0.0", -1},
		// non-echo versions behave exactly like the semantic comparator
		{"2.0.0", "1.9.9", 1},
		{"1.0.0", "1.0.0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.v1+" vs "+tt.v2, func(t *testing.T) {
			v1, err := newEchoVersion(tt.v1)
			require.NoError(t, err)

			got, err := v1.Compare(New(tt.v2, EchoFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEchoConstraint_Satisfied(t *testing.T) {
	tests := []struct {
		version    string
		constraint string
		satisfied  bool
	}{
		// the NAK shape the Echo OSV strategy emits: ">= <fixed echo build>".
		// The still-vulnerable earlier build must NOT satisfy it (this is the
		// case SemVer alone cannot express: 3.1.9+echo.1 == 3.1.9+echo.2).
		{"3.1.9+echo.1", ">= 3.1.9+echo.2", false},
		{"3.1.9+echo.2", ">= 3.1.9+echo.2", true},
		{"3.1.9+echo.10", ">= 3.1.9+echo.2", true},
		{"3.1.10+echo.1", ">= 3.1.9+echo.2", true},
		{"3.1.9", ">= 3.1.9+echo.1", false},
		// prerelease echo builds
		{"19.0.0-next.3+echo.1", ">= 19.0.0-next.3+echo.2", false},
		{"19.0.0-next.3+echo.2", ">= 19.0.0-next.3+echo.2", true},
		// range with an upper bound
		{"3.1.9+echo.1", ">= 3.1.9+echo.1, < 3.1.9+echo.2", true},
		{"3.1.9+echo.2", ">= 3.1.9+echo.1, < 3.1.9+echo.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.version+" in "+tt.constraint, func(t *testing.T) {
			c, err := GetConstraint(tt.constraint, EchoFormat)
			require.NoError(t, err)

			satisfied, err := c.Satisfied(New(tt.version, EchoFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, satisfied)
		})
	}
}

func TestParseFormat_Echo(t *testing.T) {
	assert.Equal(t, EchoFormat, ParseFormat("echo"))
}
