package version

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIncompatibleFlagIsSameVersion(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		constraint string
		satisfied  bool
	}{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newGolangConstraint(tc.constraint)
			require.NoError(t, err)
			v, err := NewVersion(tc.version, GolangFormat)
			require.NoError(t, err)
			sat, err := c.Satisfied(v)
			require.NoError(t, err)
			assert.Equal(t, tc.satisfied, sat)
		})
	}

}
