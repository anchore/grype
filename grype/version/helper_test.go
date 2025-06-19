package version

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name       string
	version    string
	constraint string
	satisfied  bool
	wantError  require.ErrorAssertionFunc
}

func (c *testCase) tName() string {
	if c.name != "" {
		return c.name
	}

	return fmt.Sprintf("ver='%s'const='%s'", c.version, strings.ReplaceAll(c.constraint, " ", ""))
}

func (c *testCase) assertVersionConstraint(t *testing.T, format Format, constraint Constraint) {
	t.Helper()
	if c.wantError == nil {
		c.wantError = require.NoError
	}

	version := NewVersion(c.version, format)

	isSatisfied, err := constraint.Satisfied(version)
	c.wantError(t, err)
	if err != nil {
		return
	}
	assert.Equal(t, c.satisfied, isSatisfied, "unexpected constraint check result")
}
