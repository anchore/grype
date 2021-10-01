package version

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testCase struct {
	name           string
	version        string
	constraint     string
	satisfied      bool
	shouldErr      bool
	errorAssertion func(t *testing.T, err error)
}

func (c *testCase) tName() string {
	if c.name != "" {
		return c.name
	}

	return fmt.Sprintf("ver='%s'const='%s'", c.version, strings.ReplaceAll(c.constraint, " ", ""))
}

func (c *testCase) assertVersionConstraint(t *testing.T, format Format, constraint Constraint) {
	t.Helper()

	version, err := NewVersion(c.version, format)
	assert.NoError(t, err, "unexpected error from NewVersion: %v", err)

	isSatisfied, err := constraint.Satisfied(version)
	if c.shouldErr {
		if c.errorAssertion != nil {
			c.errorAssertion(t, err)
		} else {
			assert.Error(t, err)
		}
	} else {
		assert.NoError(t, err, "unexpected error from constraint.Satisfied: %v", err)
	}
	assert.Equal(t, c.satisfied, isSatisfied, "unexpected constraint check result")
}
