package file

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// looks like there isn't a helper for this yet? https://github.com/stretchr/testify/issues/497
func assertErrorAs(expectedErr interface{}) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, actualErr error, i ...interface{}) bool {
		return errors.As(actualErr, &expectedErr)
	}
}

func TestSafeJoin(t *testing.T) {
	tests := []struct {
		prefix       string
		args         []string
		expected     string
		errAssertion assert.ErrorAssertionFunc
	}{
		// go cases...
		{
			prefix: "/a/place",
			args: []string{
				"somewhere/else",
			},
			expected:     "/a/place/somewhere/else",
			errAssertion: assert.NoError,
		},
		{
			prefix: "/a/place",
			args: []string{
				"somewhere/../else",
			},
			expected:     "/a/place/else",
			errAssertion: assert.NoError,
		},
		{
			prefix: "/a/../place",
			args: []string{
				"somewhere/else",
			},
			expected:     "/place/somewhere/else",
			errAssertion: assert.NoError,
		},
		// zip slip examples....
		{
			prefix: "/a/place",
			args: []string{
				"../../../etc/passwd",
			},
			expected:     "",
			errAssertion: assertErrorAs(&errZipSlipDetected{}),
		},
		{
			prefix: "/a/place",
			args: []string{
				"../",
				"../",
			},
			expected:     "",
			errAssertion: assertErrorAs(&errZipSlipDetected{}),
		},
		{
			prefix: "/a/place",
			args: []string{
				"../",
			},
			expected:     "",
			errAssertion: assertErrorAs(&errZipSlipDetected{}),
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v:%+v", test.prefix, test.args), func(t *testing.T) {
			actual, err := safeJoin(test.prefix, test.args...)
			test.errAssertion(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
