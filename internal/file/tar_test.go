package file

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func Test_copyWithLimits(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		byteReadLimit int64
		target        string
		expectWritten string
		expectErr     bool
	}{
		{
			name:          "write bytes",
			input:         "something here",
			byteReadLimit: 1000,
			target:        "dont care",
			expectWritten: "something here",
			expectErr:     false,
		},
		{
			name:          "surpass upper limit",
			input:         "something here",
			byteReadLimit: 11,
			target:        "dont care",
			expectWritten: "something h",
			expectErr:     true,
		},
		// since we want the threshold being reached to be easily detectable, simply reaching the threshold is
		// enough to cause an error. Otherwise surpassing the threshold would be undetectable.
		{
			name:          "reach limit exactly",
			input:         "something here",
			byteReadLimit: 14,
			target:        "dont care",
			expectWritten: "something here",
			expectErr:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := &bytes.Buffer{}
			err := copyWithLimits(writer, strings.NewReader(test.input), test.byteReadLimit, test.target)
			if (err != nil) != test.expectErr {
				t.Errorf("copyWithLimits() error = %v, want %v", err, test.expectErr)
				return
			} else if err != nil {
				assert.Contains(t, err.Error(), test.target)
			}
			assert.Equal(t, test.expectWritten, writer.String())

		})
	}
}
