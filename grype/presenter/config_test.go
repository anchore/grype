package presenter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatedConfig(t *testing.T) {
	cases := []struct {
		name                    string
		outputValue             []string
		includeSuppressed       bool
		outputTemplateFileValue string
		expectedConfig          Config
		assertErrExpectation    func(assert.TestingT, error, ...interface{}) bool
	}{
		{
			"valid template config",
			[]string{"template"},
			false,
			"./template/test-fixtures/test.valid.template",
			Config{
				formats:          []format{{id: templateFormat}},
				templateFilePath: "./template/test-fixtures/test.valid.template",
			},
			assert.NoError,
		},
		{
			"template file with non-template format",
			[]string{"json"},
			false,
			"./some/path/to/a/custom.template",
			Config{},
			assert.Error,
		},
		{
			"unknown format",
			[]string{"some-made-up-format"},
			false,
			"",
			Config{},
			assert.Error,
		},

		{
			"table format",
			[]string{"table"},
			true,
			"",
			Config{
				formats:        []format{{id: tableFormat}},
				showSuppressed: true,
			},
			assert.NoError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actualConfig, actualErr := ValidatedConfig(tc.outputValue, "", tc.outputTemplateFileValue, tc.includeSuppressed)

			assert.Equal(t, tc.expectedConfig, actualConfig)
			tc.assertErrExpectation(t, actualErr)
		})
	}
}
