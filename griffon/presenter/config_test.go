package presenter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatedConfig(t *testing.T) {
	cases := []struct {
		name                    string
		outputValue             string
		includeSuppressed       bool
		outputTemplateFileValue string
		expectedConfig          Config
		assertErrExpectation    func(assert.TestingT, error, ...interface{}) bool
	}{
		{
			"valid template config",
			"template",
			false,
			"./template/test-fixtures/test.valid.template",
			Config{
				format:           "template",
				templateFilePath: "./template/test-fixtures/test.valid.template",
			},
			assert.NoError,
		},
		{
			"template file with non-template format",
			"json",
			false,
			"./some/path/to/a/custom.template",
			Config{},
			assert.Error,
		},
		{
			"unknown format",
			"some-made-up-format",
			false,
			"",
			Config{},
			assert.Error,
		},

		{
			"table format",
			"table",
			true,
			"",
			Config{
				format:         tableFormat,
				showSuppressed: true,
			},
			assert.NoError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actualConfig, actualErr := ValidatedConfig(tc.outputValue, tc.outputTemplateFileValue, tc.includeSuppressed)

			assert.Equal(t, tc.expectedConfig, actualConfig)
			tc.assertErrExpectation(t, actualErr)
		})
	}
}
