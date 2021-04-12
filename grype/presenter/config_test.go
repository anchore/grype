package presenter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatedConfig(t *testing.T) {
	cases := []struct {
		name                    string
		outputValue             string
		outputTemplateFileValue string
		expectedConfig          Config
		assertErrExpectation    func(assert.TestingT, error, ...interface{}) bool
	}{
		{
			"valid template config",
			"template",
			"./some/path/to/a/custom.template",
			Config{
				format:           "template",
				templateFilePath: "./some/path/to/a/custom.template",
			},
			assert.NoError,
		},
		{
			"template file with non-template format",
			"json",
			"./some/path/to/a/custom.template",
			Config{},
			assert.Error,
		},
		{
			"unknown format",
			"some-made-up-format",
			"",
			Config{},
			assert.Error,
		},

		{
			"table format",
			"table",
			"",
			Config{
				format: tableFormat,
			},
			assert.NoError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actualConfig, actualErr := ValidatedConfig(tc.outputValue, tc.outputTemplateFileValue)

			assert.Equal(t, tc.expectedConfig, actualConfig)
			tc.assertErrExpectation(t, actualErr)
		})
	}
}
