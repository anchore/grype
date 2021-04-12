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
		expectedConfig          config
		assertErrExpectation    func(assert.TestingT, error, ...interface{}) bool
	}{
		{
			"valid template config",
			"template",
			"./some/path/to/a/custom.template",
			config{
				format:           "template",
				templateFilePath: "./some/path/to/a/custom.template",
			},
			assert.NoError,
		},
		{
			"template file with non-template format",
			"json",
			"./some/path/to/a/custom.template",
			config{},
			assert.Error,
		},
		{
			"unknown format",
			"some-made-up-format",
			"",
			config{},
			assert.Error,
		},

		{
			"table format",
			"table",
			"",
			config{
				format: tableFormat,
			},
			assert.NoError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actualConfig, actualErr := validatedConfig(tc.outputValue, tc.outputTemplateFileValue)

			assert.Equal(t, tc.expectedConfig, actualConfig)
			tc.assertErrExpectation(t, actualErr)
		})
	}
}
