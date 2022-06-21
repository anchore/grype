package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CsvProvider_Fails(t *testing.T) {
	//GIVEN
	tests := []struct {
		name      string
		userInput string
	}{
		{"fails on path with nonexistant file", "csv:tttt/empty.csv"},
		{"fails on invalid path", "csv:~&&"},
		{"fails on empty csv", "csv:test-fixtures/empty.csv"},
		{"fails on invalid file", "csv:test-fixtures/empty.csv"},
		{"fails on invalid cpe in file", "csv:test-fixtures/invalid.csv"},
		{"fails on invalid user input", "dir:test-fixtures/empty.csv"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			//WHEN
			packages, _, err := csvProvider(tc.userInput)

			//THEN
			assert.Nil(t, packages)
			assert.Error(t, err)
			assert.NotEqual(t, "", err.Error())
		})
	}
}

func Test_CsvProvide(t *testing.T) {
	//GIVEN
	tests := []struct {
		name      string
		userInput string
	}{
		{"passes", "csv:test-fixtures/valid.csv"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			//WHEN
			packages, _, err := csvProvider(tc.userInput)

			//THEN
			assert.NotNil(t, packages)
			assert.NoError(t, err)
		})
	}
}
