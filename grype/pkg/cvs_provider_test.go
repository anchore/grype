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
		{"fails on empty csv", "csv:test-fixtures/empty.csv"},
		{"fails on invalid file", "csv:test-fixtures/empty.csv"},
		{"fails on invalid user input", "dir:test-fixtures/empty.csv"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			//WHEN
			packages, _, err := csvProvider(tc.userInput)

			//THEN
			assert.Nil(t, packages)
			assert.Error(t, err)
		})
	}
}
