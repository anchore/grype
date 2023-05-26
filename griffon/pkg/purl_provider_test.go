package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PurlProvider_Fails(t *testing.T) {
	//GIVEN
	tests := []struct {
		name      string
		userInput string
	}{
		{"fails on path with nonexistant file", "purl:tttt/empty.txt"},
		{"fails on invalid path", "purl:~&&"},
		{"fails on empty purl file", "purl:test-fixtures/empty.json"},
		{"fails on invalid purl in file", "purl:test-fixtures/invalid-purl.txt"},
		{"fails on invalid cpe in file", "purl:test-fixtures/invalid-cpe.txt"},
		{"fails on invalid user input", "dir:test-fixtures/empty.json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			//WHEN
			packages, _, err := purlProvider(tc.userInput)

			//THEN
			assert.Nil(t, packages)
			assert.Error(t, err)
			assert.NotEqual(t, "", err.Error())
		})
	}
}

func Test_CsvProvide(t *testing.T) {
	//GIVEN
	expected := []string{"curl", "ant", "log4j-core"}

	//WHEN
	packages, _, err := purlProvider("purl:test-fixtures/valid-purl.txt")

	//THEN
	packageNames := []string{}
	for _, pkg := range packages {
		assert.NotEmpty(t, pkg.ID)
		packageNames = append(packageNames, pkg.Name)
	}
	assert.NoError(t, err)
	assert.Equal(t, expected, packageNames)
}
