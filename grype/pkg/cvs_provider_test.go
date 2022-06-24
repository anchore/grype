package pkg

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/logger"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		name             string
		userInput        string
		expectedLogs     []string
		expectedPackages []string
	}{
		{"passes without warnings", "csv:test-fixtures/valid.csv", []string{}, []string{"phpbugtracker", "jrun"}},
		{"passes with warnings", "csv:test-fixtures/valid-with-warnings.csv", []string{"fixed version is required", "include a purl increase"}, []string{"jrun", "redis"}},
	}

	for _, tc := range tests {
		r, w, err := os.Pipe()
		require.NoError(t, err)
		Stderr := os.Stderr
		os.Stderr = w
		currentLogger := log.Log
		log.Log = logger.NewLogrusLogger(logger.LogrusConfig{EnableConsole: true, Level: logrus.WarnLevel})
		t.Run(tc.name, func(t *testing.T) {
			//WHEN
			packages, _, err := csvProvider(tc.userInput)

			//THEN
			os.Stderr = Stderr
			assert.NoError(t, w.Close())
			assert.NoError(t, err)
			packageNames := []string{}
			for _, pkg := range packages {
				packageNames = append(packageNames, pkg.Name)
			}
			bytes, err := ioutil.ReadAll(r)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedPackages, packageNames)
			for _, expectedLog := range tc.expectedLogs {
				assert.Contains(t, string(bytes), expectedLog)
			}
		})
		log.Log = currentLogger
	}
}
