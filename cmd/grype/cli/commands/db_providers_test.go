package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestGetDBProviders(t *testing.T) {

	tests := []struct {
		name              string
		fileLocation      string
		expectedProviders dbProviders
		expectedError     error
	}{
		{
			name:         "test provider metadata file",
			fileLocation: "./test-fixtures",
			expectedProviders: dbProviders{
				Providers: []dbProviderMetadata{
					dbProviderMetadata{
						Name:              "provider1",
						LastSuccessfulRun: "2024-10-16T01:33:16.844201Z",
					},
					dbProviderMetadata{
						Name:              "provider2",
						LastSuccessfulRun: "2024-10-16T01:32:43.516596Z",
					},
				},
			},
			expectedError: nil,
		},
		{
			name:              "no metadata file found",
			fileLocation:      "./",
			expectedProviders: dbProviders{},
			expectedError:     os.ErrNotExist,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providers, err := getDBProviders(test.fileLocation)
			if err != nil {
				if errors.Is(err, test.expectedError) {
					return
				}
				t.Errorf("getDBProviders() expected list of providers, got error:  %v", err)
				return
			}
			if !reflect.DeepEqual(*providers, test.expectedProviders) {
				t.Error("getDBProviders() providers comparison failed, got error")
			}
		})
	}

}

func TestDisplayDBProvidersTable(t *testing.T) {
	tests := []struct {
		name           string
		providers      dbProviders
		expectedOutput string
	}{
		{
			name: "display providers table",
			providers: dbProviders{
				Providers: []dbProviderMetadata{
					dbProviderMetadata{
						Name:              "provider1",
						LastSuccessfulRun: "2024-10-16T01:33:16.844201Z",
					},
					dbProviderMetadata{
						Name:              "provider2",
						LastSuccessfulRun: "2024-10-16T01:32:43.516596Z",
					},
				},
			},
			expectedOutput: "NAME       LAST SUCCESSFUL RUN         \nprovider1  2024-10-16T01:33:16.844201Z  \nprovider2  2024-10-16T01:32:43.516596Z  \n",
		},
		{
			name: "empty list of providers",
			providers: dbProviders{
				Providers: []dbProviderMetadata{},
			},
			expectedOutput: "NAME  LAST SUCCESSFUL RUN \n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			var out bytes.Buffer
			displayDBProvidersTable(test.providers.Providers, &out)
			outputString := out.String()
			if outputString != test.expectedOutput {
				t.Errorf("displayDBProvidersTable() = %v, want %v", out.String(), test.expectedOutput)
			}
		})
	}
}

func TestDisplayDBProvidersJSON(t *testing.T) {
	tests := []struct {
		name      string
		providers dbProviders
	}{

		{
			name: "display providers table",
			providers: dbProviders{
				Providers: []dbProviderMetadata{
					dbProviderMetadata{
						Name:              "provider1",
						LastSuccessfulRun: "2024-10-16T01:33:16.844201Z",
					},
					dbProviderMetadata{
						Name:              "provider2",
						LastSuccessfulRun: "2024-10-16T01:32:43.516596Z",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			var out bytes.Buffer
			err := displayDBProvidersJSON(&test.providers, &out)
			if err != nil {
				t.Error(err)
			}
			var providers dbProviders

			err = json.Unmarshal(out.Bytes(), &providers)
			if err != nil {
				t.Error(err)
			}

			if !reflect.DeepEqual(providers, test.providers) {
				t.Error("DBProvidersJSON() providers comparison failed, got error")
			}

		})
	}
}
