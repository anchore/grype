package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDisplayDBProvidersTable(t *testing.T) {
	providers := []provider{
		{
			Name:         "provider1",
			Version:      "1.0.0",
			Processor:    "vunnel@3.2",
			DateCaptured: timeRef(time.Date(2024, 11, 25, 14, 30, 0, 0, time.UTC)),
			InputDigest:  "xxh64:1234567834567",
		},
		{
			Name:         "provider2",
			Version:      "2.0.0",
			Processor:    "vunnel@3.2",
			DateCaptured: timeRef(time.Date(2024, 11, 26, 10, 15, 0, 0, time.UTC)),
			InputDigest:  "xxh64:9876543212345",
		},
	}

	expectedOutput := `NAME       VERSION  PROCESSOR   DATE CAPTURED                  INPUT DIGEST        
provider1  1.0.0    vunnel@3.2  2024-11-25 14:30:00 +0000 UTC  xxh64:1234567834567  
provider2  2.0.0    vunnel@3.2  2024-11-26 10:15:00 +0000 UTC  xxh64:9876543212345  
`

	var output bytes.Buffer
	displayDBProvidersTable(providers, &output)

	require.Equal(t, expectedOutput, output.String())
}

func TestDisplayDBProvidersJSON(t *testing.T) {
	providers := []provider{
		{
			Name:         "provider1",
			Version:      "1.0.0",
			Processor:    "vunnel@3.2",
			DateCaptured: timeRef(time.Date(2024, 11, 25, 14, 30, 0, 0, time.UTC)),
			InputDigest:  "xxh64:1234567834567",
		},
		{
			Name:         "provider2",
			Version:      "2.0.0",
			Processor:    "vunnel@3.2",
			DateCaptured: timeRef(time.Date(2024, 11, 26, 10, 15, 0, 0, time.UTC)),
			InputDigest:  "xxh64:9876543212345",
		},
	}

	expectedJSON := `[
 {
  "name": "provider1",
  "version": "1.0.0",
  "processor": "vunnel@3.2",
  "dateCaptured": "2024-11-25T14:30:00Z",
  "inputDigest": "xxh64:1234567834567"
 },
 {
  "name": "provider2",
  "version": "2.0.0",
  "processor": "vunnel@3.2",
  "dateCaptured": "2024-11-26T10:15:00Z",
  "inputDigest": "xxh64:9876543212345"
 }
]
`

	var output bytes.Buffer
	err := displayDBProvidersJSON(providers, &output)
	require.NoError(t, err)

	require.JSONEq(t, expectedJSON, output.String())
}

func TestGetLegacyProviders(t *testing.T) {

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
				Providers: []legacyProviderMetadata{
					{
						Name:              "provider1",
						LastSuccessfulRun: "2024-10-16T01:33:16.844201Z",
					},
					{
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
			providers, err := getLegacyProviders(test.fileLocation)
			if err != nil {
				if errors.Is(err, test.expectedError) {
					return
				}
				t.Errorf("getLegacyProviders() expected list of providers, got error:  %v", err)
				return
			}
			if !reflect.DeepEqual(*providers, test.expectedProviders) {
				t.Error("getLegacyProviders() providers comparison failed, got error")
			}
		})
	}

}

func TestDisplayLegacyProvidersTable(t *testing.T) {
	tests := []struct {
		name           string
		providers      dbProviders
		expectedOutput string
	}{
		{
			name: "display providers table",
			providers: dbProviders{
				Providers: []legacyProviderMetadata{
					{
						Name:              "provider1",
						LastSuccessfulRun: "2024-10-16T01:33:16.844201Z",
					},
					{
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
				Providers: []legacyProviderMetadata{},
			},
			expectedOutput: "NAME  LAST SUCCESSFUL RUN \n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			var out bytes.Buffer
			displayLegacyProvidersTable(test.providers.Providers, &out)
			outputString := out.String()
			if outputString != test.expectedOutput {
				t.Errorf("displayLegacyProvidersTable() = %v, want %v", out.String(), test.expectedOutput)
			}
		})
	}
}

func TestDisplayLegacyProvidersJSON(t *testing.T) {
	tests := []struct {
		name      string
		providers dbProviders
	}{

		{
			name: "display providers table",
			providers: dbProviders{
				Providers: []legacyProviderMetadata{
					{
						Name:              "provider1",
						LastSuccessfulRun: "2024-10-16T01:33:16.844201Z",
					},
					{
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
			err := displayLegacyProvidersJSON(&test.providers, &out)
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

func timeRef(t time.Time) *time.Time {
	return &t
}
