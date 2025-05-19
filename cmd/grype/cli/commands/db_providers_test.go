package commands

import (
	"bytes"
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

func timeRef(t time.Time) *time.Time {
	return &t
}
