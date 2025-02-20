package v6

import (
	"encoding/json"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal/schemaver"
)

func TestReadDescription(t *testing.T) {
	tempDir := t.TempDir()

	s, err := NewWriter(Config{DBDirPath: tempDir})
	require.NoError(t, err)
	require.NoError(t, s.SetDBMetadata())
	expected, err := s.GetDBMetadata()
	require.NoError(t, err)
	require.NoError(t, s.Close())

	dbFilePath := path.Join(tempDir, VulnerabilityDBFileName)

	description, err := ReadDescription(dbFilePath)
	require.NoError(t, err)
	require.NotNil(t, description)

	assert.Equal(t, Description{
		SchemaVersion: schemaver.New(expected.Model, expected.Revision, expected.Addition),
		Built:         Time{*expected.BuildTimestamp},
	}, *description)
}

func TestTime_JSONMarshalling(t *testing.T) {
	tests := []struct {
		name     string
		time     Time
		expected string
	}{
		{
			name:     "go case",
			time:     Time{time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
			expected: `"2023-09-26T12:00:00Z"`,
		},
		{
			name:     "convert to utc",
			time:     Time{time.Date(2023, 9, 26, 13, 0, 0, 0, time.FixedZone("UTC+1", 3600))},
			expected: `"2023-09-26T12:00:00Z"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.time)
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(jsonData))
		})
	}
}

func TestTime_JSONUnmarshalling(t *testing.T) {
	tests := []struct {
		name         string
		jsonData     string
		expectedTime Time
		expectError  require.ErrorAssertionFunc
	}{
		{
			name:         "use zulu offset",
			jsonData:     `"2023-09-26T12:00:00Z"`,
			expectedTime: Time{time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
		},
		{
			name:         "use tz offset in another timezone",
			jsonData:     `"2023-09-26T14:00:00+02:00"`,
			expectedTime: Time{time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
		},
		{
			name:         "use tz offset that is utc",
			jsonData:     `"2023-09-26T12:00:00+00:00"`,
			expectedTime: Time{time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
		},
		{
			name:        "invalid format",
			jsonData:    `"invalid-time-format"`,
			expectError: require.Error,
		},
		{
			name:        "invalid json",
			jsonData:    `invalid`,
			expectError: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectError == nil {
				tt.expectError = require.NoError
			}
			var parsedTime Time
			err := json.Unmarshal([]byte(tt.jsonData), &parsedTime)
			tt.expectError(t, err)
			if err == nil {
				assert.Equal(t, tt.expectedTime.Time, parsedTime.Time)
			}
		})
	}
}
