package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertTypes(t *testing.T) {
	tests := []struct {
		name     string
		alert    AlertType
		expected string
	}{
		{
			name:     "distro EOL alert type",
			alert:    AlertTypeDistroEOL,
			expected: "distro-eol",
		},
		{
			name:     "distro unknown alert type",
			alert:    AlertTypeDistroUnknown,
			expected: "distro-unknown",
		},
		{
			name:     "distro disabled alert type",
			alert:    AlertTypeDistroDisabled,
			expected: "distro-disabled",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, string(tc.alert))
		})
	}
}

func TestAlertJSONSerialization(t *testing.T) {
	alert := Alert{
		Type:    AlertTypeDistroEOL,
		Message: "Ubuntu 18.04 reached end-of-life on 2023-05-31",
		Metadata: DistroAlertMetadata{
			Name:    "ubuntu",
			Version: "18.04",
		},
	}

	jsonBytes, err := json.Marshal(alert)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(jsonBytes, &result)
	require.NoError(t, err)

	assert.Equal(t, "distro-eol", result["type"])
	assert.Equal(t, "Ubuntu 18.04 reached end-of-life on 2023-05-31", result["message"])
	assert.NotNil(t, result["metadata"])
	metadata := result["metadata"].(map[string]interface{})
	assert.Equal(t, "ubuntu", metadata["name"])
	assert.Equal(t, "18.04", metadata["version"])
}

func TestPackageAlertsJSONSerialization(t *testing.T) {
	pkgAlerts := PackageAlerts{
		Package: Package{
			ID:      "pkg-123",
			Name:    "openssl",
			Version: "1.1.1",
			Type:    "deb",
		},
		Alerts: []Alert{
			{
				Type:    AlertTypeDistroEOL,
				Message: "Package is from an end-of-life distribution",
			},
		},
	}

	jsonBytes, err := json.Marshal(pkgAlerts)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(jsonBytes, &result)
	require.NoError(t, err)

	pkg := result["package"].(map[string]interface{})
	assert.Equal(t, "openssl", pkg["name"])

	alerts := result["alerts"].([]interface{})
	assert.Len(t, alerts, 1)

	alert := alerts[0].(map[string]interface{})
	assert.Equal(t, "distro-eol", alert["type"])
}

func TestAlertDetailsOmitEmpty(t *testing.T) {
	alert := Alert{
		Type:    AlertTypeDistroUnknown,
		Message: "Unknown distro",
		// Details intentionally nil
	}

	jsonBytes, err := json.Marshal(alert)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(jsonBytes, &result)
	require.NoError(t, err)

	// Details should be omitted when nil
	_, hasDetails := result["details"]
	assert.False(t, hasDetails, "details should be omitted when nil")
}
