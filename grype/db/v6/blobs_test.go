package v6

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixAvailability_MarshalJSON(t *testing.T) {
	testTime := time.Date(2022, 4, 9, 15, 30, 45, 0, time.UTC)

	fixAvail := FixAvailability{
		Date: &testTime,
		Kind: "advisory",
	}

	jsonData, err := json.Marshal(fixAvail)
	require.NoError(t, err)

	expected := `{"date":"2022-04-09","kind":"advisory"}`
	assert.JSONEq(t, expected, string(jsonData))
}

func TestFixAvailability_UnmarshalJSON_SimpleDateFormat(t *testing.T) {
	jsonData := `{"date":"2022-04-09","kind":"advisory"}`

	var fixAvail FixAvailability
	err := json.Unmarshal([]byte(jsonData), &fixAvail)
	require.NoError(t, err)

	expectedTime := time.Date(2022, 4, 9, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, &expectedTime, fixAvail.Date)
	assert.Equal(t, "advisory", fixAvail.Kind)
}

func TestFixAvailability_UnmarshalJSON_RFC3339Format(t *testing.T) {
	jsonData := `{"date":"2022-04-09T00:00:00Z","kind":"advisory"}`

	var fixAvail FixAvailability
	err := json.Unmarshal([]byte(jsonData), &fixAvail)
	require.NoError(t, err)

	expectedTime := time.Date(2022, 4, 9, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, &expectedTime, fixAvail.Date)
	assert.Equal(t, "advisory", fixAvail.Kind)
}

func TestFixAvailability_RoundTripMarshalUnmarshal(t *testing.T) {
	originalTime := time.Date(2022, 4, 9, 15, 30, 45, 0, time.UTC)

	original := FixAvailability{
		Date: &originalTime,
		Kind: "advisory",
	}

	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	var unmarshaled FixAvailability
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	// Time precision is lost during marshaling - only date is preserved
	expectedTime := time.Date(2022, 4, 9, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, &expectedTime, unmarshaled.Date)
	assert.Equal(t, "advisory", unmarshaled.Kind)
}

func TestAffectedPackageBlob_WithFixAvailability(t *testing.T) {
	testTime := time.Date(2022, 4, 9, 0, 0, 0, 0, time.UTC)

	blob := AffectedPackageBlob{
		CVEs: []string{"CVE-2021-3521"},
		Ranges: []AffectedRange{
			{
				Version: AffectedVersion{
					Type:       "rpm",
					Constraint: "< 0:4.14.2-15.cm1",
				},
				Fix: &Fix{
					Version: "0:4.14.2-15.cm1",
					State:   FixedStatus,
					Detail: &FixDetail{
						Available: &FixAvailability{
							Date: &testTime,
							Kind: "advisory",
						},
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(blob)
	require.NoError(t, err)

	assert.Contains(t, string(jsonData), `"date":"2022-04-09"`)
	assert.NotContains(t, string(jsonData), `"date":"2022-04-09T`)

	var unmarshaledBlob AffectedPackageBlob
	err = json.Unmarshal(jsonData, &unmarshaledBlob)
	require.NoError(t, err)

	require.Len(t, unmarshaledBlob.Ranges, 1)
	require.NotNil(t, unmarshaledBlob.Ranges[0].Fix)
	require.NotNil(t, unmarshaledBlob.Ranges[0].Fix.Detail)
	require.NotNil(t, unmarshaledBlob.Ranges[0].Fix.Detail.Available)

	assert.Equal(t, &testTime, unmarshaledBlob.Ranges[0].Fix.Detail.Available.Date)
	assert.Equal(t, "advisory", unmarshaledBlob.Ranges[0].Fix.Detail.Available.Kind)
}

func TestFixAvailability_UnmarshalJSON_InvalidDateFormat(t *testing.T) {
	jsonData := `{"date":"invalid-date","kind":"advisory"}`

	var fixAvail FixAvailability
	err := json.Unmarshal([]byte(jsonData), &fixAvail)

	require.Error(t, err)
	assert.Contains(t, err.Error(), `unable to parse date "invalid-date"`)
	assert.Contains(t, err.Error(), "expected format YYYY-MM-DD or RFC3339")
}
