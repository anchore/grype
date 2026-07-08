package v6

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func asPtr[T any](v T) *T { return &v }

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

func TestPackageBlob_WithFixAvailability(t *testing.T) {
	testTime := time.Date(2022, 4, 9, 0, 0, 0, 0, time.UTC)

	blob := PackageBlob{
		CVEs: []string{"CVE-2021-3521"},
		Ranges: []Range{
			{
				Version: Version{
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

	var unmarshaledBlob PackageBlob
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

// TestPackageQualifiers_RoundTrip locks in the JSON shape of PackageQualifiers.
//
// Field-level coverage matters because PackageQualifiers is persisted into the
// blob store as JSON: a stray rename or json-tag drift would silently corrupt
// every advisory's qualifiers when the build picks the new schema up. The
// `omitempty` behavior is also load-bearing — every qualifier field is a
// pointer/slice so that absent qualifiers produce a minimal blob.
func TestPackageQualifiers_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		input    PackageQualifiers
		wantJSON string
	}{
		{
			name:     "all fields nil produces empty object",
			input:    PackageQualifiers{},
			wantJSON: `{}`,
		},
		{
			name: "architecture only",
			input: PackageQualifiers{
				Architecture: asPtr("x86_64"),
			},
			wantJSON: `{"architecture":"x86_64"}`,
		},
		{
			name: "architecture aarch64",
			input: PackageQualifiers{
				Architecture: asPtr("aarch64"),
			},
			wantJSON: `{"architecture":"aarch64"}`,
		},
		{
			name: "architecture src sentinel",
			input: PackageQualifiers{
				Architecture: asPtr("src"),
			},
			wantJSON: `{"architecture":"src"}`,
		},
		{
			name: "full qualifier set",
			input: PackageQualifiers{
				RpmModularity: asPtr("nodejs:16"),
				PlatformCPEs:  []string{"cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*"},
				RootIO:        asPtr(true),
				Architecture:  asPtr("aarch64"),
			},
			wantJSON: `{"rpm_modularity":"nodejs:16","platform_cpes":["cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*"],"rootio":true,"architecture":"aarch64"}`,
		},
	}

	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.input)
			require.NoError(t, err)
			assert.JSONEq(t, test.wantJSON, string(data))

			var got PackageQualifiers
			require.NoError(t, json.Unmarshal(data, &got))
			if diff := cmp.Diff(test.input, got); diff != "" {
				t.Errorf("PackageQualifiers round-trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
