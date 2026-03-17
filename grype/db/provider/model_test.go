package provider

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	db "github.com/anchore/grype/grype/db/v6"
)

func TestProviderModel(t *testing.T) {
	tests := []struct {
		name     string
		state    State
		expected *db.Provider
	}{
		{
			name: "valid state with listing",
			state: State{
				Provider:  "test-provider",
				Version:   2,
				Processor: "test-processor",
				Timestamp: time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC),
				Listing: &File{
					Algorithm: "sha256",
					Digest:    "abc123",
				},
			},
			expected: &db.Provider{
				ID:           "test-provider",
				Version:      "2",
				Processor:    "test-processor",
				DateCaptured: func() *time.Time { t := time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC); return &t }(),
				InputDigest:  "sha256:abc123",
			},
		},
		{
			name: "valid state without listing",
			state: State{
				Provider:  "test-provider",
				Version:   1,
				Processor: "test-processor",
				Timestamp: time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC),
				Listing:   nil,
			},
			expected: &db.Provider{
				ID:           "test-provider",
				Version:      "1",
				Processor:    "test-processor",
				DateCaptured: func() *time.Time { t := time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC); return &t }(),
				InputDigest:  "",
			},
		},
		{
			name: "valid state with empty listing fields",
			state: State{
				Provider:  "test-provider",
				Version:   3,
				Processor: "test-processor",
				Timestamp: time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC),
				Listing: &File{
					Algorithm: "",
					Digest:    "",
				},
			},
			expected: &db.Provider{
				ID:           "test-provider",
				Version:      "3",
				Processor:    "test-processor",
				DateCaptured: func() *time.Time { t := time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC); return &t }(),
				InputDigest:  "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Model(tt.state)
			require.Equal(t, tt.expected, result)
		})
	}
}
