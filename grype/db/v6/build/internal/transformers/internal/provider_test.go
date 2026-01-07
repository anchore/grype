package internal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func TestProviderModel(t *testing.T) {
	tests := []struct {
		name     string
		state    provider.State
		expected *grypeDB.Provider
	}{
		{
			name: "valid state with listing",
			state: provider.State{
				Provider:  "test-provider",
				Version:   2,
				Processor: "test-processor",
				Timestamp: time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC),
				Listing: &provider.File{
					Algorithm: "sha256",
					Digest:    "abc123",
				},
			},
			expected: &grypeDB.Provider{
				ID:           "test-provider",
				Version:      "2",
				Processor:    "test-processor",
				DateCaptured: func() *time.Time { t := time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC); return &t }(),
				InputDigest:  "sha256:abc123",
			},
		},
		{
			name: "valid state without listing",
			state: provider.State{
				Provider:  "test-provider",
				Version:   1,
				Processor: "test-processor",
				Timestamp: time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC),
				Listing:   nil,
			},
			expected: &grypeDB.Provider{
				ID:           "test-provider",
				Version:      "1",
				Processor:    "test-processor",
				DateCaptured: func() *time.Time { t := time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC); return &t }(),
				InputDigest:  "",
			},
		},
		{
			name: "valid state with empty listing fields",
			state: provider.State{
				Provider:  "test-provider",
				Version:   3,
				Processor: "test-processor",
				Timestamp: time.Date(2024, 11, 15, 12, 34, 56, 0, time.UTC),
				Listing: &provider.File{
					Algorithm: "",
					Digest:    "",
				},
			},
			expected: &grypeDB.Provider{
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
			result := ProviderModel(tt.state)
			require.Equal(t, tt.expected, result)
		})
	}
}
