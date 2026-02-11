package internal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseTime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *time.Time
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:  "valid RFC3339 with Z",
			input: "2024-11-15T12:34:56Z",
			expected: func() *time.Time {
				t, _ := time.Parse(time.RFC3339, "2024-11-15T12:34:56Z")
				return &t
			}(),
		},
		{
			name:  "valid RFC3339 without Z",
			input: "2024-11-15T12:34:56",
			expected: func() *time.Time {
				t, _ := time.Parse(time.RFC3339, "2024-11-15T12:34:56Z")
				return &t
			}(),
		},
		{
			name:  "valid with milliseconds no timezone",
			input: "2024-11-15T12:34:56.789",
			expected: func() *time.Time {
				t, _ := time.Parse("2006-01-02T15:04:05.000", "2024-11-15T12:34:56.789")
				utc := t.UTC()
				return &utc
			}(),
		},
		{
			name:  "valid with milliseconds and Z",
			input: "2024-11-15T12:34:56.789Z",
			expected: func() *time.Time {
				t, _ := time.Parse("2006-01-02T15:04:05.000Z", "2024-11-15T12:34:56.789Z")
				utc := t.UTC()
				return &utc
			}(),
		},
		{
			name:  "valid dateparse format",
			input: "November 15, 2024 12:34 PM UTC",
			expected: func() *time.Time {
				t, _ := time.Parse(time.RFC3339, "2024-11-15T12:34:00Z")
				return &t
			}(),
		},
		{
			name:  "valid date only",
			input: "2024-11-15",
			expected: func() *time.Time {
				t, _ := time.Parse("2006-01-02", "2024-11-15")
				utc := t.UTC()
				return &utc
			}(),
		},
		{
			name:  "valid date with time",
			input: "2024-11-15 01:02:03",
			expected: func() *time.Time {
				t, _ := time.Parse(time.RFC3339, "2024-11-15T01:02:03Z")
				return &t
			}(),
		},
		{
			name:  "invalid time format",
			input: "invalid-time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseTime(tt.input)
			if tt.expected == nil {
				require.Nil(t, result)
			} else {
				require.NotNil(t, result)
				require.Equal(t, tt.expected.UTC(), result.UTC())
			}
		})
	}
}
