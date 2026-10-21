package internal

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/grype/grype/vulnerability"
)

func TestFixAvailabilityForVersions(t *testing.T) {
	early := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		fixVersions []string
		candidates  []vulnerability.FixAvailable
		want        []vulnerability.FixAvailable
	}{
		{
			name:        "no fix versions",
			fixVersions: nil,
			candidates:  []vulnerability.FixAvailable{{Version: "1.0", Date: early}},
			want:        nil,
		},
		{
			name:        "keeps only availability for the given fix versions",
			fixVersions: []string{"1.5"},
			candidates: []vulnerability.FixAvailable{
				{Version: "1.6", Date: early, Kind: "first-observed"},
				{Version: "1.5", Date: late, Kind: "advisory"},
			},
			want: []vulnerability.FixAvailable{{Version: "1.5", Date: late, Kind: "advisory"}},
		},
		{
			name:        "same version from multiple candidates keeps the earliest date",
			fixVersions: []string{"1.5"},
			candidates: []vulnerability.FixAvailable{
				{Version: "1.5", Date: late, Kind: "first-observed"},
				{Version: "1.5", Date: early, Kind: "advisory"},
			},
			want: []vulnerability.FixAvailable{{Version: "1.5", Date: early, Kind: "advisory"}},
		},
		{
			name:        "zero date does not displace a dated entry",
			fixVersions: []string{"1.5"},
			candidates: []vulnerability.FixAvailable{
				{Version: "1.5", Date: late, Kind: "advisory"},
				{Version: "1.5", Kind: "first-observed"}, // zero date
			},
			want: []vulnerability.FixAvailable{{Version: "1.5", Date: late, Kind: "advisory"}},
		},
		{
			name:        "follows fix version order and skips versions without availability",
			fixVersions: []string{"2.0", "1.5", "1.0"},
			candidates: []vulnerability.FixAvailable{
				{Version: "1.0", Date: early},
				{Version: "2.0", Date: late},
			},
			want: []vulnerability.FixAvailable{{Version: "2.0", Date: late}, {Version: "1.0", Date: early}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FixAvailabilityForVersions(tt.fixVersions, tt.candidates)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("FixAvailabilityForVersions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
