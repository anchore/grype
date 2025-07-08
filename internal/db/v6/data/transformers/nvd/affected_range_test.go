package nvd

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_AffectedCPERange_String(t *testing.T) {
	tests := []struct {
		name     string
		input    affectedCPERange
		expected string
	}{
		{
			name:     "empty range",
			input:    affectedCPERange{},
			expected: "",
		},
		{
			name: "exact version match",
			input: affectedCPERange{
				ExactVersion: "1.0",
			},
			expected: "= 1.0",
		},
		{
			name: "exact version and update match",
			input: affectedCPERange{
				ExactVersion: "1.0",
				ExactUpdate:  "p1",
			},
			expected: "= 1.0-p1",
		},
		{
			name: "version start including only",
			input: affectedCPERange{
				VersionStartIncluding: "1.0",
			},
			expected: ">= 1.0",
		},
		{
			name: "version start excluding only",
			input: affectedCPERange{
				VersionStartExcluding: "1.0",
			},
			expected: "> 1.0",
		},
		{
			name: "version end including only",
			input: affectedCPERange{
				VersionEndIncluding: "2.0",
			},
			expected: "<= 2.0",
		},
		{
			name: "version end excluding only",
			input: affectedCPERange{
				VersionEndExcluding: "2.0",
			},
			expected: "< 2.0",
		},
		{
			name: "version range with start and end including",
			input: affectedCPERange{
				VersionStartIncluding: "1.0",
				VersionEndIncluding:   "2.0",
			},
			expected: ">= 1.0, <= 2.0",
		},
		{
			name: "version range with start including and end excluding",
			input: affectedCPERange{
				VersionStartIncluding: "1.0",
				VersionEndExcluding:   "2.0",
			},
			expected: ">= 1.0, < 2.0",
		},
		{
			name: "version range with start excluding and end including",
			input: affectedCPERange{
				VersionStartExcluding: "1.0",
				VersionEndIncluding:   "2.0",
			},
			expected: "> 1.0, <= 2.0",
		},
		{
			name: "version range with start and end excluding",
			input: affectedCPERange{
				VersionStartExcluding: "1.0",
				VersionEndExcluding:   "2.0",
			},
			expected: "> 1.0, < 2.0",
		},
		{
			name: "version range with all bounds (prefer outer bounds)",
			input: affectedCPERange{
				VersionStartIncluding: "1.0",
				VersionStartExcluding: "0.9",
				VersionEndIncluding:   "2.0",
				VersionEndExcluding:   "2.1",
			},
			expected: ">= 1.0, < 2.1",
		},
		{
			name: "range constraints overrides exact version",
			input: affectedCPERange{
				ExactVersion:          "1.5",
				ExactUpdate:           "p2",
				VersionStartIncluding: "1.0",
				VersionEndExcluding:   "2.0",
			},
			expected: ">= 1.0, < 2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.String()

			if diff := cmp.Diff(tt.expected, actual); diff != "" {
				t.Errorf("buildConstraints() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
