package status

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllowedFilterStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		optIn []Status
		want  []Status
	}{
		{
			name:  "default is ignore list only",
			optIn: nil,
			want:  []Status{Fixed, NotAffected},
		},
		{
			name:  "under_investigation opted in via vex-add",
			optIn: []Status{UnderInvestigation},
			want:  []Status{Fixed, NotAffected, UnderInvestigation},
		},
		{
			name:  "affected and under_investigation opted in",
			optIn: []Status{Affected, UnderInvestigation},
			want:  []Status{Fixed, NotAffected, Affected, UnderInvestigation},
		},
		{
			name:  "fixed in optIn is ignored (already default)",
			optIn: []Status{Fixed, UnderInvestigation},
			want:  []Status{Fixed, NotAffected, UnderInvestigation},
		},
		{
			name:  "duplicate optIn statuses are deduped",
			optIn: []Status{UnderInvestigation, UnderInvestigation},
			want:  []Status{Fixed, NotAffected, UnderInvestigation},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, AllowedFilterStatuses(tt.optIn))
		})
	}
}
