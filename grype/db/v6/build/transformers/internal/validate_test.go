package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"

	db "github.com/anchore/grype/grype/db/v6"
)

func TestFixVersionIsVulnerable(t *testing.T) {
	tests := []struct {
		name       string
		version    db.Version
		fixVersion string
		want       bool
	}{
		{
			// the normal shape: the range is closed just below the fix, so the fix is not vulnerable
			name:       "range closed below the fix version",
			version:    db.Version{Type: "rpm", Constraint: ">= 0:7.61.0-1.el9, < 0:7.88.0-1.el9_2"},
			fixVersion: "0:7.88.0-1.el9_2",
			want:       false,
		},
		{
			// the hazard: an advisory carrying only an "introduced" event, later patched without
			// the range being closed above the fix
			name:       "range left open above the fix version",
			version:    db.Version{Type: "rpm", Constraint: ">= 0"},
			fixVersion: "0:7.88.0-1.el9_2",
			want:       true,
		},
		{
			name:       "dpkg range left open above the fix version",
			version:    db.Version{Type: "dpkg", Constraint: ">= 7.68.0"},
			fixVersion: "7.68.0-1ubuntu2.10",
			want:       true,
		},
		{
			name:       "fix version sits above a closed range",
			version:    db.Version{Type: "dpkg", Constraint: ">= 7.68.0, < 7.68.0-1ubuntu2.10"},
			fixVersion: "7.68.0-1ubuntu2.10",
			want:       false,
		},
		{
			name:       "bare upper bound excludes the fix version",
			version:    db.Version{Type: "apk", Constraint: "< 1.2.3-r1"},
			fixVersion: "1.2.3-r1",
			want:       false,
		},
		{
			name:       "no fix version to check",
			version:    db.Version{Type: "rpm", Constraint: ">= 0"},
			fixVersion: "",
			want:       false,
		},
		{
			name:       "no constraint to check",
			version:    db.Version{Type: "rpm", Constraint: ""},
			fixVersion: "0:7.88.0-1.el9_2",
			want:       false,
		},
		{
			// unparseable data is ValidateAffectedVersion's concern; this check stays quiet
			name:       "unparseable constraint is not reported",
			version:    db.Version{Type: "rpm", Constraint: "None"},
			fixVersion: "2.36.4-1",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FixVersionIsVulnerable(tt.version, tt.fixVersion))
		})
	}
}
