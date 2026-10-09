package osv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/version"
)

// Test_normalizeConstraint_conjunctionSeparator covers the separator between two
// bounds of a single range. versionutil.AndConstraints joins with a space, which
// the apk and rpm constraint parsers reject outright — they read "7.4.0 < 7.4.6-r0"
// as a malformed version rather than a conjunction. The result is not an error at
// build time but a range that silently never matches, so any OSV record pairing an
// `introduced` with a `fixed` would be dropped on the floor.
func Test_normalizeConstraint_conjunctionSeparator(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		rangeType  string
		want       string
	}{
		{
			name:       "apk two-bound window gets a comma",
			constraint: ">= 7.4.0 < 7.4.6-r0",
			rangeType:  "apk",
			want:       ">= 7.4.0, < 7.4.6-r0",
		},
		{
			name:       "rpm two-bound window gets a comma",
			constraint: ">= 8.0 < 8.4-1",
			rangeType:  "rpm",
			want:       ">= 8.0, < 8.4-1",
		},
		{
			name:       "apk single bound is untouched",
			constraint: "< 7.4.6-r0",
			rangeType:  "apk",
			want:       "< 7.4.6-r0",
		},
		{
			name:       "apk open-ended lower bound is untouched",
			constraint: ">= 7.4.0",
			rangeType:  "apk",
			want:       ">= 7.4.0",
		},
		{
			name:       "apk versions keep their own spacing and suffixes",
			constraint: ">= 2.5.4-1 < 2.6.0-r0",
			rangeType:  "apk",
			want:       ">= 2.5.4-1, < 2.6.0-r0",
		},
		{
			name:       "semver still routes through the semver rewrite",
			constraint: ">= 1.19.0-0 < 1.19.1",
			rangeType:  "semver",
			want:       ">=1.19.0-0,<1.19.1",
		},
		{
			name:       "go still routes through the semver rewrite",
			constraint: ">= 1.19.0-0 < 1.19.1",
			rangeType:  "go",
			want:       ">=1.19.0-0,<1.19.1",
		},
		{
			name:       "empty stays empty",
			constraint: "",
			rangeType:  "apk",
			want:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeConstraint(tt.constraint, tt.rangeType))
		})
	}
}

// Test_eventsToRanges_apkWindowIsSatisfiable is the regression that matters: the
// constraint this builds has to survive the apk parser and evaluate correctly,
// not merely look right as a string.
func Test_eventsToRanges_apkWindowIsSatisfiable(t *testing.T) {
	ranges := eventsToRanges(
		[]osvmodel.Event{{Introduced: "7.4.0"}, {Fixed: "7.4.6-r0"}},
		nil,
		"apk",
	)
	require.Len(t, ranges, 1)

	constraint, err := version.GetConstraint(ranges[0].Version.Constraint, version.ApkFormat)
	require.NoError(t, err, "apk parser must accept the generated constraint")

	tests := []struct {
		installed string
		want      bool
	}{
		{"7.4.5-r0", true},   // inside the window
		{"7.4.6-r0", false},  // the fix itself
		{"7.4.7-r0", false},  // past the fix
		{"7.2.11-r0", false}, // an older branch, not this window's business
		{"8.0.4-r0", false},  // a newer branch, previously swept up by "< highest"
	}
	for _, tt := range tests {
		t.Run(tt.installed, func(t *testing.T) {
			got, err := constraint.Satisfied(version.New(tt.installed, version.ApkFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
