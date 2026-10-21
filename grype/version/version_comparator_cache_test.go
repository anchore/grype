package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// a failed comparator build must never be cached: a cached broken comparator is
// returned with a nil error on the next lookup, which then panics (formats with a
// nil *hashiVer.Version) or silently compares against an empty version (value
// formats) when used.
func TestGetComparatorDoesNotCacheParseFailure(t *testing.T) {
	cases := []struct {
		name    string
		format  Format
		badRaw  string
		goodRaw string
	}{
		// formats whose zero-value comparator holds a nil pointer -> panic on use
		{"semantic", SemanticFormat, "3.e", "1.0"},
		{"jvm", JVMFormat, "abc", "1.0"},
		{"bitnami", BitnamiFormat, "abc", "1.0.0"},
		// value-receiver format whose zero-value silently compares as empty -> false negative
		{"deb", DebFormat, "abc", "1.0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := New(tc.badRaw, tc.format)

			_, err := v.getComparator(tc.format)
			require.Error(t, err, "expected the failed build to surface an error")
			assert.NotContains(t, v.comparators, tc.format, "failed comparator must not be cached")

			// a repeated lookup must re-attempt and surface the error again, not
			// hand back a cached broken comparator with a nil error.
			_, err = v.getComparator(tc.format)
			require.Error(t, err, "repeated lookup must still error, not return a cached broken comparator")

			// end-to-end: repeated comparison via Is (mirrors matcher/rpm/rhel_eus.go
			// neededFixes looping v.Is on the same *Version) must error, not panic.
			other := New(tc.goodRaw, tc.format)
			_, err = v.Is(LT, other)
			require.Error(t, err)
			_, err = v.Is(LT, other)
			require.Error(t, err, "repeated Is must still error (broken comparator was cached)")
		})
	}
}

// a successful build is cached for reuse on repeated lookups.
func TestGetComparatorCachesSuccess(t *testing.T) {
	v := New("1.2.3", SemanticFormat)

	first, err := v.getComparator(SemanticFormat)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Contains(t, v.comparators, SemanticFormat, "successful comparator should be cached")

	second, err := v.getComparator(SemanticFormat)
	require.NoError(t, err)
	assert.Equal(t, first, second)
}
