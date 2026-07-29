package version

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vnormal renders a parsed version the way Perl_vnormal does (padding to at least three
// terms for display only), so the expectations below can be copied verbatim from perl's own
// output.
func vnormal(v *cpanVersion) string {
	parts := make([]string, 0, len(v.components))
	for _, c := range v.components {
		parts = append(parts, strconv.FormatInt(c, 10))
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	return "v" + strings.Join(parts, ".")
}

// TestCpanVersionNormalization is the shared vector table, measured against perl 5. Every
// entry is also asserted by the vunnel-side port of this algorithm; the two must agree.
func TestCpanVersionNormalization(t *testing.T) {
	tests := []struct {
		input   string
		normal  string
		isAlpha bool
	}{
		{input: "1.23", normal: "v1.230.0"},
		{input: "1.2.3", normal: "v1.2.3"},
		{input: "v1.2.3", normal: "v1.2.3"},
		{input: "1.230", normal: "v1.230.0"},
		{input: "1.2", normal: "v1.200.0"},
		{input: "v1.2", normal: "v1.2.0"},
		{input: "1.0203", normal: "v1.20.300"},
		{input: "0.90380906", normal: "v0.903.809.60"},
		{input: "5.008001", normal: "v5.8.1"},
		{input: "5.40.0", normal: "v5.40.0"},
		{input: "1.004008", normal: "v1.4.8"},
		{input: "1.303", normal: "v1.303.0"},
		{input: "v1.1.4", normal: "v1.1.4"},
		{input: "v0.41.0", normal: "v0.41.0"},
		{input: "2.150013", normal: "v2.150.13"},
		{input: "0.32", normal: "v0.320.0"},
		{input: "6.68", normal: "v6.680.0"},
		{input: "9.31", normal: "v9.310.0"},
		{input: "1.23_01", normal: "v1.230.100", isAlpha: true},
		{input: "1.23_1", normal: "v1.231.0", isAlpha: true},
		{input: "0.999920", normal: "v0.999.920"},
		{input: "20260726.001", normal: "v20260726.1.0"},
		{input: "1.9.9", normal: "v1.9.9"},
		{input: "1.10", normal: "v1.100.0"},
		{input: "1.9", normal: "v1.900.0"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			v, err := newCpanVersion(test.input)
			require.NoError(t, err)
			assert.Equal(t, test.normal, vnormal(v))
			assert.Equal(t, test.isAlpha, v.isAlpha, "unexpected alpha flag")
		})
	}
}

// TestCpanVersionOrdering is the shared ordering table. Every one of these inverts or breaks
// under semver rules and they are all correct: perl orders decimal versions by fractional
// value, not by integer components, and the alpha flag takes no part in ordering.
func TestCpanVersionOrdering(t *testing.T) {
	tests := []struct {
		left     string
		right    string
		expected int
	}{
		{left: "1.23", right: "1.2.3", expected: 1},
		{left: "1.23", right: "1.230", expected: 0},
		{left: "1.2", right: "1.10", expected: 1},
		{left: "1.9", right: "1.10", expected: 1},
		{left: "v1.2.3", right: "1.2.3", expected: 0},
		{left: "1.23", right: "v1.23.0", expected: 1},
		{left: "1.23", right: "v1.230.0", expected: 0},
		{left: "5.008001", right: "5.8.1", expected: 0},
		{left: "v1.1.4", right: "1.1.4", expected: 0},
		{left: "1.23_01", right: "1.23", expected: 1},
		{left: "1.23_01", right: "1.24", expected: -1},
		{left: "0.90380906", right: "0.9038", expected: 1},
		{left: "1.0", right: "1", expected: 0},
		{left: "v1.2", right: "v1.2.0", expected: 0},
	}

	for _, test := range tests {
		t.Run(test.left+"_vs_"+test.right, func(t *testing.T) {
			left, err := newCpanVersion(test.left)
			require.NoError(t, err)

			actual, err := left.Compare(New(test.right, CpanFormat))
			require.NoError(t, err)
			assert.Equal(t, test.expected, actual)

			// the ordering must be antisymmetric
			right, err := newCpanVersion(test.right)
			require.NoError(t, err)

			actual, err = right.Compare(New(test.left, CpanFormat))
			require.NoError(t, err)
			assert.Equal(t, -test.expected, actual)
		})
	}
}

// TestCpanVersionParseEdges covers the lax grammar edges, including the forms that perl
// accepts only in lax mode and the ones prescan_version rejects outright.
func TestCpanVersionParseEdges(t *testing.T) {
	tests := []struct {
		input   string
		normal  string
		wantErr string
	}{
		{input: "", wantErr: "version required"},
		{input: "abc", wantErr: "non-numeric data"},
		{input: "v", wantErr: "dotted-decimal versions require at least three parts"},
		{input: "1..2", wantErr: "fractional part required"},
		{input: "1_2", wantErr: "alpha without decimal"},
		{input: "1.2.3.4.5", normal: "v1.2.3.4.5"},
		{input: "0", normal: "v0.0.0"},
		{input: "v0", normal: "v0.0.0"},
		{input: ".5", normal: "v0.500.0"},
		{input: "1.", normal: "v1.0.0"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			v, err := newCpanVersion(test.input)
			if test.wantErr != "" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.normal, vnormal(v))
		})
	}
}

func TestCpanVersionComponents(t *testing.T) {
	tests := []struct {
		input      string
		components []int64
	}{
		// decimal fractional grouping
		{input: "1.2", components: []int64{1, 200}},
		{input: "1.23", components: []int64{1, 230}},
		{input: "1.0203", components: []int64{1, 20, 300}},
		{input: "0.90380906", components: []int64{0, 903, 809, 60}},
		// dotted-decimal parsing, padded to at least three components
		{input: "v1.2", components: []int64{1, 2, 0}},
		{input: "v1.2.3", components: []int64{1, 2, 3}},
		{input: "1.2.3", components: []int64{1, 2, 3}},
		// alpha underscore digits fold into the numeric groups
		{input: "1.23_01", components: []int64{1, 230, 100}},
		{input: "v1.2_3", components: []int64{1, 23, 0}},
		// lax forms
		{input: ".5", components: []int64{0, 500}},
		{input: "1.", components: []int64{1, 0}},
		// a trailing "." is only an error once a second "." has been seen, so "v1." parses
		// even though $LAX does not admit it
		{input: "v1.", components: []int64{1, 0, 0}},
		{input: "0", components: []int64{0}},
		{input: "v0", components: []int64{0, 0, 0}},
		{input: "1.2.3.4.5", components: []int64{1, 2, 3, 4, 5}},
		// leading zeros are legal in lax and always mean decimal, never octal
		{input: "010", components: []int64{10}},
		// "undef" is a valid lax version, a concession to ExtUtils::MM->parse_version
		{input: "undef", components: []int64{0}},
		// components are clamped at VERSION_MAX rather than erroring
		{input: "v1.99999999999.0", components: []int64{1, cpanVersionMax, 0}},
		{input: "v2147483647.2147483648.0", components: []int64{cpanVersionMax, cpanVersionMax, 0}},
		{input: "2147483647.5", components: []int64{cpanVersionMax, 500}},
		// an overflowed integer part stops the scan, so the fraction is never reached
		{input: "99999999999.1", components: []int64{cpanVersionMax}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			v, err := newCpanVersion(test.input)
			require.NoError(t, err)
			assert.Equal(t, test.components, v.components)
		})
	}
}

// TestCpanVersionUnparseableDegrades pins the failure mode: an unparseable version surfaces
// an error from the comparison rather than silently comparing equal. The search layer turns
// that into "skip this vulnerability" and keeps the package (see
// grype/search/version_constraint.go), so a bad version never drops a package from matching.
func TestCpanVersionUnparseableDegrades(t *testing.T) {
	c, err := GetConstraint("< 1.24", CpanFormat)
	require.NoError(t, err)

	satisfied, err := c.Satisfied(New("abc", CpanFormat))
	require.Error(t, err)
	assert.False(t, satisfied)

	// a package version that does parse still resolves against the same constraint
	satisfied, err = c.Satisfied(New("1.23_01", CpanFormat))
	require.NoError(t, err)
	assert.True(t, satisfied)

	// an unparseable constraint version is an error, not a bogus equality
	v, err := newCpanVersion("1.23")
	require.NoError(t, err)
	_, err = v.Compare(New("not-a-version", CpanFormat))
	require.Error(t, err)
}
