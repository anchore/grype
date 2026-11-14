package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpamVersionCompare(t *testing.T) {
	// all expectations are the results of `opam admin compare-versions` (opam 2.6.1)
	tests := []struct {
		v1   string
		v2   string
		want int
	}{
		{v1: "1.0.0", v2: "1.0.0", want: 0},
		{v1: "1.0.1", v2: "1.0.0", want: 1},
		{v1: "1.0.9", v2: "1.0.10", want: -1},
		{v1: "4.14.3", v2: "4.14.10", want: -1},
		// missing components are smaller
		{v1: "5", v2: "5.0.0", want: -1},
		{v1: "1.0", v2: "1.0.0", want: -1},
		// leading zeros are ignored in numeric parts
		{v1: "1.0", v2: "1.00", want: 0},
		{v1: "1.0", v2: "01.0", want: 0},
		// "~" sorts before anything, even the end of the version
		{v1: "1.0~beta", v2: "1.0", want: -1},
		{v1: "1.0~~", v2: "1.0~beta", want: -1},
		{v1: "2", v2: "2.0~alpha5", want: -1},
		{v1: "2.0~alpha5", v2: "2.0.0~beta", want: -1},
		{v1: "1.0.0~rc1", v2: "1.0.0", want: -1},
		{v1: "1.0~beta2", v2: "1.0~beta10", want: -1},
		// letters sort before other characters
		{v1: "1.0z", v2: "1.0+", want: -1},
		{v1: "1.0a", v2: "1.0_1", want: -1},
		{v1: "1", v2: "a", want: -1},
		{v1: "A", v2: "a", want: -1},
		// the parts before the last "-" are compared first
		{v1: "1.0-test", v2: "1.0+dev", want: -1},
		{v1: "1.0-rc1", v2: "1.0+", want: -1},
		{v1: "1.0-1", v2: "1.0-10", want: -1},
		{v1: "1.0~rc1-1", v2: "1.0", want: -1},
		{v1: "1.0-a-b", v2: "1.0-1", want: 1},
		{v1: "1.0", v2: "1.0-0", want: 0},
		{v1: "1.0", v2: "1.0-", want: 0},
		{v1: "-1", v2: "0.1", want: -1},
		// opam versions are not necessarily semver: dates (menhir), "v" prefixes (Jane Street)
		{v1: "20260209", v2: "20220210", want: 1},
		{v1: "20260209~rc1", v2: "20260209", want: -1},
		{v1: "20260209", v2: "20260209.1", want: -1},
		{v1: "20260209", v2: "dev", want: -1},
		{v1: "1.0.0", v2: "20260209", want: -1},
		{v1: "v0.16.0", v2: "v0.15.1", want: 1},
		{v1: "v0.16", v2: "v0.16.0", want: -1},
		{v1: "v0.16.0~preview.129.00+243", v2: "v0.16.0", want: -1},
		{v1: "0.17.0", v2: "v0.17.0", want: -1},
	}
	for _, tt := range tests {
		t.Run(tt.v1+" vs "+tt.v2, func(t *testing.T) {
			v1, err := newOpamVersion(tt.v1)
			require.NoError(t, err)
			v2, err := newOpamVersion(tt.v2)
			require.NoError(t, err)

			got, err := v1.Compare(New(tt.v2, OpamFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)

			got, err = v2.Compare(New(tt.v1, OpamFormat))
			require.NoError(t, err)
			assert.Equal(t, -tt.want, got, "reverse comparison")
		})
	}
}

func TestOpamVersionOrdering(t *testing.T) {
	// the example ordered sequence from https://opam.ocaml.org/doc/Manual.html#Version-ordering
	ordered := []string{"~~", "~", "~beta2", "~beta10", "0.1", "1.0~beta", "1.0", "1.0-test", "1.0.1", "1.0.10", "dev", "trunk"}
	for i := range ordered {
		for j := range ordered {
			want := opamCompareInts(i, j)
			assert.Equal(t, want, compareOpamVersions(ordered[i], ordered[j]), "%q vs %q", ordered[i], ordered[j])
		}
	}
}

func TestOpamVersionInvalid(t *testing.T) {
	for _, raw := range []string{"", "1.0 beta", "1.0/2", "1.0:1", "v1.0é"} {
		t.Run(raw, func(t *testing.T) {
			_, err := newOpamVersion(raw)
			require.Error(t, err)

			v, err := newOpamVersion("1.0")
			require.NoError(t, err)
			_, err = v.Compare(New(raw, OpamFormat))
			require.Error(t, err)
		})
	}
}

func TestOpamVersionCompareNil(t *testing.T) {
	v, err := newOpamVersion("1.0")
	require.NoError(t, err)
	_, err = v.Compare(nil)
	require.ErrorIs(t, err, ErrNoVersionProvided)
}

func TestOpamVersionConstraint(t *testing.T) {
	tests := []struct {
		constraint string
		version    string
		satisfied  bool
	}{
		// shapes produced from the OCaml security advisories
		{constraint: "< 4.14.3", version: "4.14.2", satisfied: true},
		{constraint: "< 4.14.3", version: "4.14.3", satisfied: false},
		{constraint: ">= 5.0.0, < 5.4.1", version: "5.4.0", satisfied: true},
		{constraint: ">= 5.0.0, < 5.4.1", version: "5.4.1~rc1", satisfied: true},
		{constraint: ">= 5.0.0, < 5.4.1", version: "5.0.0~alpha1", satisfied: false},
		{constraint: ">= 5.0.0, < 5.4.1", version: "5.4.1", satisfied: false},
		{constraint: ">= 4.04.0, < 4.04.2", version: "4.04.1", satisfied: true},
		{constraint: ">= 4.04.0, < 4.04.2", version: "4.04.2", satisfied: false},
		{constraint: ">= 1.0.1", version: "2.8.2", satisfied: true},
		{constraint: "<= 2.0.0", version: "2.0.0", satisfied: true},
		{constraint: "<= 2.0.0", version: "2.0.0+dev", satisfied: false},
		{constraint: "< 4.14.3 || >= 5.0.0, < 5.4.1", version: "5.3.0", satisfied: true},
		{constraint: "< 4.14.3 || >= 5.0.0, < 5.4.1", version: "4.14.3", satisfied: false},
		// non-semver versions
		{constraint: ">=20220210,<20260209", version: "20230415", satisfied: true},
		{constraint: ">=20220210,<20260209", version: "20260209~rc1", satisfied: true},
		{constraint: ">=20220210,<20260209", version: "20260209", satisfied: false},
		{constraint: ">=v0.15.0,<v0.16.0", version: "v0.15.1", satisfied: true},
		{constraint: ">=v0.15.0,<v0.16.0", version: "v0.16.0~preview.129.00+243", satisfied: true},
		{constraint: ">=v0.15.0,<v0.16.0", version: "v0.16.0", satisfied: false},
	}
	for _, tt := range tests {
		t.Run(tt.constraint+" with "+tt.version, func(t *testing.T) {
			c, err := GetConstraint(tt.constraint, OpamFormat)
			require.NoError(t, err)
			assert.Equal(t, OpamFormat, c.Format())

			got, err := c.Satisfied(New(tt.version, OpamFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, got)
		})
	}
}
