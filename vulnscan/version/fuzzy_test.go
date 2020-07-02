package version

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSplitFuzzyPhrase(t *testing.T) {
	tests := []struct {
		phrase   string
		expected []fuzzyConstraintPart
		err      bool
	}{
		{
			phrase:   "",
			expected: []fuzzyConstraintPart{},
		},
		{
			phrase: "= something",
			expected: []fuzzyConstraintPart{
				{
					operator: EQ,
					version:  "something",
				},
			},
		},
		{
			phrase: "something",
			expected: []fuzzyConstraintPart{
				{
					operator: EQ,
					version:  "something",
				},
			},
		},
		{
			phrase: "> something",
			expected: []fuzzyConstraintPart{
				{
					operator: GT,
					version:  "something",
				},
			},
		},
		{
			phrase: ">= 2.3",
			expected: []fuzzyConstraintPart{
				{
					operator: GTE,
					version:  "2.3",
				},
			},
		},
		{
			phrase: "< 2.3",
			expected: []fuzzyConstraintPart{
				{
					operator: LT,
					version:  "2.3",
				},
			},
		},
		{
			phrase: "<= 2.3",
			expected: []fuzzyConstraintPart{
				{
					operator: LTE,
					version:  "2.3",
				},
			},
		},
		{
			phrase: ">= 1.0, <= 2.3",
			expected: []fuzzyConstraintPart{
				{
					operator: GTE,
					version:  "1.0",
				},
				{
					operator: LTE,
					version:  "2.3",
				},
			},
		},
		{
			phrase: "  >=   1.0 ,   <=   2.3  ",
			expected: []fuzzyConstraintPart{
				{
					operator: GTE,
					version:  "1.0",
				},
				{
					operator: LTE,
					version:  "2.3",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.phrase, func(t *testing.T) {
			actuals, err := splitFuzzyPhrase(test.phrase)
			if err != nil && test.err == false {
				t.Fatalf("expected no error, got %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected an error but did not get one")
			}

			if len(actuals) != len(test.expected) {
				t.Fatalf("unexpected length: %d!=%d", len(actuals), len(test.expected))
			}

			for idx, actual := range actuals {
				if !reflect.DeepEqual(test.expected[idx], actual) {
					t.Errorf("expected: '%+v' got: '%+v'", test.expected[idx], actual)
				}
			}
		})
	}
}

func TestSmartVerCmp(t *testing.T) {
	cases := []struct {
		v1, v2 string
		ret    int
	}{
		{"5", "8", -1},
		{"15", "3", 1},
		{"4a", "4c", -1},
		{"1.0", "1.0", 0},
		{"1.0.1", "1.0", 1},
		{"1.0.14", "1.0.4", 1},
		{"95SE", "98SP1", -1},
		{"98SE", "98SP1", -1},
		{"98SP1", "98SP3", -1},
		{"16.0.0", "3.2.7", 1},
		{"10.23", "10.21", 1},
		{"64.0", "3.6.24", 1},
		{"5-1.15", "5-1.16", -1},
		{"5-1.15.2", "5-1.16", -1},
		{"5-appl_1.16.1", "5-1.0.1", -1}, // this is wrong, but seems to be impossible to account for
		{"5-1.16", "5_1.0.6", 1},
		{"5-6", "5-16", -1},
		{"5a1", "5a2", -1},
		{"5a1", "6a1", -1},
		{"5-a1", "5a1", -1}, // meh, kind of makes sense
		{"5-a1", "5.a1", 0},
		{"1.4", "1.02", 1},
		{"5.0", "08.0", -1},
		{"10.0", "1.0", 1},
		{"10.0", "1.000", 1},
		{"10.0", "1.000.0.1", 1},
		{"1.0.4", "1.0.4+metadata", -1}, // this is also somewhat wrong, however, there is a semver parser that can handle this case (which should be leveraged when possible)
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q vs %q", c.v1, c.v2), func(t *testing.T) {
			if ret := fuzzyVersionComparison(c.v1, c.v2); ret != c.ret {
				t.Fatalf("expected %d, got %d", c.ret, ret)
			}
		})
	}
}

func TestFuzzyConstraintSatisfaction(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		version    string
		expected   bool
	}{
		{
			name:       "version range within",
			constraint: ">1.0, <2.0",
			version:    "1.2+beta-3",
			expected:   true,
		},
		{
			name:       "version range within (prerelease)",
			constraint: ">1.0, <2.0",
			version:    "1.2.0-beta-prerelease",
			expected:   true,
		},
		{
			name:       "version range within (prerelease)",
			constraint: ">=1.0, <2.0",
			version:    "1.0.0-beta-prerelease",
			expected:   false,
		},
		{
			name:       "version range outside (right)",
			constraint: ">1.0, <2.0",
			version:    "2.1-beta-3",
			expected:   false,
		},
		{
			name:       "version range outside (left)",
			constraint: ">1.0, <2.0",
			version:    "0.9-beta-2",
			expected:   false,
		},
		{
			name:       "version range within (excluding left, prerelease)",
			constraint: ">=1.0, <2.0",
			version:    "1.0-beta-3",
			expected:   false,
		},
		{
			name:       "version range within (including left)",
			constraint: ">=1.1, <2.0",
			version:    "1.1",
			expected:   true,
		},
		{
			name:       "version range within (excluding right, 1)",
			constraint: ">1.0, <=2.0",
			version:    "2.0-beta-3",
			expected:   true,
		},
		{
			name:       "version range within (excluding right, 2)",
			constraint: ">1.0, <2.0",
			version:    "2.0-beta-3",
			expected:   true,
		},
		{
			name:       "version range within (including right)",
			constraint: ">1.0, <=2.0",
			version:    "2.0",
			expected:   true,
		},
		{
			name:       "version range within (including right, longer version [valid semver, bad fuzzy])",
			constraint: ">1.0, <=2.0",
			version:    "2.0.0",
			expected:   true,
		},
		{
			name:       "version range not within range (prefix)",
			constraint: ">1.0, <2.0",
			version:    "5-1.2+beta-3",
			expected:   false,
		},
		{
			name:       "odd major prefix wide constraint range",
			constraint: ">4, <6",
			version:    "5-1.2+beta-3",
			expected:   true,
		},
		{
			name:       "odd major prefix narrow constraint",
			constraint: ">5-1.15",
			version:    "5-1.16",
			expected:   true,
		},
		{
			name:       "odd major prefix narrow constraint range",
			constraint: ">5-1.15, <=5-1.16",
			version:    "5-1.16",
			expected:   true,
		},
		{
			name:       "odd major prefix narrow constraint range (excluding)",
			constraint: ">4, <5-1.16",
			version:    "5-1.16",
			expected:   false,
		},
		{
			name:       "bad semver (gt)",
			constraint: ">5a1",
			version:    "5a2",
			expected:   true,
		},
		{
			name:       "bad semver (lt)",
			constraint: "<6a1",
			version:    "5a2",
			expected:   true,
		},
		{
			name:       "bad semver (lte)",
			constraint: "<=5a2",
			version:    "5a2",
			expected:   true,
		},
		{
			name:       "bad semver (lt boundary)",
			constraint: "<5a2",
			version:    "5a2",
			expected:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := newFuzzyConstraint(test.constraint)
			if err != nil {
				t.Fatalf("could not create constraint: %+v", err)
			}

			verObj := Version{
				Raw: test.version,
			}

			actual, err := c.Satisfied(&verObj)
			if err != nil {
				t.Fatalf("could not check constraint satisfaction: %+v", err)
			}

			if actual != test.expected {
				t.Errorf("unexpected constraint satisfaction: exp:%v got:%v", test.expected, actual)
			}

		})
	}
}
