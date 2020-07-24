package version

import (
	"reflect"
	"testing"
)

func TestSplitFuzzyPhrase(t *testing.T) {
	tests := []struct {
		phrase   string
		expected []constraintPart
		err      bool
	}{
		{
			phrase:   "",
			expected: []constraintPart{},
		},
		{
			phrase: "= something",
			expected: []constraintPart{
				{
					operator: EQ,
					version:  "something",
				},
			},
		},
		{
			phrase: "something",
			expected: []constraintPart{
				{
					operator: EQ,
					version:  "something",
				},
			},
		},
		{
			phrase: "> something",
			expected: []constraintPart{
				{
					operator: GT,
					version:  "something",
				},
			},
		},
		{
			phrase: ">= 2.3",
			expected: []constraintPart{
				{
					operator: GTE,
					version:  "2.3",
				},
			},
		},
		{
			phrase: "< 2.3",
			expected: []constraintPart{
				{
					operator: LT,
					version:  "2.3",
				},
			},
		},
		{
			phrase: "<= 2.3",
			expected: []constraintPart{
				{
					operator: LTE,
					version:  "2.3",
				},
			},
		},
		{
			phrase: ">= 1.0, <= 2.3",
			expected: []constraintPart{
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
			expected: []constraintPart{
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
			phrase: ">1.0,<2.3",
			expected: []constraintPart{
				{
					operator: GT,
					version:  "1.0",
				},
				{
					operator: LT,
					version:  "2.3",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.phrase, func(t *testing.T) {
			actuals, err := splitConstraintPhrase(test.phrase)
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
