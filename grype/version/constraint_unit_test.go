package version

import (
	"reflect"
	"testing"
)

func TestSplitFuzzyPhrase(t *testing.T) {
	tests := []struct {
		phrase   string
		expected *constraintUnit
		err      bool
	}{
		{
			phrase: "",
		},
		{
			phrase: `="in<(b e t w e e n)>quotes<=||>=not!="`,
			expected: &constraintUnit{
				rangeOperator: EQ,
				version:       "in<(b e t w e e n)>quotes<=||>=not!=",
			},
		},
		{
			phrase: ` >= "in<(b e t w e e n)>quotes<=||>=not!=" `,
			expected: &constraintUnit{
				rangeOperator: GTE,
				version:       "in<(b e t w e e n)>quotes<=||>=not!=",
			},
		},
		{
			// to cover a version that has quotes within it, but not necessarily surrounding the entire version
			phrase: ` >= inbet"ween)>quotes" with trailing words `,
			expected: &constraintUnit{
				rangeOperator: GTE,
				version:       `inbet"ween)>quotes" with trailing words`,
			},
		},
		{
			phrase: `="something"`,
			expected: &constraintUnit{
				rangeOperator: EQ,
				version:       "something",
			},
		},
		{
			phrase: "=something",
			expected: &constraintUnit{
				rangeOperator: EQ,
				version:       "something",
			},
		},
		{
			phrase: "= something",
			expected: &constraintUnit{
				rangeOperator: EQ,
				version:       "something",
			},
		},
		{
			phrase: "something",
			expected: &constraintUnit{

				rangeOperator: EQ,
				version:       "something",
			},
		},
		{
			phrase: "> something",
			expected: &constraintUnit{

				rangeOperator: GT,
				version:       "something",
			},
		},
		{
			phrase: ">= 2.3",
			expected: &constraintUnit{

				rangeOperator: GTE,
				version:       "2.3",
			},
		},
		{
			phrase: "< 2.3",
			expected: &constraintUnit{

				rangeOperator: LT,
				version:       "2.3",
			},
		},
		{
			phrase: "<=2.3",
			expected: &constraintUnit{

				rangeOperator: LTE,
				version:       "2.3",
			},
		},
		{
			phrase: "  >=   1.0 ",
			expected: &constraintUnit{

				rangeOperator: GTE,
				version:       "1.0",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.phrase, func(t *testing.T) {
			actual, err := parseUnit(test.phrase)
			if err != nil && test.err == false {
				t.Fatalf("expected no error, got %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected an error but did not get one")
			}

			if !reflect.DeepEqual(test.expected, actual) {
				t.Errorf("expected: '%+v' got: '%+v'", test.expected, actual)
			}

		})
	}
}
