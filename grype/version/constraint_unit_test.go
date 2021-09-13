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

func TestTrimQuotes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		err      bool
	}{
		{
			name:     "no quotes",
			input:    "test",
			expected: "test",
			err:      true,
		},
		{
			name:     "double quotes",
			input:    "\"test\"",
			expected: "test",
			err:      false,
		},
		{
			name:     "single quotes",
			input:    "'test'",
			expected: "test",
			err:      false,
		},
		{
			name:     "leading_single_quote",
			input:    "'test",
			expected: "'test",
			err:      true,
		},
		{
			name:     "trailing_single_quote",
			input:    "test'",
			expected: "test'",
			err:      true,
		},
		{
			name:     "leading_double_quote",
			input:    "'test",
			expected: "'test",
			err:      true,
		},
		{
			name:     "trailing_double_quote",
			input:    "test'",
			expected: "test'",
			err:      true,
		},
		{
			// This raises an error, but I do not believe that this is a scenario that we need to account for, so should be ok.
			name:     "nested double/double quotes",
			input:    "\"t\"es\"t\"",
			expected: "\"t\"es\"t\"",
			err:      true,
		},
		{
			name:     "nested single/single quotes",
			input:    "'t'es't'",
			expected: "t'es't",
			err:      false,
		},
		{
			name:     "nested single/double quotes",
			input:    "'t\"es\"t'",
			expected: "t\"es\"t",
			err:      false,
		},
		{
			name:     "nested double/single quotes",
			input:    "\"t'es't\"",
			expected: "t'es't",
			err:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := trimQuotes(test.input)
			if err != nil && test.err == false {
				t.Errorf("expected no error, got \"%+v\"", err)
			} else if err == nil && test.err {
				t.Errorf("expected an error but did not get one")
			}
			if actual != test.expected {
				t.Errorf("unexpected constraint satisfaction: exp:%v got:%v", test.expected, actual)
			}
		})
	}
}
