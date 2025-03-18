package version

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRangeUnit(t *testing.T) {
	tests := []struct {
		phrase    string
		expected  *Range
		wantError require.ErrorAssertionFunc
	}{
		{
			phrase: "",
		},
		{
			phrase: `="in<(b e t w e e n)>quotes<=||>=not!="`,
			expected: &Range{
				operator: EQ,
				version:  "in<(b e t w e e n)>quotes<=||>=not!=",
			},
		},
		{
			phrase: ` >= "in<(b e t w e e n)>quotes<=||>=not!=" `,
			expected: &Range{
				operator: GTE,
				version:  "in<(b e t w e e n)>quotes<=||>=not!=",
			},
		},
		{
			// to cover a version that has quotes within it, but not necessarily surrounding the entire version
			phrase: ` >= inbet"ween)>quotes" with trailing words `,
			expected: &Range{
				operator: GTE,
				version:  `inbet"ween)>quotes" with trailing words`,
			},
		},
		{
			phrase:    `="unbalandedquotes`,
			wantError: require.Error,
		},
		{
			phrase: `="something"`,
			expected: &Range{
				operator: EQ,
				version:  "something",
			},
		},
		{
			phrase: "=something",
			expected: &Range{
				operator: EQ,
				version:  "something",
			},
		},
		{
			phrase: "= something",
			expected: &Range{
				operator: EQ,
				version:  "something",
			},
		},
		{
			phrase: "something",
			expected: &Range{

				operator: EQ,
				version:  "something",
			},
		},
		{
			phrase: "> something",
			expected: &Range{

				operator: GT,
				version:  "something",
			},
		},
		{
			phrase: ">= 2.3",
			expected: &Range{

				operator: GTE,
				version:  "2.3",
			},
		},
		{
			phrase: "< 2.3",
			expected: &Range{

				operator: LT,
				version:  "2.3",
			},
		},
		{
			phrase: "<=2.3",
			expected: &Range{

				operator: LTE,
				version:  "2.3",
			},
		},
		{
			phrase: "  >=   1.0 ",
			expected: &Range{

				operator: GTE,
				version:  "1.0",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.phrase, func(t *testing.T) {
			if test.wantError == nil {
				test.wantError = require.NoError
			}
			actual, err := parseRange(test.phrase)
			test.wantError(t, err)
			if err != nil {
				return
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
			// this raises an error, but I do not believe that this is a scenario that we need to account for, so should be ok.
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
			if test.err {
				assert.NotNil(t, err, "expected an error but did not get one")
			} else {
				assert.Nil(t, err, "expected no error, got \"%+v\"", err)
			}
			assert.Equal(t, actual, test.expected, "output does not match expected: exp:%v got:%v", test.expected, actual)
		})
	}
}
