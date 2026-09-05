package format

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	cases := []struct {
		input    string
		expected Format
	}{
		{
			"",
			TableFormat,
		},
		{
			"table",
			TableFormat,
		},
		{
			"jSOn",
			JSONFormat,
		},
		{
			"jsonl",
			JSONLinesFormat,
		},
		{
			"JSONL",
			JSONLinesFormat,
		},
		{
			// ndjson is a common alias for JSON lines and is accepted as an alternate spelling.
			"ndjson",
			JSONLinesFormat,
		},
		{
			"booboodepoopoo",
			UnknownFormat,
		},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			actual := Parse(tc.input)
			assert.Equal(t, tc.expected, actual, "unexpected result for input %q", tc.input)
		})
	}
}
