package presenter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	cases := []struct {
		input    string
		expected format
	}{
		{
			"",
			format{id: "table"},
		},
		{
			"table",
			format{id: "table"},
		},
		{
			"jSOn",
			format{id: "json"},
		},
		{
			"booboodepoopoo",
			format{id: "unknown"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			actual := parse(tc.input)
			assert.Equal(t, tc.expected, actual, "unexpected result for input %q", tc.input)
		})
	}
}
