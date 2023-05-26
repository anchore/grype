package version

import (
	"testing"

	"github.com/go-test/deep"
)

func TestScanExpression(t *testing.T) {
	tests := []struct {
		phrase   string
		expected [][]string
		err      bool
	}{
		{
			phrase: "x,y||z",
			expected: [][]string{
				{
					"x",
					"y",
				},
				{
					"z",
				},
			},
		},
		{
			phrase: "<1.0, >=2.0|| 3.0 || =4.0",
			expected: [][]string{
				{
					"<1.0",
					">=2.0",
				},
				{
					"3.0",
				},
				{
					"=4.0",
				},
			},
		},
		{
			// parenthetical expression are not supported yet
			phrase: "(<1.0, >=2.0|| 3.0) || =4.0",
			err:    true,
		},
		{
			phrase: ` > 1.0,  <=   2.0,,,    || = 3.0 `,
			expected: [][]string{
				{
					">1.0",
					"<=2.0",
				},
				{
					"=3.0",
				},
			},
		},
		{
			phrase: ` > 1.0,  <= "  (2.0||),,, ",   || = 3.0 `,
			expected: [][]string{
				{
					">1.0",
					`<="  (2.0||),,, "`,
				},
				{
					"=3.0",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.phrase, func(t *testing.T) {
			actual, err := scanExpression(test.phrase)
			if err != nil && test.err == false {
				t.Fatalf("expected no error, got %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected an error but did not get one")
			}

			for _, d := range deep.Equal(test.expected, actual) {
				t.Errorf("difference: %+v", d)
			}

		})
	}
}
