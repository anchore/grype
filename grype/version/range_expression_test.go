package version

import (
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/require"
)

func TestScanExpression(t *testing.T) {
	tests := []struct {
		name     string
		phrase   string
		expected [][]string
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:   "simple AND and OR expression",
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
			name:   "complex version constraints with operators",
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
			name:    "parenthetical expression not supported",
			phrase:  "(<1.0, >=2.0|| 3.0) || =4.0",
			wantErr: require.Error,
		},
		{
			name:   "whitespace handling",
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
			name:   "quoted version with special characters",
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
		{
			name:     "empty string",
			phrase:   "",
			expected: nil,
		},
		{
			name:   "single version",
			phrase: "1.0",
			expected: [][]string{
				{
					"1.0",
				},
			},
		},
		{
			name:   "only AND operators",
			phrase: ">=1.0, <2.0, !=1.5",
			expected: [][]string{
				{
					">=1.0",
					"<2.0",
					"!=1.5",
				},
			},
		},
		{
			name:   "only OR operators",
			phrase: "1.0 || 2.0 || 3.0",
			expected: [][]string{
				{
					"1.0",
				},
				{
					"2.0",
				},
				{
					"3.0",
				},
			},
		},
		{
			name:   "single pipe character should be treated as version",
			phrase: "1.0|2.0",
			expected: [][]string{
				{
					"1.02.0",
				},
			},
		},
		{
			name:   "multiple consecutive commas",
			phrase: "1.0,,,2.0",
			expected: [][]string{
				{
					"1.0",
					"2.0",
				},
			},
		},
		{
			name:   "trailing comma",
			phrase: "1.0,2.0,",
			expected: [][]string{
				{
					"1.0",
					"2.0",
				},
			},
		},
		{
			name:   "leading comma",
			phrase: ",1.0,2.0",
			expected: [][]string{
				{
					"1.0",
					"2.0",
				},
			},
		},
		{
			name:   "complex version numbers",
			phrase: "1.0.0-alpha+build.1,2.0.0-beta.2||3.0.0-rc.1",
			expected: [][]string{
				{
					"1.0.0-alpha+build.1",
					"2.0.0-beta.2",
				},
				{
					"3.0.0-rc.1",
				},
			},
		},
		{
			name:    "parentheses at start",
			phrase:  "(1.0",
			wantErr: require.Error,
		},
		{
			name:    "parentheses at end",
			phrase:  "1.0)",
			wantErr: require.Error,
		},
		{
			name:   "special characters in version",
			phrase: "1.0.0+build.123-abc_def",
			expected: [][]string{
				{
					"1.0.0+build.123-abc_def",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			actual, err := scanExpression(tt.phrase)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			for _, d := range deep.Equal(tt.expected, actual) {
				t.Errorf("difference: %+v", d)
			}
		})
	}
}
