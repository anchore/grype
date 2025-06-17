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

//func TestNewConstraintExpression(t *testing.T) {
//	tests := []struct {
//		name     string
//		phrase   string
//		genFn    comparatorGenerator
//		expected constraintExpression
//		wantErr  error
//	}{
//		{
//			name:   "single valid constraint",
//			phrase: "<1.1.1",
//			genFn:  newGolangComparator,
//			expected: constraintExpression{
//				units: [][]constraintUnit{
//					{constraintUnit{
//						rangeOperator: LT,
//						rawVersion:    "1.1.1",
//					}},
//				},
//				comparators: [][]Comparator{
//					{mustGolangComparator(t, constraintUnit{
//						rangeOperator: LT,
//						rawVersion:    "1.1.1",
//					})},
//				},
//			},
//			wantErr: nil,
//		},
//		{
//			name:   "fall back to fuzzy on invalid semver",
//			phrase: ">9.6.0b1",
//			genFn:  newGolangComparator,
//			expected: constraintExpression{
//				units: [][]constraintUnit{
//					{constraintUnit{
//						rangeOperator: GT,
//						rawVersion:    "9.6.0b1",
//					}},
//				},
//				comparators: [][]Comparator{
//					{mustFuzzyComparator(t, constraintUnit{
//						rangeOperator: GT,
//						rawVersion:    "9.6.0b1",
//					})},
//				},
//			},
//			wantErr: ErrFallbackToFuzzy,
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			actual, err := newConstraintExpression(test.phrase, test.genFn)
//			if test.wantErr != nil {
//				require.ErrorIs(t, err, test.wantErr)
//			} else {
//				require.NoError(t, err)
//			}
//
//			opts := []cmp.Option{
//				cmp.AllowUnexported(constraintExpression{},
//					constraintUnit{}, golangVersion{}, fuzzyVersion{}, semanticVersion{}),
//			}
//			if diff := cmp.Diff(test.expected, actual, opts...); diff != "" {
//				t.Errorf("actual does not match expected, diff: %s", diff)
//			}
//		})
//	}
//}

//func mustGolangComparator(t *testing.T, unit constraintUnit) Comparator {
//	t.Helper()
//	c, err := newGolangComparator(unit)
//	if err != nil {
//		t.Fatal(err)
//	}
//	return c
//}
//
//func mustFuzzyComparator(t *testing.T, unit constraintUnit) Comparator {
//	t.Helper()
//	c, err := newFuzzyComparator(unit)
//	if err != nil {
//		t.Fatal(err)
//	}
//	return c
//}
