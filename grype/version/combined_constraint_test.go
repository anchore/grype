package version

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCombineConstraints(t *testing.T) {
	tests := []struct {
		name        string
		constraints []Constraint
		want        Constraint
	}{
		{
			name:        "no constraints returns nil",
			constraints: []Constraint{},
			want:        nil,
		},
		{
			name: "single constraint returns same constraint",
			constraints: []Constraint{
				MustGetConstraint(">= 1.0.0", SemanticFormat),
			},
			want: MustGetConstraint(">= 1.0.0", SemanticFormat),
		},
		{
			name: "multiple constraints returns combined constraint",
			constraints: []Constraint{
				MustGetConstraint(">= 1.0.0", SemanticFormat),
				MustGetConstraint("< 2.0.0", SemanticFormat),
			},
			want: combinedConstraint{
				OrOperands: []Constraint{
					MustGetConstraint(">= 1.0.0", SemanticFormat),
					MustGetConstraint("< 2.0.0", SemanticFormat),
				},
			},
		},
		{
			name: "nil constraints are filtered out",
			constraints: []Constraint{
				nil,
				MustGetConstraint(">= 1.0.0", SemanticFormat),
				nil,
			},
			want: MustGetConstraint(">= 1.0.0", SemanticFormat),
		},
		{
			name: "duplicate constraints are filtered out",
			constraints: []Constraint{
				MustGetConstraint(">= 1.0.0", SemanticFormat),
				MustGetConstraint(">= 1.0.0", SemanticFormat),
				MustGetConstraint("< 2.0.0", SemanticFormat),
			},
			want: combinedConstraint{
				OrOperands: []Constraint{
					MustGetConstraint(">= 1.0.0", SemanticFormat),
					MustGetConstraint("< 2.0.0", SemanticFormat),
				},
			},
		},
		{
			name: "all nil constraints returns nil",
			constraints: []Constraint{
				nil,
				nil,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CombineConstraints(tt.constraints...)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCombinedConstraint_Methods(t *testing.T) {
	tests := []struct {
		name          string
		constraint    combinedConstraint
		version       *Version
		wantValue     string
		wantString    string
		wantFormat    Format
		wantSatisfied bool
		wantErr       require.ErrorAssertionFunc
	}{
		{
			name: "single operand semantic constraint satisfied",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					MustGetConstraint(">= 1.0.0", SemanticFormat),
				},
			},
			version:       New("1.5.0", SemanticFormat),
			wantValue:     ">= 1.0.0",
			wantString:    ">= 1.0.0 (semantic)",
			wantFormat:    SemanticFormat,
			wantSatisfied: true,
		},
		{
			name: "single operand semantic constraint not satisfied",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					MustGetConstraint(">= 2.0.0", SemanticFormat),
				},
			},
			version:       New("1.5.0", SemanticFormat),
			wantValue:     ">= 2.0.0",
			wantString:    ">= 2.0.0 (semantic)",
			wantFormat:    SemanticFormat,
			wantSatisfied: false,
		},
		{
			name: "multiple operands with OR logic - first satisfies",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					MustGetConstraint(">= 1.0.0", SemanticFormat),
					MustGetConstraint(">= 3.0.0", SemanticFormat),
				},
			},
			version:       New("1.5.0", SemanticFormat),
			wantValue:     ">= 1.0.0 || >= 3.0.0",
			wantString:    ">= 1.0.0 || >= 3.0.0 (semantic)",
			wantFormat:    SemanticFormat,
			wantSatisfied: true,
		},
		{
			name: "multiple operands with OR logic - second satisfies",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					MustGetConstraint(">= 2.0.0", SemanticFormat),
					MustGetConstraint("< 2.0.0", SemanticFormat),
				},
			},
			version:       New("1.5.0", SemanticFormat),
			wantValue:     ">= 2.0.0 || < 2.0.0",
			wantString:    ">= 2.0.0 || < 2.0.0 (semantic)",
			wantFormat:    SemanticFormat,
			wantSatisfied: true,
		},
		{
			name: "multiple operands with OR logic - none satisfy",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					MustGetConstraint(">= 2.0.0", SemanticFormat),
					MustGetConstraint(">= 3.0.0", SemanticFormat),
				},
			},
			version:       New("1.5.0", SemanticFormat),
			wantValue:     ">= 2.0.0 || >= 3.0.0",
			wantString:    ">= 2.0.0 || >= 3.0.0 (semantic)",
			wantFormat:    SemanticFormat,
			wantSatisfied: false,
		},
		{
			name: "empty operands returns unknown format",
			constraint: combinedConstraint{
				OrOperands: []Constraint{},
			},
			version:       New("1.5.0", SemanticFormat),
			wantValue:     "",
			wantString:    " (unknown)",
			wantFormat:    UnknownFormat,
			wantSatisfied: false,
		},
		{
			name: "rpm format constraint",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					MustGetConstraint(">= 1.0.0", RpmFormat),
					MustGetConstraint("< 0.5.0", RpmFormat),
				},
			},
			version:       New("1.5.0", RpmFormat),
			wantValue:     ">= 1.0.0 || < 0.5.0",
			wantString:    ">= 1.0.0 || < 0.5.0 (rpm)",
			wantFormat:    RpmFormat,
			wantSatisfied: true,
		},
		{
			name: "nil version returns error",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					MustGetConstraint(">= 1.0.0", SemanticFormat),
				},
			},
			version:       nil,
			wantValue:     ">= 1.0.0",
			wantString:    ">= 1.0.0 (semantic)",
			wantFormat:    SemanticFormat,
			wantSatisfied: false,
			wantErr:       require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			// test Value() method
			gotValue := tt.constraint.Value()
			require.Equal(t, tt.wantValue, gotValue)

			// test String() method
			gotString := tt.constraint.String()
			require.Equal(t, tt.wantString, gotString)

			// test Format() method
			gotFormat := tt.constraint.Format()
			require.Equal(t, tt.wantFormat, gotFormat)

			// test Satisfied() method
			gotSatisfied, err := tt.constraint.Satisfied(tt.version)
			tt.wantErr(t, err)

			if err != nil {
				return
			}
			require.Equal(t, tt.wantSatisfied, gotSatisfied)
		})
	}
}

func TestCombinedConstraint_Satisfied_WithErrors(t *testing.T) {
	tests := []struct {
		name       string
		constraint combinedConstraint
		version    *Version
		wantErr    require.ErrorAssertionFunc
	}{
		{
			name: "error from first constraint",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					mockConstraint{value: ">= 1.0.0", format: SemanticFormat, returnErr: true},
					mockConstraint{value: "< 2.0.0", format: SemanticFormat, satisfied: true},
				},
			},
			version: New("1.5.0", SemanticFormat),
			wantErr: require.Error,
		},
		{
			name: "error from second constraint when first doesn't satisfy",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					mockConstraint{value: ">= 1.0.0", format: SemanticFormat, satisfied: false},
					mockConstraint{value: "< 2.0.0", format: SemanticFormat, returnErr: true},
				},
			},
			version: New("1.5.0", SemanticFormat),
			wantErr: require.Error,
		},
		{
			name: "no error when first constraint satisfies",
			constraint: combinedConstraint{
				OrOperands: []Constraint{
					mockConstraint{value: ">= 1.0.0", format: SemanticFormat, satisfied: true},
					mockConstraint{value: "< 2.0.0", format: SemanticFormat, returnErr: true},
				},
			},
			version: New("1.5.0", SemanticFormat),
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.constraint.Satisfied(tt.version)
			tt.wantErr(t, err)
		})
	}
}

type mockConstraint struct {
	value     string
	format    Format
	satisfied bool
	returnErr bool
}

func (m mockConstraint) String() string {
	return m.value + " (" + strings.ToLower(m.format.String()) + ")"
}

func (m mockConstraint) Value() string {
	return m.value
}

func (m mockConstraint) Format() Format {
	return m.format
}

func (m mockConstraint) Satisfied(*Version) (bool, error) {
	if m.returnErr {
		return false, errors.New("mock constraint error")
	}
	return m.satisfied, nil
}
