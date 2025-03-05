package schemaver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSchemaVerComparisons(t *testing.T) {
	tests := []struct {
		name           string
		v1             SchemaVer
		v2             SchemaVer
		lessThan       bool
		greaterOrEqual bool
	}{
		{
			name:           "equal versions",
			v1:             New(1, 0, 0),
			v2:             New(1, 0, 0),
			lessThan:       false,
			greaterOrEqual: true,
		},
		{
			name:           "different model versions",
			v1:             New(1, 0, 0),
			v2:             New(2, 0, 0),
			lessThan:       true,
			greaterOrEqual: false,
		},
		{
			name:           "different revision versions",
			v1:             New(1, 1, 0),
			v2:             New(1, 2, 0),
			lessThan:       true,
			greaterOrEqual: false,
		},
		{
			name:           "different addition versions",
			v1:             New(1, 0, 1),
			v2:             New(1, 0, 2),
			lessThan:       true,
			greaterOrEqual: false,
		},
		{
			name:           "inverted addition versions",
			v1:             New(1, 0, 2),
			v2:             New(1, 0, 1),
			lessThan:       false,
			greaterOrEqual: true,
		},
		{
			name:           "greater model overrides lower revision",
			v1:             New(2, 0, 0),
			v2:             New(1, 9, 9),
			lessThan:       false,
			greaterOrEqual: true,
		},
		{
			name:           "greater revision overrides lower addition",
			v1:             New(1, 2, 0),
			v2:             New(1, 1, 9),
			lessThan:       false,
			greaterOrEqual: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v1.LessThan(tt.v2); got != tt.lessThan {
				t.Errorf("LessThan() = %v, want %v", got, tt.lessThan)
			}
			if got := tt.v1.GreaterOrEqualTo(tt.v2); got != tt.greaterOrEqual {
				t.Errorf("GreaterOrEqualTo() = %v, want %v", got, tt.greaterOrEqual)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    SchemaVer
		wantErr bool
	}{
		{
			name:    "valid version",
			input:   "1.2.3",
			want:    New(1, 2, 3),
			wantErr: false,
		},
		{
			name:    "valid large numbers",
			input:   "999.888.777",
			want:    New(999, 888, 777),
			wantErr: false,
		},
		{
			name:    "valid with whitespace",
			input:   "  1.2.3  ",
			want:    New(1, 2, 3),
			wantErr: false,
		},
		{
			name:    "invalid version with zeros",
			input:   "0.0.0",
			want:    New(0, 0, 0),
			wantErr: true,
		},
		{
			name:    "invalid empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid too few parts",
			input:   "1.2",
			wantErr: true,
		},
		{
			name:    "invalid too many parts",
			input:   "1.2.3.4",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric model",
			input:   "a.2.3",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric revision",
			input:   "1.b.3",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric addition",
			input:   "1.2.c",
			wantErr: true,
		},
		{
			name:    "invalid negative number",
			input:   "-1.2.3",
			wantErr: true,
		},
		{
			name:    "invalid format with spaces",
			input:   "1 . 2 . 3",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && (got.Model != tt.want.Model ||
				got.Revision != tt.want.Revision ||
				got.Addition != tt.want.Addition) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSchemaVer_Valid(t *testing.T) {
	tests := []struct {
		name     string
		schema   SchemaVer
		expected bool
	}{
		{
			name: "valid schema version - all positive",
			schema: SchemaVer{
				Model:    1,
				Revision: 1,
				Addition: 1,
			},
			expected: true,
		},
		{
			name: "valid schema version - zero revision and addition",
			schema: SchemaVer{
				Model:    1,
				Revision: 0,
				Addition: 0,
			},
			expected: true,
		},
		{
			name: "invalid - zero model",
			schema: SchemaVer{
				Model:    0,
				Revision: 1,
				Addition: 1,
			},
			expected: false,
		},
		{
			name: "invalid - negative model",
			schema: SchemaVer{
				Model:    -1,
				Revision: 1,
				Addition: 1,
			},
			expected: false,
		},
		{
			name: "invalid - negative revision",
			schema: SchemaVer{
				Model:    1,
				Revision: -1,
				Addition: 1,
			},
			expected: false,
		},
		{
			name: "invalid - negative addition",
			schema: SchemaVer{
				Model:    1,
				Revision: 1,
				Addition: -1,
			},
			expected: false,
		},
		{
			name: "invalid - all negative",
			schema: SchemaVer{
				Model:    -1,
				Revision: -1,
				Addition: -1,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.schema.Valid())
		})
	}
}
