package schemaver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemaVer_VersionComponents(t *testing.T) {
	tests := []struct {
		name             string
		version          String
		expectedModel    int
		expectedRevision int
		expectedAddition int
	}{
		{
			name:             "go case",
			version:          "1.2.3",
			expectedModel:    1,
			expectedRevision: 2,
			expectedAddition: 3,
		},
		{
			name:             "model only",
			version:          "1.0.0",
			expectedModel:    1,
			expectedRevision: 0,
			expectedAddition: 0,
		},
		{
			name:             "invalid model",
			version:          "0.2.3",
			expectedModel:    -1,
			expectedRevision: 2,
			expectedAddition: 3,
		},
		{
			name:             "invalid version format",
			version:          "invalid.version",
			expectedModel:    -1,
			expectedRevision: -1,
			expectedAddition: -1,
		},
		{
			name:             "zero version",
			version:          "0.0.0",
			expectedModel:    -1,
			expectedRevision: 0,
			expectedAddition: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			type subject struct {
				name string
				exp  int
				fn   func() (int, bool)
			}

			for _, sub := range []subject{
				{
					name: "model",
					exp:  tt.expectedModel,
					fn:   tt.version.ModelPart,
				},
				{
					name: "revision",
					exp:  tt.expectedRevision,
					fn:   tt.version.RevisionPart,
				},
				{
					name: "addition",
					exp:  tt.expectedAddition,
					fn:   tt.version.AdditionPart,
				},
			} {
				t.Run(sub.name, func(t *testing.T) {
					act, ok := sub.fn()

					if sub.exp == -1 {
						require.False(t, ok, fmt.Sprintf("Expected %s to be invalid", sub.name))
						return
					}
					require.True(t, ok, fmt.Sprintf("Expected %s to be valid", sub.name))
					assert.Equal(t, sub.exp, act, fmt.Sprintf("Expected %s to be %d, got %d", sub.name, sub.exp, act))
				})
			}

		})
	}
}

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
