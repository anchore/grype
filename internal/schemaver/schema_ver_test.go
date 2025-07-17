package schemaver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemaVer_LessThan(t *testing.T) {
	tests := []struct {
		name string
		v1   SchemaVer
		v2   SchemaVer
		want bool
	}{
		{
			name: "equal versions",
			v1:   New(1, 0, 0),
			v2:   New(1, 0, 0),
			want: false,
		},
		{
			name: "different model versions",
			v1:   New(1, 0, 0),
			v2:   New(2, 0, 0),
			want: true,
		},
		{
			name: "different revision versions",
			v1:   New(1, 1, 0),
			v2:   New(1, 2, 0),
			want: true,
		},
		{
			name: "different addition versions",
			v1:   New(1, 0, 1),
			v2:   New(1, 0, 2),
			want: true,
		},
		{
			name: "inverted addition versions",
			v1:   New(1, 0, 2),
			v2:   New(1, 0, 1),
			want: false,
		},
		{
			name: "greater model overrides lower revision",
			v1:   New(2, 0, 0),
			v2:   New(1, 9, 9),
			want: false,
		},
		{
			name: "greater revision overrides lower addition",
			v1:   New(1, 2, 0),
			v2:   New(1, 1, 9),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.v1.LessThan(tt.v2))
		})
	}
}

func TestSchemaVer_GreaterOrEqualTo(t *testing.T) {
	tests := []struct {
		name string
		v1   SchemaVer
		v2   SchemaVer
		want bool
	}{
		{
			name: "equal versions",
			v1:   New(1, 0, 0),
			v2:   New(1, 0, 0),
			want: true,
		},
		{
			name: "different model versions",
			v1:   New(1, 0, 0),
			v2:   New(2, 0, 0),
			want: false,
		},
		{
			name: "different revision versions",
			v1:   New(1, 1, 0),
			v2:   New(1, 2, 0),
			want: false,
		},
		{
			name: "different addition versions",
			v1:   New(1, 0, 1),
			v2:   New(1, 0, 2),
			want: false,
		},
		{
			name: "inverted addition versions",
			v1:   New(1, 0, 2),
			v2:   New(1, 0, 1),
			want: true,
		},
		{
			name: "greater model overrides lower revision",
			v1:   New(2, 0, 0),
			v2:   New(1, 9, 9),
			want: true,
		},
		{
			name: "greater revision overrides lower addition",
			v1:   New(1, 2, 0),
			v2:   New(1, 1, 9),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.v1.GreaterOrEqualTo(tt.v2))
		})
	}
}

func TestSchemaVer_LessThanOrEqualTo(t *testing.T) {
	tests := []struct {
		name string
		v1   SchemaVer
		v2   SchemaVer
		want bool
	}{
		{
			name: "equal versions",
			v1:   New(1, 2, 3),
			v2:   New(1, 2, 3),
			want: true,
		},
		{
			name: "less than version",
			v1:   New(1, 2, 3),
			v2:   New(1, 2, 4),
			want: true,
		},
		{
			name: "greater than version",
			v1:   New(1, 2, 4),
			v2:   New(1, 2, 3),
			want: false,
		},
		{
			name: "different model - less",
			v1:   New(1, 9, 9),
			v2:   New(2, 0, 0),
			want: true,
		},
		{
			name: "different model - greater",
			v1:   New(2, 0, 0),
			v2:   New(1, 9, 9),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.v1.LessThanOrEqualTo(tt.v2))
		})
	}
}

func TestSchemaVer_Equal(t *testing.T) {
	tests := []struct {
		name string
		v1   SchemaVer
		v2   SchemaVer
		want bool
	}{
		{
			name: "equal versions",
			v1:   New(1, 2, 3),
			v2:   New(1, 2, 3),
			want: true,
		},
		{
			name: "different addition",
			v1:   New(1, 2, 3),
			v2:   New(1, 2, 4),
			want: false,
		},
		{
			name: "different revision",
			v1:   New(1, 2, 3),
			v2:   New(1, 3, 3),
			want: false,
		},
		{
			name: "different model",
			v1:   New(1, 2, 3),
			v2:   New(2, 2, 3),
			want: false,
		},
		{
			name: "zero values equal",
			v1:   New(1, 0, 0),
			v2:   New(1, 0, 0),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.v1.Equal(tt.v2))
		})
	}
}

func TestSchemaVer_GreaterThan(t *testing.T) {
	tests := []struct {
		name string
		v1   SchemaVer
		v2   SchemaVer
		want bool
	}{
		{
			name: "equal versions",
			v1:   New(1, 2, 3),
			v2:   New(1, 2, 3),
			want: false,
		},
		{
			name: "greater addition",
			v1:   New(1, 2, 4),
			v2:   New(1, 2, 3),
			want: true,
		},
		{
			name: "greater revision",
			v1:   New(1, 3, 0),
			v2:   New(1, 2, 9),
			want: true,
		},
		{
			name: "greater model",
			v1:   New(2, 0, 0),
			v2:   New(1, 9, 9),
			want: true,
		},
		{
			name: "less than",
			v1:   New(1, 2, 3),
			v2:   New(1, 2, 4),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.v1.GreaterThan(tt.v2))
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
			name:    "valid version with v prefix",
			input:   "v1.2.3",
			want:    New(1, 2, 3),
			wantErr: false,
		},
		{
			name:    "valid version with v prefix and zeros",
			input:   "v1.0.0",
			want:    New(1, 0, 0),
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
			name:    "invalid version with v prefix and zero model",
			input:   "v0.0.0",
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

func TestSchemaVer_String(t *testing.T) {
	tests := []struct {
		name   string
		schema SchemaVer
		want   string
	}{
		{
			name:   "basic version",
			schema: New(1, 2, 3),
			want:   "v1.2.3",
		},
		{
			name:   "version with zeros",
			schema: New(1, 0, 0),
			want:   "v1.0.0",
		},
		{
			name:   "large numbers",
			schema: New(999, 888, 777),
			want:   "v999.888.777",
		},
		{
			name:   "single digits",
			schema: New(5, 4, 3),
			want:   "v5.4.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.schema.String())
		})
	}
}

func TestSchemaVer_MarshalJSON(t *testing.T) {
	tests := []struct {
		name   string
		schema SchemaVer
		want   string
	}{
		{
			name:   "basic version",
			schema: New(1, 2, 3),
			want:   `"v1.2.3"`,
		},
		{
			name:   "version with zeros",
			schema: New(1, 0, 0),
			want:   `"v1.0.0"`,
		},
		{
			name:   "large numbers",
			schema: New(999, 888, 777),
			want:   `"v999.888.777"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.schema.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestSchemaVer_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    SchemaVer
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "valid version",
			input:   `"v1.2.3"`,
			want:    New(1, 2, 3),
			wantErr: require.NoError,
		},
		{
			name:    "valid version without v prefix",
			input:   `"1.2.3"`,
			want:    New(1, 2, 3),
			wantErr: require.NoError,
		},
		{
			name:    "valid version with zeros",
			input:   `"v1.0.0"`,
			want:    New(1, 0, 0),
			wantErr: require.NoError,
		},
		{
			name:    "invalid JSON format",
			input:   `{"version": "v1.2.3"}`,
			wantErr: require.Error,
		},
		{
			name:    "invalid version format",
			input:   `"invalid"`,
			wantErr: require.Error,
		},
		{
			name:    "invalid zero model",
			input:   `"v0.1.2"`,
			wantErr: require.Error,
		},
		{
			name:    "malformed JSON",
			input:   `"v1.2.3`,
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got SchemaVer
			err := json.Unmarshal([]byte(tt.input), &got)
			tt.wantErr(t, err)
			if err == nil {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestSchemaVer_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		schema SchemaVer
	}{
		{
			name:   "basic version",
			schema: New(1, 2, 3),
		},
		{
			name:   "version with zeros",
			schema: New(1, 0, 0),
		},
		{
			name:   "large numbers",
			schema: New(999, 888, 777),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// marshal
			data, err := json.Marshal(tt.schema)
			require.NoError(t, err)

			// unmarshal
			var got SchemaVer
			err = json.Unmarshal(data, &got)
			require.NoError(t, err)

			// should be equal
			assert.Equal(t, tt.schema, got)
		})
	}
}
