package schemaver

import (
	"testing"
)

func TestStringComparisons(t *testing.T) {
	tests := []struct {
		name           string
		v1             String
		v2             String
		lessThan       bool
		greaterOrEqual bool
	}{
		{
			name:           "equal versions",
			v1:             NewString(1, 0, 0),
			v2:             NewString(1, 0, 0),
			lessThan:       false,
			greaterOrEqual: true,
		},
		{
			name:           "different model versions",
			v1:             NewString(1, 0, 0),
			v2:             NewString(2, 0, 0),
			lessThan:       true,
			greaterOrEqual: false,
		},
		{
			name:           "different revision versions",
			v1:             NewString(1, 1, 0),
			v2:             NewString(1, 2, 0),
			lessThan:       true,
			greaterOrEqual: false,
		},
		{
			name:           "different addition versions",
			v1:             NewString(1, 0, 1),
			v2:             NewString(1, 0, 2),
			lessThan:       true,
			greaterOrEqual: false,
		},
		{
			name:           "inverted addition versions",
			v1:             NewString(1, 0, 2),
			v2:             NewString(1, 0, 1),
			lessThan:       false,
			greaterOrEqual: true,
		},
		{
			name:           "greater model overrides lower revision",
			v1:             NewString(2, 0, 0),
			v2:             NewString(1, 9, 9),
			lessThan:       false,
			greaterOrEqual: true,
		},
		{
			name:           "greater revision overrides lower addition",
			v1:             NewString(1, 2, 0),
			v2:             NewString(1, 1, 9),
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

func TestParseAsString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    String
		wantErr bool
	}{
		{
			name:    "valid version",
			input:   "1.2.3",
			want:    NewString(1, 2, 3),
			wantErr: false,
		},
		{
			name:    "valid version with zeros",
			input:   "0.0.0",
			want:    NewString(0, 0, 0),
			wantErr: false,
		},
		{
			name:    "valid large numbers",
			input:   "999.888.777",
			want:    NewString(999, 888, 777),
			wantErr: false,
		},
		{
			name:    "valid with whitespace",
			input:   "  1.2.3  ",
			want:    NewString(1, 2, 3),
			wantErr: false,
		},
		{
			name:    "invalid empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid too few parts",
			input:   "1.2",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid too many parts",
			input:   "1.2.3.4",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric model",
			input:   "a.2.3",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric revision",
			input:   "1.b.3",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric addition",
			input:   "1.2.c",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid negative number",
			input:   "-1.2.3",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid format with spaces",
			input:   "1 . 2 . 3",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAsString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAsString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseAsString() = %v, want %v", got, tt.want)
			}
		})
	}
}
