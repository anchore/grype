package sqlite

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestToNullString(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected NullString
	}{
		{
			name:     "Nil input",
			input:    nil,
			expected: NullString{},
		},
		{
			name:     "String null",
			input:    "null",
			expected: NullString{},
		},
		{
			name:     "Other string",
			input:    "Hello there {}",
			expected: NewNullString("Hello there {}", true),
		},
		{
			name: "Single struct with all fields populated",
			input: struct {
				Boolean     bool   `json:"boolean"`
				String      string `json:"string"`
				Integer     int    `json:"integer"`
				InnerStruct struct {
					StringList []string `json:"string_list"`
				} `json:"inner_struct"`
			}{
				Boolean: true,
				String:  "{}",
				Integer: 1034,
				InnerStruct: struct {
					StringList []string `json:"string_list"`
				}{
					StringList: []string{"a", "b", "c"},
				},
			},
			expected: NewNullString(`{"boolean":true,"string":"{}","integer":1034,"inner_struct":{"string_list":["a","b","c"]}}`, true),
		},
		{
			name: "Single struct with one field populated",
			input: struct {
				Boolean     bool   `json:"boolean"`
				String      string `json:"string"`
				Integer     int    `json:"integer"`
				InnerStruct struct {
					StringList []string `json:"string_list"`
				} `json:"inner_struct"`
			}{
				Boolean: true,
			},
			expected: NewNullString(`{"boolean":true,"string":"","integer":0,"inner_struct":{"string_list":null}}`, true),
		},
		{
			name: "Single struct with one field populated omit empty",
			input: struct {
				Boolean     bool   `json:"boolean,omitempty"`
				String      string `json:"string,omitempty"`
				Integer     int    `json:"integer,omitempty"`
				InnerStruct struct {
					StringList []string `json:"string_list,omitempty"`
				} `json:"inner_struct,omitempty"`
			}{
				Boolean: true,
			},
			expected: NewNullString(`{"boolean":true,"inner_struct":{}}`, true),
		},
		{
			name: "Array of structs",
			input: []struct {
				Boolean bool   `json:"boolean,omitempty"`
				String  string `json:"string,omitempty"`
				Integer int    `json:"integer,omitempty"`
			}{
				{
					Boolean: true,
					String:  "{}",
					Integer: 1034,
				},
				{
					String: "[{}]",
				},
				{
					Integer: -5000,
					Boolean: false,
				},
			},
			expected: NewNullString(`[{"boolean":true,"string":"{}","integer":1034},{"string":"[{}]"},{"integer":-5000}]`, true),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ToNullString(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}
