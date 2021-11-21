package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasAnyOfSuffixes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		suffixes []string
		expected bool
	}{
		{
			name:  "go case",
			input: "this has something",
			suffixes: []string{
				"has something",
				"has NOT something",
			},
			expected: true,
		},
		{
			name:  "no match",
			input: "this has something",
			suffixes: []string{
				"has NOT something",
			},
			expected: false,
		},
		{
			name:     "empty",
			input:    "this has something",
			suffixes: []string{},
			expected: false,
		},
		{
			name:  "positive match last",
			input: "this has something",
			suffixes: []string{
				"that does not have",
				"something",
			},
			expected: true,
		},
		{
			name:  "empty input",
			input: "",
			suffixes: []string{
				"that does not have",
				"this has",
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, HasAnyOfSuffixes(test.input, test.suffixes...))
		})
	}
}
