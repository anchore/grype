package stringutil

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

func TestHasAnyOfPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		prefixes []string
		expected bool
	}{
		{
			name:  "go case",
			input: "this has something",
			prefixes: []string{
				"this has",
				"that does not have",
			},
			expected: true,
		},
		{
			name:  "no match",
			input: "this has something",
			prefixes: []string{
				"this DOES NOT has",
				"that does not have",
			},
			expected: false,
		},
		{
			name:     "empty",
			input:    "this has something",
			prefixes: []string{},
			expected: false,
		},
		{
			name:  "positive match last",
			input: "this has something",
			prefixes: []string{
				"that does not have",
				"this has",
			},
			expected: true,
		},
		{
			name:  "empty input",
			input: "",
			prefixes: []string{
				"that does not have",
				"this has",
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, HasAnyOfPrefixes(test.input, test.prefixes...))
		})
	}
}

func TestSplitCommaSeparatedString(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "testing",
			expected: []string{"testing"},
		},
		{
			input:    "",
			expected: []string{},
		},
		{
			input:    "testing1,testing2",
			expected: []string{"testing1", "testing2"},
		},
		{
			input:    "testing1,,testing2,testing3",
			expected: []string{"testing1", "testing2", "testing3"},
		},
		{
			input:    "testing1,testing2,,",
			expected: []string{"testing1", "testing2"},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			assert.Equal(t, test.expected, SplitCommaSeparatedString(test.input))
		})
	}
}
