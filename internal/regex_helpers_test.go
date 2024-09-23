package internal

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchCaptureGroups(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		pattern  string
		expected map[string]string
	}{
		{
			name:    "go-case",
			input:   "match this thing",
			pattern: `(?P<name>match).*(?P<version>thing)`,
			expected: map[string]string{
				"name":    "match",
				"version": "thing",
			},
		},
		{
			name:    "only matches the first instance",
			input:   "match this thing batch another think",
			pattern: `(?P<name>[mb]atch).*?(?P<version>thin[gk])`,
			expected: map[string]string{
				"name":    "match",
				"version": "thing",
			},
		},
		{
			name:    "nested capture groups",
			input:   "cool something to match against",
			pattern: `((?P<name>match) (?P<version>against))`,
			expected: map[string]string{
				"name":    "match",
				"version": "against",
			},
		},
		{
			name:    "nested optional capture groups",
			input:   "cool something to match against",
			pattern: `((?P<name>match) (?P<version>against))?`,
			expected: map[string]string{
				"name":    "match",
				"version": "against",
			},
		},
		{
			name:    "nested optional capture groups with larger match",
			input:   "cool something to match against match never",
			pattern: `.*?((?P<name>match) (?P<version>(against|never)))?`,
			expected: map[string]string{
				"name":    "match",
				"version": "against",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := MatchNamedCaptureGroups(regexp.MustCompile(test.pattern), test.input)
			assert.Equal(t, test.expected, actual)
		})
	}
}
