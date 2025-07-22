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

func TestSplitOnFirstString(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		separators []string
		wantBefore string
		wantAfter  string
	}{
		// go cases
		{
			name:       "single separator found",
			input:      "key=value",
			separators: []string{"="},
			wantBefore: "key",
			wantAfter:  "value",
		},
		{
			name:       "multiple separators, first one wins",
			input:      "protocol://host:port",
			separators: []string{"://", ":"},
			wantBefore: "protocol",
			wantAfter:  "host:port",
		},
		{
			name:       "multiple separators, earlier position wins",
			input:      "name:value=data",
			separators: []string{"=", ":"},
			wantBefore: "name",
			wantAfter:  "value=data",
		},
		// edge cases
		{
			name:       "no separator found",
			input:      "noseparator",
			separators: []string{"=", ":"},
			wantBefore: "noseparator",
			wantAfter:  "",
		},
		{
			name:       "empty input",
			input:      "",
			separators: []string{"="},
			wantBefore: "",
			wantAfter:  "",
		},
		{
			name:       "separator at beginning",
			input:      "=value",
			separators: []string{"="},
			wantBefore: "",
			wantAfter:  "value",
		},
		{
			name:       "separator at end",
			input:      "key=",
			separators: []string{"="},
			wantBefore: "key",
			wantAfter:  "",
		},
		{
			name:       "only separator",
			input:      "=",
			separators: []string{"="},
			wantBefore: "",
			wantAfter:  "",
		},
		// multiple occurrences
		{
			name:       "multiple occurrences of same separator",
			input:      "a=b=c=d",
			separators: []string{"="},
			wantBefore: "a",
			wantAfter:  "b=c=d",
		},
		{
			name:       "multiple different separators, choose earliest",
			input:      "a:b=c:d",
			separators: []string{"=", ":"},
			wantBefore: "a",
			wantAfter:  "b=c:d",
		},

		// multi-character separators
		{
			name:       "multi-character separator",
			input:      "before::after",
			separators: []string{"::"},
			wantBefore: "before",
			wantAfter:  "after",
		},
		{
			name:       "overlapping separators",
			input:      "test:::data",
			separators: []string{"::", ":::"},
			wantBefore: "test",
			wantAfter:  ":data",
		},
		{
			name:       "longer separator wins when at same position",
			input:      "test:::data",
			separators: []string{":::", "::"},
			wantBefore: "test",
			wantAfter:  "data",
		},
		// more realistic cases
		{
			name:       "URL parsing",
			input:      "https://user:pass@host:8080/path?query=value",
			separators: []string{"://", "@", ":", "/", "?", "="},
			wantBefore: "https",
			wantAfter:  "user:pass@host:8080/path?query=value",
		},
		{
			name:       "environment variable",
			input:      "PATH=/usr/bin:/bin",
			separators: []string{"=", ":"},
			wantBefore: "PATH",
			wantAfter:  "/usr/bin:/bin",
		},
		{
			name:       "docker image tag",
			input:      "registry.example.com/namespace/image:v1.0",
			separators: []string{":", "/"},
			wantBefore: "registry.example.com",
			wantAfter:  "namespace/image:v1.0",
		},

		// special characters
		{
			name:       "unicode separators",
			input:      "hello→world",
			separators: []string{"→"},
			wantBefore: "hello",
			wantAfter:  "world",
		},
		{
			name:       "whitespace separators",
			input:      "word1 word2\tword3",
			separators: []string{" ", "\t"},
			wantBefore: "word1",
			wantAfter:  "word2\tword3",
		},
		// co separators provided
		{
			name:       "no separators provided",
			input:      "test=data",
			separators: []string{},
			wantBefore: "test=data",
			wantAfter:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBefore, gotAfter := SplitOnFirstString(tt.input, tt.separators...)

			if gotBefore != tt.wantBefore {
				t.Errorf("SplitOnFirstString() gotBefore = %q, want %q", gotBefore, tt.wantBefore)
			}
			if gotAfter != tt.wantAfter {
				t.Errorf("SplitOnFirstString() gotAfter = %q, want %q", gotAfter, tt.wantAfter)
			}
		})
	}
}

func TestSplitOnAny(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		separators []string
		expected   []string
	}{
		{
			name:       "empty string",
			input:      "",
			separators: []string{","},
			expected:   nil,
		},
		{
			name:       "single separator",
			input:      "a,b,c",
			separators: []string{","},
			expected:   []string{"a", "b", "c"},
		},
		{
			name:       "multiple separators",
			input:      "a,b;c:d",
			separators: []string{",", ";", ":"},
			expected:   []string{"a", "b", "c", "d"},
		},
		{
			name:       "no separators found",
			input:      "hello",
			separators: []string{",", ";"},
			expected:   []string{"hello"},
		},
		{
			name:       "consecutive separators",
			input:      "a,,b",
			separators: []string{","},
			expected:   []string{"a", "", "b"},
		},
		{
			name:       "separator at beginning",
			input:      ",a,b",
			separators: []string{","},
			expected:   []string{"", "a", "b"},
		},
		{
			name:       "separator at end",
			input:      "a,b,",
			separators: []string{","},
			expected:   []string{"a", "b", ""},
		},
		{
			name:       "only separators",
			input:      ",,",
			separators: []string{","},
			expected:   []string{"", "", ""},
		},
		{
			name:       "overlapping separators",
			input:      "a,b;c,d",
			separators: []string{",", ";"},
			expected:   []string{"a", "b", "c", "d"},
		},
		{
			name:       "separator is substring of another",
			input:      "a::b:c",
			separators: []string{"::", ":"},
			expected:   []string{"a", "b", "c"},
		},
		{
			name:       "order does not matter for overlapping",
			input:      "a::b:c",
			separators: []string{":", "::"},
			expected:   []string{"a", "b", "c"},
		},
		{
			name:       "no separators provided",
			input:      "hello",
			separators: []string{},
			expected:   []string{"hello"},
		},
		{
			name:       "multi-character separator",
			input:      "a<->b<->c",
			separators: []string{"<->"},
			expected:   []string{"a", "b", "c"},
		},
		{
			name:       "mixed single and multi-character separators",
			input:      "a,b<->c;d",
			separators: []string{",", "<->", ";"},
			expected:   []string{"a", "b", "c", "d"},
		},
		{
			name:       "space separator",
			input:      "hello world test",
			separators: []string{" "},
			expected:   []string{"hello", "world", "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitOnAny(tt.input, tt.separators...)
			assert.Equal(t, tt.expected, result)
		})
	}
}
