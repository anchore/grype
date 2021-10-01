package models

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/grype/grype/match"
)

func TestNewIgnoreRule(t *testing.T) {
	cases := []struct {
		name     string
		input    match.IgnoreRule
		expected IgnoreRule
	}{
		{
			name:  "no values",
			input: match.IgnoreRule{},
			expected: IgnoreRule{
				Vulnerability: "",
				Package:       nil,
			},
		},
		{
			name: "only vulnerability field",
			input: match.IgnoreRule{
				Vulnerability: "CVE-2020-1234",
			},
			expected: IgnoreRule{
				Vulnerability: "CVE-2020-1234",
			},
		},
		{
			name: "all package fields",
			input: match.IgnoreRule{
				Package: match.IgnoreRulePackage{
					Name:     "libc",
					Version:  "3.0.0",
					Type:     "rpm",
					Location: "/some/location",
				},
			},
			expected: IgnoreRule{
				Package: &IgnoreRulePackage{
					Name:     "libc",
					Version:  "3.0.0",
					Type:     "rpm",
					Location: "/some/location",
				},
			},
		},
		{
			name: "only one package field",
			input: match.IgnoreRule{
				Package: match.IgnoreRulePackage{
					Type: "apk",
				},
			},
			expected: IgnoreRule{
				Package: &IgnoreRulePackage{
					Type: "apk",
				},
			},
		},
		{
			name: "all fields",
			input: match.IgnoreRule{
				Vulnerability: "CVE-2020-1234",
				Package: match.IgnoreRulePackage{
					Name:     "libc",
					Version:  "3.0.0",
					Type:     "rpm",
					Location: "/some/location",
				},
			},
			expected: IgnoreRule{
				Vulnerability: "CVE-2020-1234",
				Package: &IgnoreRulePackage{
					Name:     "libc",
					Version:  "3.0.0",
					Type:     "rpm",
					Location: "/some/location",
				},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := newIgnoreRule(testCase.input)
			if diff := cmp.Diff(testCase.expected, actual); diff != "" {
				t.Errorf("(-expected +actual):\n%s", diff)
			}
		})
	}
}
