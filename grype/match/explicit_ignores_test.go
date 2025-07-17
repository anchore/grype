package match

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockExclusionProvider struct {
	data map[string][]IgnoreRule
}

func newMockExclusionProvider() *mockExclusionProvider {
	d := mockExclusionProvider{
		data: make(map[string][]IgnoreRule),
	}
	d.stub()
	return &d
}

func (d *mockExclusionProvider) stub() {
}

func (d *mockExclusionProvider) IgnoreRules(vulnerabilityID string) ([]IgnoreRule, error) {
	return d.data[vulnerabilityID], nil
}

func Test_ApplyExplicitIgnoreRules(t *testing.T) {
	type cvePkg struct {
		cve string
		pkg string
	}
	tests := []struct {
		name     string
		typ      syftPkg.Type
		matches  []cvePkg
		expected []string
		ignored  []string
	}{
		// some explicit log4j-related data:
		// "CVE-2021-44228", "CVE-2021-45046", "GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33",
		// "log4j-api", "log4j-slf4j-impl", "log4j-to-slf4j", "log4j-1.2-api",
		{
			name: "keeps non-matching packages",
			typ:  "java-archive",
			matches: []cvePkg{
				{"CVE-2021-44228", "log4j-core"},
				{"CVE-2021-43452", "foo-tool"},
			},
			expected: []string{"log4j-core", "foo-tool"},
		},
		{
			name: "keeps non-matching CVEs",
			typ:  "java-archive",
			matches: []cvePkg{
				{"CVE-2021-428", "log4j-api"},
				{"CVE-2021-43452", "foo-tool"},
			},
			expected: []string{"log4j-api", "foo-tool"},
		},
		{
			name: "filters only matching CVE and package",
			typ:  "java-archive",
			matches: []cvePkg{
				{"CVE-2021-44228", "log4j-api"},
				{"CVE-2021-44228", "log4j-core"},
			},
			expected: []string{"log4j-core"},
			ignored:  []string{"log4j-api"},
		},
		{
			name: "filters all matching CVEs and packages",
			typ:  "java-archive",
			matches: []cvePkg{
				{"GHSA-jfh8-c2jp-5v3q", "log4j-api"},
				{"GHSA-jfh8-c2jp-5v3q", "log4j-slf4j-impl"},
			},
			expected: []string{},
			ignored:  []string{"log4j-api", "log4j-slf4j-impl"},
		},
		{
			name: "filters invalid CVEs for protobuf Go module",
			typ:  "go-module",
			matches: []cvePkg{
				{"CVE-2015-5237", "google.golang.org/protobuf"},
				{"CVE-2021-22570", "google.golang.org/protobuf"},
			},
			expected: []string{},
			ignored:  []string{"google.golang.org/protobuf", "google.golang.org/protobuf"},
		},
		{
			name: "keeps valid CVEs for protobuf Go module",
			typ:  "go-module",
			matches: []cvePkg{
				{"CVE-1998-99999", "google.golang.org/protobuf"},
			},
			expected: []string{"google.golang.org/protobuf"},
		},
	}

	p := newMockExclusionProvider()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches := NewMatches()

			for _, cp := range test.matches {
				matches.Add(Match{

					Package: pkg.Package{
						ID:   pkg.ID(cp.pkg),
						Name: cp.pkg,
						Type: test.typ,
					},
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{ID: cp.cve},
					},
				})
			}

			filtered, ignores := ApplyExplicitIgnoreRules(p, matches)

			var found []string
			for match := range filtered.Enumerate() {
				found = append(found, match.Package.Name)

			}
			assert.ElementsMatch(t, test.expected, found)

			if len(test.ignored) > 0 {
				var ignored []string
				for _, i := range ignores {
					ignored = append(ignored, i.Package.Name)
				}
				assert.ElementsMatch(t, test.ignored, ignored)
			} else {
				assert.Empty(t, ignores)
			}
		})
	}
}
