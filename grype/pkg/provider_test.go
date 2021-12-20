package pkg

import (
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProviderLocationExcludes(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		excludes []string
		expected []string
	}{
		{
			name:     "exclude everything",
			fixture:  "test-fixtures/syft-spring.json",
			excludes: []string{"**"},
			expected: []string{},
		},
		{
			name:     "exclude specific real path match",
			fixture:  "test-fixtures/syft-spring.json",
			excludes: []string{"**/tomcat*.jar"},
			expected: []string{"charsets"},
		},
		{
			name:     "include everything with no match",
			fixture:  "test-fixtures/syft-spring.json",
			excludes: []string{},
			expected: []string{"charsets", "tomcat-embed-el"},
		},
		{
			name:     "include everything with no excludes",
			fixture:  "test-fixtures/syft-spring.json",
			excludes: []string{},
			expected: []string{"charsets", "tomcat-embed-el"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgs, _, _ := Provide(test.fixture, source.SquashedScope, nil, test.excludes...)

			var pkgNames []string

			for _, pkg := range pkgs {
				pkgNames = append(pkgNames, pkg.Name)
			}

			assert.ElementsMatch(t, pkgNames, test.expected)
		})
	}
}
