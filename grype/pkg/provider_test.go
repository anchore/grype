package pkg

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
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
			excludes: []string{"**/asdf*.jar"},
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

func TestSyftLocationExcludes(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		excludes []string
		expected []string
	}{
		{
			name:     "exclude everything",
			fixture:  "image-simple",
			excludes: []string{"**"},
			expected: []string{},
		},
		{
			name:     "exclude specific real path match",
			fixture:  "image-simple",
			excludes: []string{"**/nested/package.json"},
			expected: []string{"top-level-package"},
		},
		{
			name:     "include everything with no match",
			fixture:  "image-simple",
			excludes: []string{"**/asdf*.json"},
			expected: []string{"nested-package", "top-level-package"},
		},
		{
			name:     "include everything with no excludes",
			fixture:  "image-simple",
			excludes: []string{},
			expected: []string{"nested-package", "top-level-package"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userInput := imagetest.GetFixtureImageTarPath(t, test.fixture)

			pkgs, _, err := Provide(userInput, source.SquashedScope, &image.RegistryOptions{}, test.excludes...)

			assert.NoErrorf(t, err, "error calling Provide function")

			var pkgNames []string

			for _, pkg := range pkgs {
				pkgNames = append(pkgNames, pkg.Name)
			}

			assert.ElementsMatch(t, pkgNames, test.expected)
		})
	}
}
