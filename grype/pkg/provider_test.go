package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
)

func TestProviderLocationExcludes(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		excludes []string
		expected []string
		wantErr  assert.ErrorAssertionFunc
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
		{
			name:     "exclusions must not hide parsing error",
			fixture:  "test-fixtures/bad-sbom.json",
			excludes: []string{"**/some-glob/*"},
			wantErr:  assert.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ProviderConfig{
				SyftProviderConfig: SyftProviderConfig{
					Exclusions:  test.excludes,
					SBOMOptions: syft.DefaultCreateSBOMConfig(),
				},
			}
			if test.wantErr == nil {
				test.wantErr = assert.NoError
			}
			pkgs, _, _, err := Provide(test.fixture, cfg)
			test.wantErr(t, err)
			if err != nil {
				return
			}

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
			cfg := ProviderConfig{
				SyftProviderConfig: SyftProviderConfig{
					Exclusions:  test.excludes,
					SBOMOptions: syft.DefaultCreateSBOMConfig(),
				},
			}
			pkgs, _, _, err := Provide(userInput, cfg)

			assert.NoErrorf(t, err, "error calling Provide function")

			var pkgNames []string

			for _, pkg := range pkgs {
				pkgNames = append(pkgNames, pkg.Name)
			}

			assert.ElementsMatch(t, pkgNames, test.expected)
		})
	}
}

func Test_filterPackageExclusions(t *testing.T) {
	tests := []struct {
		name       string
		locations  [][]string
		exclusions []string
		expected   int
	}{
		{
			name:       "exclude nothing",
			locations:  [][]string{{"/foo", "/bar"}, {"/foo", "/bar"}},
			exclusions: []string{"/asdf/**"},
			expected:   2,
		},
		{
			name:       "exclude everything",
			locations:  [][]string{{"/foo", "/bar"}, {"/foo", "/bar"}},
			exclusions: []string{"**"},
			expected:   0,
		},
		{
			name:       "exclude based on all location match",
			locations:  [][]string{{"/foo1", "/bar1"}, {"/foo2", "/bar2"}},
			exclusions: []string{"/foo2", "/bar2"},
			expected:   1,
		},
		{
			name:       "don't exclude with single location match",
			locations:  [][]string{{"/foo1", "/bar1"}, {"/foo2", "/bar2"}},
			exclusions: []string{"/foo1", "/foo2"},
			expected:   2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var packages []Package
			for _, pkg := range test.locations {
				locations := file.NewLocationSet()
				for _, l := range pkg {
					locations.Add(
						file.NewVirtualLocation(l, l),
					)
				}
				packages = append(packages, Package{Locations: locations})
			}
			filtered, err := filterPackageExclusions(packages, test.exclusions)

			assert.NoError(t, err)
			assert.Len(t, filtered, test.expected)
		})
	}
}

func Test_matchesLocation(t *testing.T) {
	tests := []struct {
		name        string
		realPath    string
		virtualPath string
		match       string
		expected    bool
	}{
		{
			name:        "doesn't match real",
			realPath:    "/asdf",
			virtualPath: "",
			match:       "/usr",
			expected:    false,
		},
		{
			name:        "doesn't match virtual",
			realPath:    "",
			virtualPath: "/asdf",
			match:       "/usr",
			expected:    false,
		},
		{
			name:        "does match real",
			realPath:    "/usr/foo",
			virtualPath: "",
			match:       "/usr/**",
			expected:    true,
		},
		{
			name:        "does match virtual",
			realPath:    "",
			virtualPath: "/usr/bar/oof.txt",
			match:       "/usr/**",
			expected:    true,
		},
		{
			name:        "does match file",
			realPath:    "",
			virtualPath: "/usr/bar/oof.txt",
			match:       "**/*.txt",
			expected:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, err := locationMatches(file.NewVirtualLocation(test.realPath, test.virtualPath), test.match)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, matches)
		})
	}
}
