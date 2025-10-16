package rpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestExtractSourceRPMName(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected string
	}{
		{
			name: "binary package with upstream source",
			pkg: pkg.Package{
				Name: "python3-criu",
				Type: syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{Name: "criu", Version: "3.12"},
				},
			},
			expected: "criu",
		},
		{
			name: "source package with no upstreams",
			pkg: pkg.Package{
				Name:      "criu",
				Type:      syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{},
			},
			expected: "criu",
		},
		{
			name: "package with self-referential upstream",
			pkg: pkg.Package{
				Name: "kernel",
				Type: syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{Name: "kernel", Version: "5.4.0"},
				},
			},
			expected: "kernel",
		},
		{
			name: "package with RPM metadata but no upstreams",
			pkg: pkg.Package{
				Name: "util-linux",
				Type: syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					Epoch: intPtr(0),
				},
			},
			expected: "util-linux",
		},
		{
			name: "non-RPM package",
			pkg: pkg.Package{
				Name: "some-deb-package",
				Type: syftPkg.DebPkg,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSourceRPMName(tt.pkg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRelatedPackageNames(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []string
	}{
		{
			name: "binary package with source upstream",
			pkg: pkg.Package{
				Name: "python3-criu",
				Type: syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{Name: "criu", Version: "3.12"},
				},
			},
			expected: []string{"python3-criu", "criu"}, // should include both binary and source names
		},
		{
			name: "source package with no upstreams",
			pkg: pkg.Package{
				Name:      "httpd",
				Type:      syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{},
			},
			expected: []string{"httpd"}, // should only include itself
		},
		{
			name: "package with self-referential upstream",
			pkg: pkg.Package{
				Name: "kernel",
				Type: syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{Name: "kernel", Version: "5.4.0"},
				},
			},
			expected: []string{"kernel"}, // should only include itself since source name is same
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRelatedPackageNames(tt.pkg)

			// Check that all expected names are present
			for _, expected := range tt.expected {
				assert.Contains(t, result, expected, "Missing expected package name: %s", expected)
			}

			// Check that we don't have unexpected names
			assert.Equal(t, len(tt.expected), len(result), "Unexpected number of package names")

			// The first name should always be the package name itself
			require.NotEmpty(t, result)
			assert.Equal(t, tt.pkg.Name, result[0])
		})
	}
}

// Helper function for tests
func intPtr(i int) *int {
	return &i
}
