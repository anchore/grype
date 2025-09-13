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
			name: "source package generates binary patterns",
			pkg: pkg.Package{
				Name:      "python3",
				Type:      syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{},
			},
			// should include the source name plus common binary patterns
			expected: []string{
				"python3",
				"python3-devel", "python3-libs", "python3-tools", "python3-utils",
				"python3-client", "python3-server", "python3-common", "python3-doc",
				"python3-debuginfo", "libpython3", "libpython3-devel",
				"python3-python3", "python2-python3", "python3-python3", "python3-python2",
			},
		},
		{
			name: "python package with prefix handling",
			pkg: pkg.Package{
				Name:      "python3-requests",
				Type:      syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{},
			},
			expected: []string{
				"python3-requests",
				"python3-requests-devel", "python3-requests-libs", "python3-requests-tools",
				"python3-requests-utils", "python3-requests-client", "python3-requests-server",
				"python3-requests-common", "python3-requests-doc", "python3-requests-debuginfo",
				"libpython3-requests", "libpython3-requests-devel",
				"python3-python3-requests", "python2-python3-requests", "python3-requests-python3",
				"python3-requests-python2", "requests", "python3-requests",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRelatedPackageNames(tt.pkg)

			// Check that all expected names are present
			for _, expected := range tt.expected {
				assert.Contains(t, result, expected, "Missing expected package name: %s", expected)
			}

			// The first name should always be the package name itself
			require.NotEmpty(t, result)
			assert.Equal(t, tt.pkg.Name, result[0])
		})
	}
}

func TestGenerateCommonBinaryPackageNames(t *testing.T) {
	tests := []struct {
		name             string
		sourcePackage    string
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name:          "basic package",
			sourcePackage: "util-linux",
			shouldContain: []string{
				"util-linux-devel",
				"util-linux-libs",
				"util-linux-tools",
				"libutil-linux",
				"libutil-linux-devel",
			},
			shouldNotContain: []string{
				"python3-util-linux", // python patterns shouldn't apply
			},
		},
		{
			name:          "python package",
			sourcePackage: "python-requests",
			shouldContain: []string{
				"python-requests-devel",
				"python3-python-requests",
				"python2-python-requests",
				"python-requests-python3",
				"python3-requests", // from python prefix removal
			},
			shouldNotContain: []string{},
		},
		{
			name:          "python3 package",
			sourcePackage: "python3-flask",
			shouldContain: []string{
				"python3-flask-devel",
				"flask", // from python3 prefix removal
				"python3-python3-flask",
			},
			shouldNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateCommonBinaryPackageNames(tt.sourcePackage)

			for _, expected := range tt.shouldContain {
				assert.Contains(t, result, expected, "Missing expected pattern: %s", expected)
			}

			for _, notExpected := range tt.shouldNotContain {
				assert.NotContains(t, result, notExpected, "Should not contain: %s", notExpected)
			}
		})
	}
}

// Helper function for tests
func intPtr(i int) *int {
	return &i
}
