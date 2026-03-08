package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestRootIO_Satisfied(t *testing.T) {
	tests := []struct {
		name           string
		required       bool
		pkg            pkg.Package
		expectedResult bool
	}{
		{
			name:     "NAK: standard Alpine package with Root IO vuln suppressed",
			required: true,
			pkg: pkg.Package{
				Name:    "util-linux",
				Version: "2.38.1-r0",
				Type:    syftPkg.ApkPkg,
			},
			expectedResult: false,
		},
		{
			name:     "Root IO Alpine package with Root IO vuln allowed",
			required: true,
			pkg: pkg.Package{
				Name:    "rootio-util-linux",
				Version: "2.38.1-r10071",
				Type:    syftPkg.ApkPkg,
			},
			expectedResult: true,
		},
		{
			name:     "Standard package without Root IO qualifier allowed",
			required: false,
			pkg: pkg.Package{
				Name:    "util-linux",
				Version: "2.38.1-r0",
				Type:    syftPkg.ApkPkg,
			},
			expectedResult: true,
		},
		{
			name:     "Root IO package without Root IO qualifier allowed",
			required: false,
			pkg: pkg.Package{
				Name:    "rootio-util-linux",
				Version: "2.38.1-r10071",
				Type:    syftPkg.ApkPkg,
			},
			expectedResult: true,
		},
		{
			name:     "NAK: standard Debian package with Root IO vuln suppressed",
			required: true,
			pkg: pkg.Package{
				Name:    "imagemagick",
				Version: "8:6.9.11.60",
				Type:    syftPkg.DebPkg,
			},
			expectedResult: false,
		},
		{
			name:     "Root IO Debian package with Root IO vuln allowed",
			required: true,
			pkg: pkg.Package{
				Name:    "rootio-imagemagick",
				Version: "8:6.9.11.root.io.1",
				Type:    syftPkg.DebPkg,
			},
			expectedResult: true,
		},
		{
			name:     "NAK: standard NPM package with Root IO vuln suppressed",
			required: true,
			pkg: pkg.Package{
				Name:    "semver",
				Version: "7.5.4",
				Type:    syftPkg.NpmPkg,
			},
			expectedResult: false,
		},
		{
			name:     "Root IO NPM scoped package with Root IO vuln allowed",
			required: true,
			pkg: pkg.Package{
				Name:    "@rootio/semver",
				Version: "7.5.4",
				Type:    syftPkg.NpmPkg,
			},
			expectedResult: true,
		},
		{
			name:     "Root IO NPM package with version suffix allowed",
			required: true,
			pkg: pkg.Package{
				Name:    "semver",
				Version: "7.5.4-root.io.1",
				Type:    syftPkg.NpmPkg,
			},
			expectedResult: true,
		},
		{
			name:     "NAK: standard PyPI package with Root IO vuln suppressed",
			required: true,
			pkg: pkg.Package{
				Name:    "requests",
				Version: "2.31.0",
				Type:    syftPkg.PythonPkg,
			},
			expectedResult: false,
		},
		{
			name:     "Root IO PyPI package with version suffix allowed",
			required: true,
			pkg: pkg.Package{
				Name:    "rootio-requests",
				Version: "2.31.0+root.io.1",
				Type:    syftPkg.PythonPkg,
			},
			expectedResult: true,
		},
		{
			name:     "NAK: standard Java package with Root IO vuln suppressed (placeholder)",
			required: true,
			pkg: pkg.Package{
				Name:    "jackson-databind",
				Version: "2.14.0",
				Type:    syftPkg.JavaPkg,
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := New(tt.required)
			result, err := q.Satisfied(tt.pkg)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestIsRootIOPackage(t *testing.T) {
	tests := []struct {
		name           string
		pkg            pkg.Package
		expectedResult bool
	}{
		{
			name: "Alpine: rootio- prefix with -r1007N suffix",
			pkg: pkg.Package{
				Name:    "rootio-util-linux",
				Version: "2.38.1-r10071",
				Type:    syftPkg.ApkPkg,
			},
			expectedResult: true,
		},
		{
			name: "Alpine: rootio- prefix only",
			pkg: pkg.Package{
				Name:    "rootio-util-linux",
				Version: "2.38.1-r0",
				Type:    syftPkg.ApkPkg,
			},
			expectedResult: true,
		},
		{
			name: "Alpine: standard package",
			pkg: pkg.Package{
				Name:    "util-linux",
				Version: "2.38.1-r0",
				Type:    syftPkg.ApkPkg,
			},
			expectedResult: false,
		},
		{
			name: "Debian: rootio- prefix with .root.io.N suffix",
			pkg: pkg.Package{
				Name:    "rootio-imagemagick",
				Version: "8:6.9.11.root.io.1",
				Type:    syftPkg.DebPkg,
			},
			expectedResult: true,
		},
		{
			name: "Debian: rootio- prefix only",
			pkg: pkg.Package{
				Name:    "rootio-imagemagick",
				Version: "8:6.9.11",
				Type:    syftPkg.DebPkg,
			},
			expectedResult: true,
		},
		{
			name: "Debian: standard package",
			pkg: pkg.Package{
				Name:    "imagemagick",
				Version: "8:6.9.11",
				Type:    syftPkg.DebPkg,
			},
			expectedResult: false,
		},
		{
			name: "NPM: @rootio/ scoped package",
			pkg: pkg.Package{
				Name:    "@rootio/semver",
				Version: "7.5.4",
				Type:    syftPkg.NpmPkg,
			},
			expectedResult: true,
		},
		{
			name: "NPM: rootio- prefix",
			pkg: pkg.Package{
				Name:    "rootio-semver",
				Version: "7.5.4",
				Type:    syftPkg.NpmPkg,
			},
			expectedResult: true,
		},
		{
			name: "NPM: version suffix only",
			pkg: pkg.Package{
				Name:    "semver",
				Version: "7.5.4-root.io.1",
				Type:    syftPkg.NpmPkg,
			},
			expectedResult: true,
		},
		{
			name: "NPM: standard package",
			pkg: pkg.Package{
				Name:    "semver",
				Version: "7.5.4",
				Type:    syftPkg.NpmPkg,
			},
			expectedResult: false,
		},
		{
			name: "PyPI: rootio- prefix with +root.io.N suffix",
			pkg: pkg.Package{
				Name:    "rootio-requests",
				Version: "2.31.0+root.io.1",
				Type:    syftPkg.PythonPkg,
			},
			expectedResult: true,
		},
		{
			name: "PyPI: rootio- prefix only",
			pkg: pkg.Package{
				Name:    "rootio-requests",
				Version: "2.31.0",
				Type:    syftPkg.PythonPkg,
			},
			expectedResult: true,
		},
		{
			name: "PyPI: +root.io.N suffix only",
			pkg: pkg.Package{
				Name:    "requests",
				Version: "2.31.0+root.io.1",
				Type:    syftPkg.PythonPkg,
			},
			expectedResult: true,
		},
		{
			name: "PyPI: standard package",
			pkg: pkg.Package{
				Name:    "requests",
				Version: "2.31.0",
				Type:    syftPkg.PythonPkg,
			},
			expectedResult: false,
		},
		{
			name: "Java: placeholder returns false",
			pkg: pkg.Package{
				Name:    "rootio-jackson-databind",
				Version: "2.14.0",
				Type:    syftPkg.JavaPkg,
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRootIOPackage(tt.pkg)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestHasRootIOPrefix(t *testing.T) {
	tests := []struct {
		name           string
		packageName    string
		pkgType        syftPkg.Type
		expectedResult bool
	}{
		{
			name:           "rootio- prefix for Alpine",
			packageName:    "rootio-util-linux",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: true,
		},
		{
			name:           "rootio- prefix for Debian",
			packageName:    "rootio-imagemagick",
			pkgType:        syftPkg.DebPkg,
			expectedResult: true,
		},
		{
			name:           "@rootio/ scoped NPM package",
			packageName:    "@rootio/semver",
			pkgType:        syftPkg.NpmPkg,
			expectedResult: true,
		},
		{
			name:           "rootio- prefix for NPM",
			packageName:    "rootio-semver",
			pkgType:        syftPkg.NpmPkg,
			expectedResult: true,
		},
		{
			name:           "rootio- prefix for PyPI",
			packageName:    "rootio-requests",
			pkgType:        syftPkg.PythonPkg,
			expectedResult: true,
		},
		{
			name:           "no prefix",
			packageName:    "util-linux",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: false,
		},
		{
			name:           "empty string",
			packageName:    "",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: false,
		},
		{
			name:           "Java placeholder returns false",
			packageName:    "rootio-jackson-databind",
			pkgType:        syftPkg.JavaPkg,
			expectedResult: false,
		},
		{
			name:           "short name with root",
			packageName:    "root",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: false,
		},
		{
			name:           "name containing root but not prefix",
			packageName:    "myroot-package",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasRootIOPrefix(tt.packageName, tt.pkgType)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestHasRootIOVersionSuffix(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		pkgType        syftPkg.Type
		expectedResult bool
	}{
		{
			name:           "NPM: -root.io. suffix",
			version:        "7.5.4-root.io.1",
			pkgType:        syftPkg.NpmPkg,
			expectedResult: true,
		},
		{
			name:           "Debian: .root.io. suffix",
			version:        "8:6.9.11.root.io.1",
			pkgType:        syftPkg.DebPkg,
			expectedResult: true,
		},
		{
			name:           "PyPI: +root.io. suffix",
			version:        "2.31.0+root.io.1",
			pkgType:        syftPkg.PythonPkg,
			expectedResult: true,
		},
		{
			name:           "Alpine: -r10071 suffix",
			version:        "2.38.1-r10071",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: true,
		},
		{
			name:           "Alpine: -r10072 suffix",
			version:        "2.38.1-r10072",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: true,
		},
		{
			name:           "Alpine: standard -r0 suffix",
			version:        "2.38.1-r0",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: false,
		},
		{
			name:           "Alpine: standard -r1 suffix",
			version:        "2.38.1-r1",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: false,
		},
		{
			name:           "Alpine: -r1007 without digit after (edge case)",
			version:        "2.38.1-r1007",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: false,
		},
		{
			name:           "no suffix",
			version:        "2.38.1",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: false,
		},
		{
			name:           "empty version",
			version:        "",
			pkgType:        syftPkg.ApkPkg,
			expectedResult: false,
		},
		{
			name:           "Java placeholder returns false",
			version:        "2.14.0.root.io.1",
			pkgType:        syftPkg.JavaPkg,
			expectedResult: false,
		},
		{
			name:           "PyPI: wrong suffix type (should use +)",
			version:        "2.31.0.root.io.1",
			pkgType:        syftPkg.PythonPkg,
			expectedResult: false,
		},
		{
			name:           "NPM: wrong suffix type (should use -)",
			version:        "7.5.4.root.io.1",
			pkgType:        syftPkg.NpmPkg,
			expectedResult: false,
		},
		{
			name:           "NPM: wrong suffix with +",
			version:        "7.5.4+root.io.1",
			pkgType:        syftPkg.NpmPkg,
			expectedResult: false,
		},
		{
			name:           "Debian: wrong suffix with -",
			version:        "5.10.234-1-root.io.1",
			pkgType:        syftPkg.DebPkg,
			expectedResult: false,
		},
		{
			name:           "Debian: wrong suffix with +",
			version:        "5.10.234-1+root.io.1",
			pkgType:        syftPkg.DebPkg,
			expectedResult: false,
		},
		{
			name:           "PyPI: wrong suffix with -",
			version:        "2.31.0-root.io.1",
			pkgType:        syftPkg.PythonPkg,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasRootIOVersionSuffix(tt.version, tt.pkgType)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
