package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestIsJvmPackage(t *testing.T) {
	tests := []struct {
		name     string
		pkg      Package
		expected bool
	}{
		{
			name: "binary package with jdk in name set",
			pkg: Package{
				Type: syftPkg.BinaryPkg,
				Name: "jdk",
			},
			expected: true,
		},
		{
			name: "binary package with jre in name set",
			pkg: Package{
				Type: syftPkg.BinaryPkg,
				Name: "jre",
			},
			expected: true,
		},
		{
			name: "binary package with java_se in name set",
			pkg: Package{
				Type: syftPkg.BinaryPkg,
				Name: "java_se",
			},
			expected: true,
		},
		{
			name: "binary package with zulu in name set",
			pkg: Package{
				Type: syftPkg.BinaryPkg,
				Name: "zulu",
			},
			expected: true,
		},
		{
			name: "binary package with openjdk in name set",
			pkg: Package{
				Type: syftPkg.BinaryPkg,
				Name: "openjdk",
			},
			expected: true,
		},
		{
			name: "binary package from syft (java/jdk",
			pkg: Package{
				Type: syftPkg.BinaryPkg,
				Name: "java/jre",
			},
			expected: true,
		},
		{
			name: "binary package from syft (java/jre)",
			pkg: Package{
				Type: syftPkg.BinaryPkg,
				Name: "java/jdk",
			},
			expected: true,
		},
		{
			name: "binary package without jvm-related name",
			pkg: Package{
				Type: syftPkg.BinaryPkg,
				Name: "nodejs",
			},
			expected: false,
		},
		{
			name: "non-binary package with jvm-related name",
			pkg: Package{
				Type: syftPkg.NpmPkg, // we know this could not be a JVM package installation
				Name: "jdk",
			},
			expected: false,
		},
		{
			name: "package with JavaVMInstallationMetadata",
			pkg: Package{
				Type:     syftPkg.RpmPkg,
				Name:     "random-package",
				Metadata: JavaVMInstallationMetadata{},
			},
			expected: true,
		},
		{
			name: "package without JavaVMInstallationMetadata",
			pkg: Package{
				Type:     syftPkg.RpmPkg,
				Name:     "non-jvm-package",
				Metadata: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsJvmPackage(tt.pkg)
			assert.Equal(t, tt.expected, result)
		})
	}
}
