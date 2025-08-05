package pkg

import (
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/version"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestVersionFormat(t *testing.T) {
	tests := []struct {
		name   string
		p      Package
		format version.Format
	}{
		{
			name: "bitnami",
			p: Package{
				Type: syftPkg.BitnamiPkg,
			},
			format: version.BitnamiFormat,
		},
		{
			name: "deb",
			p: Package{
				Type: syftPkg.DebPkg,
			},
			format: version.DebFormat,
		},
		{
			name: "java jar",
			p: Package{
				Type: syftPkg.JavaPkg,
			},
			format: version.MavenFormat,
		},
		{
			name: "gem",
			p: Package{
				Type: syftPkg.GemPkg,
			},
			format: version.GemFormat,
		},
		{
			name: "jvm by metadata",
			p: Package{
				Metadata: JavaVMInstallationMetadata{},
			},
			format: version.JVMFormat,
		},
		{
			name: "jvm by type and name (jdk)",
			p: Package{
				Type: syftPkg.BinaryPkg,
				Name: "jdk",
			},
			format: version.JVMFormat,
		},
		{
			name: "jvm by type and name (openjdk)",
			p: Package{
				Type: syftPkg.BinaryPkg,
				Name: "openjdk",
			},
			format: version.JVMFormat,
		},
		{
			name: "jvm by type and name (jre)",
			p: Package{
				Type: syftPkg.BinaryPkg,
				Name: "jre",
			},
			format: version.JVMFormat,
		},
		{
			name: "jvm by type and name (java_se)",
			p: Package{
				Type: syftPkg.BinaryPkg,
				Name: "java_se",
			},
			format: version.JVMFormat,
		},
	}

	for _, test := range tests {
		name := fmt.Sprintf("pkgType[%s]->format[%s]", test.p.Type, test.format)
		t.Run(name, func(t *testing.T) {
			actual := VersionFormat(test.p)
			if actual != test.format {
				t.Errorf("mismatched pkgType->format mapping, pkgType='%s': '%s'!='%s'", test.p.Type, test.format, actual)
			}
		})
	}
}
