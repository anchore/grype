package version

import (
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input  string
		format Format
	}{
		{
			input:  "dpkg",
			format: DebFormat,
		},
		{
			input:  "maven",
			format: MavenFormat,
		},
		{
			input:  "gem",
			format: GemFormat,
		},
		{
			input:  "deb",
			format: DebFormat,
		},
		{
			input:  "semantic",
			format: SemanticFormat,
		},
		{
			input:  "semver",
			format: SemanticFormat,
		},
	}

	for _, test := range tests {
		name := fmt.Sprintf("'%s'->format[%s]", test.input, test.format)
		t.Run(name, func(t *testing.T) {
			actual := ParseFormat(test.input)
			if actual != test.format {
				t.Errorf("mismatched user string -> format mapping, pkgType='%s': '%s'!='%s'", test.input, test.format, actual)
			}
		})
	}
}

func TestFormatFromPkgType(t *testing.T) {
	tests := []struct {
		name   string
		p      pkg.Package
		format Format
	}{
		{
			name: "deb",
			p: pkg.Package{
				Type: syftPkg.DebPkg,
			},
			format: DebFormat,
		},
		{
			name: "java jar",
			p: pkg.Package{
				Type: syftPkg.JavaPkg,
			},
			format: MavenFormat,
		},
		{
			name: "gem",
			p: pkg.Package{
				Type: syftPkg.GemPkg,
			},
			format: GemFormat,
		},
		{
			name: "jvm by metadata",
			p: pkg.Package{
				Metadata: pkg.JavaVMInstallationMetadata{},
			},
			format: JVMFormat,
		},
		{
			name: "jvm by type and name (jdk)",
			p: pkg.Package{
				Type: syftPkg.BinaryPkg,
				Name: "jdk",
			},
			format: JVMFormat,
		},
		{
			name: "jvm by type and name (openjdk)",
			p: pkg.Package{
				Type: syftPkg.BinaryPkg,
				Name: "openjdk",
			},
			format: JVMFormat,
		},
		{
			name: "jvm by type and name (jre)",
			p: pkg.Package{
				Type: syftPkg.BinaryPkg,
				Name: "jre",
			},
			format: JVMFormat,
		},
		{
			name: "jvm by type and name (java_se)",
			p: pkg.Package{
				Type: syftPkg.BinaryPkg,
				Name: "java_se",
			},
			format: JVMFormat,
		},
	}

	for _, test := range tests {
		name := fmt.Sprintf("pkgType[%s]->format[%s]", test.p.Type, test.format)
		t.Run(name, func(t *testing.T) {
			actual := FormatFromPkg(test.p)
			if actual != test.format {
				t.Errorf("mismatched pkgType->format mapping, pkgType='%s': '%s'!='%s'", test.p.Type, test.format, actual)
			}
		})
	}
}
