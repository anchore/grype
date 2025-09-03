package version

import (
	"fmt"
	"testing"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input  string
		format Format
	}{
		// SemanticFormat cases
		{
			input:  "semantic",
			format: SemanticFormat,
		},
		{
			input:  "semver",
			format: SemanticFormat,
		},
		{
			input:  "npm",
			format: SemanticFormat,
		},
		{
			input:  "nuget",
			format: SemanticFormat,
		},
		{
			input:  "composer",
			format: SemanticFormat,
		},
		{
			input:  "hex",
			format: SemanticFormat,
		},
		{
			input:  "pub",
			format: SemanticFormat,
		},
		{
			input:  "swift",
			format: SemanticFormat,
		},
		{
			input:  "conan",
			format: SemanticFormat,
		},
		{
			input:  "cocoapods",
			format: SemanticFormat,
		},
		{
			input:  "hackage",
			format: SemanticFormat,
		},
		// ApkFormat cases
		{
			input:  "apk",
			format: ApkFormat,
		},
		// BitnamiFormat cases
		{
			input:  "bitnami",
			format: BitnamiFormat,
		},
		// DebFormat cases
		{
			input:  "deb",
			format: DebFormat,
		},
		{
			input:  "dpkg",
			format: DebFormat,
		},
		// GolangFormat cases
		{
			input:  "golang",
			format: GolangFormat,
		},
		{
			input:  "go",
			format: GolangFormat,
		},
		// MavenFormat cases
		{
			input:  "maven",
			format: MavenFormat,
		},
		// RpmFormat cases
		{
			input:  "rpm",
			format: RpmFormat,
		},
		// PythonFormat cases
		{
			input:  "python",
			format: PythonFormat,
		},
		{
			input:  "pypi",
			format: PythonFormat,
		},
		{
			input:  "pep440",
			format: PythonFormat,
		},
		// KBFormat cases
		{
			input:  "kb",
			format: KBFormat,
		},
		// GemFormat cases
		{
			input:  "gem",
			format: GemFormat,
		},
		// PortageFormat cases
		{
			input:  "portage",
			format: PortageFormat,
		},
		// JVMFormat cases
		{
			input:  "jvm",
			format: JVMFormat,
		},
		{
			input:  "jre",
			format: JVMFormat,
		},
		{
			input:  "jdk",
			format: JVMFormat,
		},
		{
			input:  "openjdk",
			format: JVMFormat,
		},
		{
			input:  "jep223",
			format: JVMFormat,
		},
		// UnknownFormat case
		{
			input:  "unknown",
			format: UnknownFormat,
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
