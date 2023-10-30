package version

import (
	"fmt"
	"testing"

	"github.com/anchore/syft/syft/pkg"
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
		pkgType pkg.Type
		format  Format
	}{
		{
			pkgType: pkg.DebPkg,
			format:  DebFormat,
		},
		{
			pkgType: pkg.JavaPkg,
			format:  MavenFormat,
		},
		{
			pkgType: pkg.GemPkg,
			format:  GemFormat,
		},
	}

	for _, test := range tests {
		name := fmt.Sprintf("pkgType[%s]->format[%s]", test.pkgType, test.format)
		t.Run(name, func(t *testing.T) {
			actual := FormatFromPkgType(test.pkgType)
			if actual != test.format {
				t.Errorf("mismatched pkgType->format mapping, pkgType='%s': '%s'!='%s'", test.pkgType, test.format, actual)
			}
		})
	}
}
