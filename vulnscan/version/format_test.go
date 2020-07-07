package version

import (
	"fmt"
	"testing"

	"github.com/anchore/imgbom/imgbom/pkg"
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
			pkgType: pkg.BundlerPkg,
			format:  SemanticFormat,
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

	// TODO: once all pkgs are added, make this fail
	if len(tests) != len(pkg.AllPkgs) {
		t.Log("may have missed testing a pkgType -> version.Format test case")
	}
}
