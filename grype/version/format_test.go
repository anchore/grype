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
		{
			input:  "dpkg",
			format: DebFormat,
		},
		{
			input:  "bitnami",
			format: BitnamiFormat,
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
