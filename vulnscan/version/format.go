package version

import (
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
)

const (
	UnknownFormat Format = iota
	SemanticFormat
	DpkgFormat
)

type Format int

var formatStr = []string{
	"UnknownFormat",
	"Semantic",
	"Dpkg",
}

var Formats = []Format{
	SemanticFormat,
	DpkgFormat,
}

func ParseFormat(userStr string) Format {
	switch strings.ToLower(userStr) {
	case strings.ToLower(SemanticFormat.String()), "semver":
		return SemanticFormat
	case strings.ToLower(DpkgFormat.String()), "deb":
		return DpkgFormat
	}
	return UnknownFormat
}

func FormatFromPkgType(t pkg.Type) Format {
	var format Format
	switch t {
	case pkg.DebPkg:
		format = DpkgFormat
	case pkg.BundlerPkg:
		format = SemanticFormat
	default:
		format = UnknownFormat
	}
	return format
}

func (f Format) String() string {
	if int(f) >= len(formatStr) || f < 0 {
		return formatStr[0]
	}

	return formatStr[f]
}
