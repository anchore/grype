package version

import (
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
)

const (
	UnknownFormat Format = iota
	SemanticFormat
	DpkgFormat
	Cpe23Format
)

type Format int

var formatStr = []string{
	"UnknownFormat",
	"Semantic",
	"Dpkg",
	"Cpe2.3",
}

var Formats = []Format{
	SemanticFormat,
	DpkgFormat,
	Cpe23Format,
}

func ParseFormat(userStr string) Format {
	switch strings.ToLower(userStr) {
	case strings.ToLower(SemanticFormat.String()), "semver":
		return SemanticFormat
	case strings.ToLower(DpkgFormat.String()), "deb":
		return DpkgFormat
	case strings.ToLower(Cpe23Format.String()), "cpe23":
		return Cpe23Format
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
	case pkg.EggPkg:
		format = SemanticFormat
	case pkg.WheelPkg:
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
