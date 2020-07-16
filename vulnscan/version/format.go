package version

import (
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
)

const (
	UnknownFormat Format = iota
	SemanticFormat
	DebFormat
	RpmFormat
)

type Format int

var formatStr = []string{
	"UnknownFormat",
	"Semantic",
	"Deb",
	"RPM",
}

var Formats = []Format{
	SemanticFormat,
	DebFormat,
	RpmFormat,
}

func ParseFormat(userStr string) Format {
	switch strings.ToLower(userStr) {
	case strings.ToLower(SemanticFormat.String()), "semver":
		return SemanticFormat
	case strings.ToLower(DebFormat.String()), "dpkg":
		return DebFormat
	case strings.ToLower(RpmFormat.String()), "rpmdb":
		return RpmFormat
	}
	return UnknownFormat
}

func FormatFromPkgType(t pkg.Type) Format {
	var format Format
	switch t {
	case pkg.DebPkg:
		format = DebFormat
	case pkg.RpmPkg:
		format = RpmFormat
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
