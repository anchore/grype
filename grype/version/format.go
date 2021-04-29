package version

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

const (
	UnknownFormat Format = iota
	SemanticFormat
	DebFormat
	RpmFormat
	PythonFormat
	KBFormat
)

type Format int

var formatStr = []string{
	"UnknownFormat",
	"Semantic",
	"Deb",
	"RPM",
	"Python",
	"KB",
}

var Formats = []Format{
	SemanticFormat,
	DebFormat,
	RpmFormat,
	PythonFormat,
	KBFormat,
}

func ParseFormat(userStr string) Format {
	switch strings.ToLower(userStr) {
	case strings.ToLower(SemanticFormat.String()), "semver":
		return SemanticFormat
	case strings.ToLower(DebFormat.String()), "dpkg":
		return DebFormat
	case strings.ToLower(RpmFormat.String()), "rpmdb":
		return RpmFormat
	case strings.ToLower(PythonFormat.String()), "python":
		return PythonFormat
	case strings.ToLower(KBFormat.String()), "kb":
		return KBFormat
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
	case pkg.GemPkg:
		format = SemanticFormat
	case pkg.PythonPkg:
		format = PythonFormat
	case pkg.KbPkg:
		format = KBFormat
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
