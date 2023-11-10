package version

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

const (
	UnknownFormat Format = iota
	SemanticFormat
	ApkFormat
	DebFormat
	MavenFormat
	RpmFormat
	PythonFormat
	KBFormat
	GemFormat
	PortageFormat
	GolangFormat
)

type Format int

var formatStr = []string{
	"UnknownFormat",
	"Semantic",
	"Apk",
	"Deb",
	"Maven",
	"RPM",
	"Python",
	"KB",
	"Gem",
	"Portage",
	"Go",
}

var Formats = []Format{
	SemanticFormat,
	ApkFormat,
	DebFormat,
	MavenFormat,
	RpmFormat,
	PythonFormat,
	KBFormat,
	GemFormat,
	PortageFormat,
}

func ParseFormat(userStr string) Format {
	switch strings.ToLower(userStr) {
	case strings.ToLower(SemanticFormat.String()), "semver":
		return SemanticFormat
	case strings.ToLower(ApkFormat.String()), "apk":
		return ApkFormat
	case strings.ToLower(DebFormat.String()), "dpkg":
		return DebFormat
	case strings.ToLower(GolangFormat.String()), "go":
		return GolangFormat
	case strings.ToLower(MavenFormat.String()), "maven":
		return MavenFormat
	case strings.ToLower(RpmFormat.String()), "rpm":
		return RpmFormat
	case strings.ToLower(PythonFormat.String()), "python":
		return PythonFormat
	case strings.ToLower(KBFormat.String()), "kb":
		return KBFormat
	case strings.ToLower(GemFormat.String()), "gem":
		return GemFormat
	case strings.ToLower(PortageFormat.String()), "portage":
		return PortageFormat
	}
	return UnknownFormat
}

func FormatFromPkgType(t pkg.Type) Format {
	var format Format
	switch t {
	case pkg.ApkPkg:
		format = ApkFormat
	case pkg.DebPkg:
		format = DebFormat
	case pkg.JavaPkg:
		format = MavenFormat
	case pkg.RpmPkg:
		format = RpmFormat
	case pkg.GemPkg:
		format = GemFormat
	case pkg.PythonPkg:
		format = PythonFormat
	case pkg.KbPkg:
		format = KBFormat
	case pkg.PortagePkg:
		format = PortageFormat
	case pkg.GoModulePkg:
		format = GolangFormat
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
