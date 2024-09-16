package version

import (
	"strings"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
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
	JVMFormat
)

type Format int

var formatStr = []string{
	"Unknown",
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
	"JVM",
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
	GolangFormat,
	JVMFormat,
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
	case strings.ToLower(JVMFormat.String()), "jvm", "jre", "jdk", "openjdk", "jep223":
		return JVMFormat
	}
	return UnknownFormat
}

func FormatFromPkg(p pkg.Package) Format {
	switch p.Type {
	case syftPkg.ApkPkg:
		return ApkFormat
	case syftPkg.DebPkg:
		return DebFormat
	case syftPkg.JavaPkg:
		return MavenFormat
	case syftPkg.RpmPkg:
		return RpmFormat
	case syftPkg.GemPkg:
		return GemFormat
	case syftPkg.PythonPkg:
		return PythonFormat
	case syftPkg.KbPkg:
		return KBFormat
	case syftPkg.PortagePkg:
		return PortageFormat
	case syftPkg.GoModulePkg:
		return GolangFormat
	}

	if pkg.IsJvmPackage(p) {
		return JVMFormat
	}

	return UnknownFormat
}

func (f Format) String() string {
	if int(f) >= len(formatStr) || f < 0 {
		return formatStr[0]
	}

	return formatStr[f]
}
