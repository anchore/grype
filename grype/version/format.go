package version

import (
	"strings"

	"github.com/anchore/packageurl-go"
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
	JVMFormat
	BitnamiFormat
	PacmanFormat
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
	"Bitnami",
	"Pacman",
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
	BitnamiFormat,
	PacmanFormat,
}

func ParseFormat(userStr string) Format {
	switch strings.ToLower(userStr) {
	// sever includes known ecosystem types that use semver or a very semver-like schemes
	case strings.ToLower(SemanticFormat.String()), "semver", packageurl.TypeNPM, packageurl.TypeNuget, packageurl.TypeComposer, packageurl.TypeHex, packageurl.TypePub, packageurl.TypeSwift, packageurl.TypeConan, packageurl.TypeCocoapods, packageurl.TypeHackage:
		return SemanticFormat
	case strings.ToLower(ApkFormat.String()), "apk", pkg.ApkPkg.String():
		return ApkFormat
	case strings.ToLower(BitnamiFormat.String()), "bitnami", pkg.BitnamiPkg.String():
		return BitnamiFormat
	case strings.ToLower(DebFormat.String()), "dpkg", packageurl.TypeDebian, pkg.DebPkg.String():
		return DebFormat
	case strings.ToLower(GolangFormat.String()), "go", packageurl.TypeGolang, pkg.GoModulePkg.String():
		return GolangFormat
	case strings.ToLower(MavenFormat.String()), "maven", pkg.JavaPkg.String(), pkg.JenkinsPluginPkg.String():
		return MavenFormat
	case strings.ToLower(RpmFormat.String()), "rpm", pkg.RpmPkg.String():
		return RpmFormat
	case strings.ToLower(PythonFormat.String()), "python", packageurl.TypePyPi, "pep440", pkg.PythonPkg.String():
		return PythonFormat
	case strings.ToLower(KBFormat.String()), "kb", pkg.KbPkg.String():
		return KBFormat
	case strings.ToLower(GemFormat.String()), "gem", pkg.GemPkg.String():
		return GemFormat
	case strings.ToLower(PortageFormat.String()), "portage", pkg.PortagePkg.String():
		return PortageFormat
	case strings.ToLower(JVMFormat.String()), "jvm", "jre", "jdk", "openjdk", "jep223":
		return JVMFormat
	case strings.ToLower(PacmanFormat.String()), "pacman", pkg.AlpmPkg.String():
		return PacmanFormat
	}
	return UnknownFormat
}

func (f Format) String() string {
	if int(f) >= len(formatStr) || f < 0 {
		return formatStr[0]
	}

	return formatStr[f]
}
