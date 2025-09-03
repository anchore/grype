package version

import (
	"github.com/anchore/packageurl-go"
	"strings"
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
}

func ParseFormat(userStr string) Format {
	switch strings.ToLower(userStr) {
	// sever includes known ecosystem types that use semver or a very semver-like schemes
	case strings.ToLower(SemanticFormat.String()), "semver", packageurl.TypeNPM, packageurl.TypeNuget, packageurl.TypeComposer, packageurl.TypeHex, packageurl.TypePub, packageurl.TypeSwift, packageurl.TypeConan, packageurl.TypeCocoapods, packageurl.TypeHackage:
		return SemanticFormat
	case strings.ToLower(ApkFormat.String()), "apk":
		return ApkFormat
	case strings.ToLower(BitnamiFormat.String()), "bitnami":
		return BitnamiFormat
	case strings.ToLower(DebFormat.String()), "dpkg", packageurl.TypeDebian:
		return DebFormat
	case strings.ToLower(GolangFormat.String()), "go", packageurl.TypeGolang:
		return GolangFormat
	case strings.ToLower(MavenFormat.String()), "maven":
		return MavenFormat
	case strings.ToLower(RpmFormat.String()), "rpm":
		return RpmFormat
	case strings.ToLower(PythonFormat.String()), "python", packageurl.TypePyPi, "pep440":
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

func (f Format) String() string {
	if int(f) >= len(formatStr) || f < 0 {
		return formatStr[0]
	}

	return formatStr[f]
}
