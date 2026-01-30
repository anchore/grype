package pkg

import (
	"github.com/anchore/grype/grype/version"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func VersionFormat(p Package) version.Format {
	switch p.Type {
	case syftPkg.ApkPkg:
		return version.ApkFormat
	case syftPkg.BitnamiPkg:
		return version.BitnamiFormat
	case syftPkg.DebPkg:
		return version.DebFormat
	case syftPkg.JavaPkg:
		return version.MavenFormat
	case syftPkg.RpmPkg:
		return version.RpmFormat
	case syftPkg.GemPkg:
		return version.GemFormat
	case syftPkg.PythonPkg:
		return version.PythonFormat
	case syftPkg.KbPkg:
		return version.KBFormat
	case syftPkg.PortagePkg:
		return version.PortageFormat
	case syftPkg.GoModulePkg:
		return version.GolangFormat
	case syftPkg.AlpmPkg:
		return version.PacmanFormat
	}

	if isJvmPackage(p) {
		return version.JVMFormat
	}

	return version.UnknownFormat
}
