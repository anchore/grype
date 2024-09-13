package version

import (
	"fmt"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/cpe"
)

// ErrUnsupportedVersion is returned when a version string cannot be parsed into a rich version object
// for a known unsupported case (e.g. golang "devel" version).
var ErrUnsupportedVersion = fmt.Errorf("unsupported version value")

type Version struct {
	Raw    string
	Format Format
	rich   rich
}

type rich struct {
	cpeVers       []cpe.CPE
	semVer        *semanticVersion
	apkVer        *apkVersion
	debVer        *debVersion
	golangVersion *golangVersion
	mavenVer      *mavenVersion
	rpmVer        *rpmVersion
	kbVer         *kbVersion
	portVer       *portageVersion
	pep440version *pep440Version
	jvmVersion    *jvmVersion
}

func NewVersion(raw string, format Format) (*Version, error) {
	version := &Version{
		Raw:    raw,
		Format: format,
	}

	err := version.populate()
	if err != nil {
		return nil, err
	}

	return version, nil
}

func NewVersionFromPkg(p pkg.Package) (*Version, error) {
	format := FormatFromPkg(p)

	ver, err := NewVersion(p.Version, format)
	if err != nil {
		return nil, err
	}

	ver.rich.cpeVers = p.CPEs
	return ver, nil
}

func (v *Version) populate() error {
	switch v.Format {
	case SemanticFormat:
		ver, err := newSemanticVersion(v.Raw)
		v.rich.semVer = ver
		return err
	case ApkFormat:
		ver, err := newApkVersion(v.Raw)
		v.rich.apkVer = ver
		return err
	case DebFormat:
		ver, err := newDebVersion(v.Raw)
		v.rich.debVer = ver
		return err
	case GolangFormat:
		ver, err := newGolangVersion(v.Raw)
		v.rich.golangVersion = ver
		return err
	case MavenFormat:
		ver, err := newMavenVersion(v.Raw)
		v.rich.mavenVer = ver
		return err
	case RpmFormat:
		ver, err := newRpmVersion(v.Raw)
		v.rich.rpmVer = &ver
		return err
	case PythonFormat:
		ver, err := newPep440Version(v.Raw)
		v.rich.pep440version = &ver
		return err
	case KBFormat:
		ver := newKBVersion(v.Raw)
		v.rich.kbVer = &ver
		return nil
	case GemFormat:
		ver, err := newGemfileVersion(v.Raw)
		v.rich.semVer = ver
		return err
	case PortageFormat:
		ver := newPortageVersion(v.Raw)
		v.rich.portVer = &ver
		return nil
	case JVMFormat:
		ver, err := newJvmVersion(v.Raw)
		v.rich.jvmVersion = ver
		return err
	case UnknownFormat:
		// use the raw string + fuzzy constraint
		return nil
	}

	return fmt.Errorf("no rich version populated (format=%s)", v.Format)
}

func (v Version) CPEs() []cpe.CPE {
	return v.rich.cpeVers
}

func (v Version) String() string {
	return fmt.Sprintf("%s (%s)", v.Raw, v.Format)
}
