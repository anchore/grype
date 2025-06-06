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
	rubyVer       *rubyVersion
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
		ver, err := newGemVersion(v.Raw)
		v.rich.rubyVer = ver
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

func (v Version) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	if other.Format == v.Format {
		return v.compareSameFormat(other)
	}

	// different formats, try to convert to a common format
	common, err := finalizeComparisonVersion(other, v.Format)
	if err != nil {
		return -1, err
	}

	return v.compareSameFormat(common)
}

func (v Version) compareSameFormat(other *Version) (int, error) {
	switch v.Format {
	case SemanticFormat:
		return v.rich.semVer.verObj.Compare(other.rich.semVer.verObj), nil
	case ApkFormat:
		return v.rich.apkVer.Compare(other)
	case DebFormat:
		return v.rich.debVer.Compare(other)
	case GolangFormat:
		return v.rich.golangVersion.Compare(other)
	case MavenFormat:
		return v.rich.mavenVer.Compare(other)
	case RpmFormat:
		return v.rich.rpmVer.Compare(other)
	case PythonFormat:
		return v.rich.pep440version.Compare(other)
	case KBFormat:
		return v.rich.kbVer.Compare(other)
	case GemFormat:
		return v.rich.rubyVer.Compare(other)
	case PortageFormat:
		return v.rich.portVer.Compare(other)
	case JVMFormat:
		return v.rich.jvmVersion.Compare(other)
	}

	v1, err := newFuzzyVersion(v.Raw)
	if err != nil {
		return -1, fmt.Errorf("unable to parse version (%s) as a fuzzy version: %w", v.Raw, err)
	}

	return v1.Compare(other)
}
