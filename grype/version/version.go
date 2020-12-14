package version

import (
	"fmt"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Version struct {
	Raw    string
	Format Format
	rich   rich
}

type rich struct {
	cpeVers []syftPkg.CPE
	semVer  *semanticVersion
	debVer  *debVersion
	rpmVer  *rpmVersion
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
	ver, err := NewVersion(p.Version, FormatFromPkgType(p.Type))
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
	case DebFormat:
		ver, err := newDebVersion(v.Raw)
		v.rich.debVer = ver
		return err
	case RpmFormat:
		ver, err := newRpmVersion(v.Raw)
		v.rich.rpmVer = &ver
		return err
	case PythonFormat:
		// use the fuzzy constraint
		return nil
	case UnknownFormat:
		// use the raw string + fuzzy constraint
		return nil
	}
	return fmt.Errorf("no rich version populated (format=%s)", v.Format)
}

func (v Version) CPEs() []syftPkg.CPE {
	return v.rich.cpeVers
}

func (v Version) String() string {
	return fmt.Sprintf("%s (%s)", v.Raw, v.Format)
}
