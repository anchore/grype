package version

import (
	"fmt"

	hashiVer "github.com/anchore/go-version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/vulnscan/vulnscan/cpe"
	deb "github.com/knqyf263/go-deb-version"
)

type Version struct {
	Raw    string
	Format Format
	rich   rich
}

type rich struct {
	cpeVers []cpe.CPE
	semVer  *hashiVer.Version
	debVer  *deb.Version
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

func NewVersionFromPkg(p *pkg.Package) (*Version, error) {
	ver, err := NewVersion(p.Version, FormatFromPkgType(p.Type))
	if err != nil {
		return nil, err
	}
	cpes, err := cpe.Generate(p)
	if err != nil {
		return nil, err
	}

	ver.rich.cpeVers = cpes
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
