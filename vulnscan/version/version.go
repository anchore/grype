package version

import (
	"fmt"

	hashiVer "github.com/anchore/go-version"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/cpe"
	deb "github.com/knqyf263/go-deb-version"
)

type Version struct {
	Raw    string
	Format Format
	rich   rich
}

type rich struct {
	semVer  *hashiVer.Version
	dpkgVer *deb.Version
	cpeVers []cpe.CPE
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
		version, err := newSemanticVersion(v.Raw)
		v.rich.semVer = version
		return err
	case DpkgFormat:
		version, err := newDpkgVersion(v.Raw)
		v.rich.dpkgVer = version
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
