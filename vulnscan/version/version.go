package version

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/cpe"
	deb "github.com/knqyf263/go-deb-version"
	hashiVer "github.com/knqyf263/go-version"
)


type Version struct {
	Raw    string
	Format Format
	rich   rich
}

type rich struct {
	semVer  *hashiVer.Version
	dpkgVer *deb.Version
	cpeVers []cpe.CPE // CPEs have additional fields, so allow array here for testing combinations of vendor and product tuples
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
	return NewVersion(p.Version, FormatFromPkgType(p.Type))
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
	}
	return fmt.Errorf("no rich version populated (format=%s)", v.Format)
}

func (v Version) String() string {
	return fmt.Sprintf("%s (%s)", v.Raw, v.Format)
}
