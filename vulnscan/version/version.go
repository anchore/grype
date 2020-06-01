package version

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/pkg"
	hashiVer "github.com/hashicorp/go-version"
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
	var format Format
	switch p.Type {
	case pkg.DebPkg:
		format = DpkgFormat
	// ...
	default:
		format = UnknownFormat
	}
	return NewVersion(p.Version, format)
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
