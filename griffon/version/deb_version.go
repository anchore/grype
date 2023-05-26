package version

import (
	"fmt"

	deb "github.com/knqyf263/go-deb-version"
)

type debVersion struct {
	obj deb.Version
}

func newDebVersion(raw string) (*debVersion, error) {
	ver, err := deb.NewVersion(raw)
	if err != nil {
		return nil, err
	}
	return &debVersion{
		obj: ver,
	}, nil
}

func (d *debVersion) Compare(other *Version) (int, error) {
	if other.Format != DebFormat {
		return -1, fmt.Errorf("unable to compare deb to given format: %s", other.Format)
	}
	if other.rich.debVer == nil {
		return -1, fmt.Errorf("given empty debVersion object")
	}

	return other.rich.debVer.obj.Compare(d.obj), nil
}
