package version

import (
	"fmt"

	goPepVersion "github.com/aquasecurity/go-pep440-version"
)

var _ Comparator = (*pep440Version)(nil)

type pep440Version struct {
	obj goPepVersion.Version
}

func (p pep440Version) Compare(other *Version) (int, error) {
	if other.Format != PythonFormat {
		return -1, fmt.Errorf("unable to compare pep440 to given format: %s", other.Format)
	}
	if other.rich.pep440version == nil {
		return -1, fmt.Errorf("given empty pep440 object")
	}

	return other.rich.pep440version.obj.Compare(p.obj), nil
}

func newPep440Version(raw string) (pep440Version, error) {
	parsed, err := goPepVersion.Parse(raw)
	if err != nil {
		return pep440Version{}, fmt.Errorf("could not parse pep440 version: %w", err)
	}
	return pep440Version{
		obj: parsed,
	}, nil
}
