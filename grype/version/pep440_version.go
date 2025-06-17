package version

import (
	"fmt"

	goPepVersion "github.com/aquasecurity/go-pep440-version"
)

var _ Comparator = (*pep440Version)(nil)

type pep440Version struct {
	obj goPepVersion.Version
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

func (v pep440Version) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newPep440Version(other.Raw)
	if err != nil {
		return 0, err
	}

	return v.obj.Compare(o.obj), nil
}
