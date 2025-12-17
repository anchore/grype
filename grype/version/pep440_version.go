package version

import (
	goPepVersion "github.com/aquasecurity/go-pep440-version"
)

var _ Comparator = (*pep440Version)(nil)

type pep440Version struct {
	obj goPepVersion.Version
}

func newPep440Version(raw string) (pep440Version, error) {
	// lets ensure this is a valid PEP 440 version
	parsed, err := goPepVersion.Parse(raw)
	if err != nil {
		return pep440Version{}, invalidFormatError(SemanticFormat, raw, err)
	}

	// we want to use the "public" portion of the version for comparison purposes (for specifier matching, not local versions).
	// Note per PEP 440:
	//   <public version identifier>[+<local version label>]
	// see:
	// - https://peps.python.org/pep-0440/#public-version-identifiers
	// - https://peps.python.org/pep-0440/#local-version-identifiers
	//
	// This means that for a version like "1.0.0+abc.1", we only want to consider "1.0.0" for comparison purposes.
	public, err := goPepVersion.Parse(parsed.Public())
	if err != nil {
		return pep440Version{}, invalidFormatError(SemanticFormat, raw, err)
	}
	return pep440Version{
		obj: public,
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
