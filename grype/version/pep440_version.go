package version

import (
	goPepVersion "github.com/aquasecurity/go-pep440-version"
)

var _ Comparator = (*pep440Version)(nil)

type pep440Version struct {
	// public is the public portion of the version (without local segment), used for most comparisons
	public goPepVersion.Version
	// full is the complete parsed version including local segment, used when constraint has local
	full goPepVersion.Version
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
		public: public,
		full:   parsed,
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

	result := v.public.Compare(o.public)
	if result != 0 {
		return result, nil
	}

	// Public portions are equal - handle local version segments per PEP 440 specifier semantics.
	// If constraint has no local segment, ignore package's local (they're equal).
	// If constraint has a local segment, require exact match.
	if o.full.Local() == "" {
		return 0, nil
	}

	return v.full.Compare(o.full), nil
}
