package version

import "github.com/anchore/grype/internal"

var _ Comparator = (*fuzzyVersion)(nil)

type fuzzyVersion struct {
	semVer *semanticVersion
	raw    string
}

//nolint:unparam
func newFuzzyVersion(raw string) (fuzzyVersion, error) {
	var semVer *semanticVersion

	// we need to be a little more strict here than the hashcorp lib, but not as strict as the semver spec.
	// a good example of this is being able to reason about openssl versions like "1.0.2k" or "1.0.2l" which are
	// not semver compliant, but we still want to be able to compare them. But the hashicorp lib will not parse
	// the postfix letter as a prerelease version, which is wrong. In these cases we want a true fuzzy version
	// comparison.
	if pseudoSemverPattern.MatchString(raw) {
		candidate, err := newSemanticVersion(raw, false)
		if err == nil {
			semVer = &candidate
		}
	}

	return fuzzyVersion{
		semVer: semVer,
		raw:    raw,
	}, nil
}

func (v fuzzyVersion) acceptsFormats() *internal.OrderedSet[Format] {
	return internal.NewOrderedSet(SemanticFormat, UnknownFormat)
}

func (v fuzzyVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	// check if both versions can be compared as semvers...
	switch o := other.comparator.(type) {
	case semanticVersion:
		if o.obj == nil {
			break
		}
		if v.semVer == nil || v.semVer.obj == nil {
			break
		}
		return v.semVer.obj.Compare(o.obj), nil
	case fuzzyVersion:
		if o.semVer == nil || o.semVer.obj == nil {
			break
		}
		if v.semVer == nil || v.semVer.obj == nil {
			break
		}
		return v.semVer.obj.Compare(o.semVer.obj), nil
	}

	// one or both are no semver compliant, use fuzzy comparison
	return fuzzyVersionComparison(v.raw, other.Raw), nil
}
