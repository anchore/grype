package version

var _ Comparator = (*fuzzyVersion)(nil)

type fuzzyVersion struct {
	semVer *semanticVersion
	raw    string
}

//nolint:unparam
func newFuzzyVersion(raw string) (fuzzyVersion, error) {
	return fuzzyVersion{
		semVer: newFuzzySemver(raw),
		raw:    raw,
	}, nil
}

func (v fuzzyVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	semver := newFuzzySemver(other.Raw)
	if semver != nil && v.semVer != nil && v.semVer.obj != nil && semver.obj != nil {
		return v.semVer.obj.Compare(semver.obj), nil
	}

	// one or both are no semver compliant, use fuzzy comparison
	return fuzzyVersionComparison(v.raw, other.Raw), nil
}

func newFuzzySemver(raw string) *semanticVersion {
	// we need to be a little more strict here than the hashicorp lib, but not as strict as the semver spec.
	// a good example of this is being able to reason about openssl versions like "1.0.2k" or "1.0.2l" which are
	// not semver compliant, but we still want to be able to compare them. But the hashicorp lib will not parse
	// the postfix letter as a prerelease version, which is wrong. In these cases we want a true fuzzy version
	// comparison.
	if pseudoSemverPattern.MatchString(raw) {
		candidate, err := newSemanticVersion(raw, false)
		if err == nil {
			return &candidate
		}
	}

	return nil
}
