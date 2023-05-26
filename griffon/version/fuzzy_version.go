package version

import (
	"fmt"
)

type fuzzyVersion struct {
	semVer *semanticVersion
	raw    string
}

//nolint:unparam
func newFuzzyVersion(raw string) (fuzzyVersion, error) {
	var semVer *semanticVersion

	candidate, err := newSemanticVersion(raw)
	if err == nil {
		semVer = candidate
	}

	return fuzzyVersion{
		semVer: semVer,
		raw:    raw,
	}, nil
}

func (v *fuzzyVersion) Compare(other *Version) (int, error) {
	// check if both versions can be compared as semvers...
	if other.Format == SemanticFormat && v.semVer != nil {
		if other.rich.semVer == nil {
			return -1, fmt.Errorf("given empty semver object (fuzzy)")
		}
		return other.rich.semVer.verObj.Compare(v.semVer.verObj), nil
	}

	// one or both are no semver compliant, use fuzzy comparison
	return fuzzyVersionComparison(other.Raw, v.raw), nil
}
