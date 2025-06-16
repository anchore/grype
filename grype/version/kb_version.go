package version

import (
	"reflect"
)

var _ Comparator = (*kbVersion)(nil)

type kbVersion struct {
	version string
}

func newKBVersion(raw string) kbVersion {
	return kbVersion{
		version: raw,
	}
}

func (v kbVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	if o, ok := other.comparator.(kbVersion); ok {
		return v.compare(o), nil
	}

	return -1, newNotComparableError(KBFormat, other)
}

// Compare returns 0 if v == v2, 1 otherwise
func (v kbVersion) compare(other kbVersion) int {
	if reflect.DeepEqual(v, other) {
		return 0
	}

	return 1
}

func (v kbVersion) String() string {
	return v.version
}
