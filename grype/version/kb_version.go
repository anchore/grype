package version

import (
	"fmt"
	"reflect"
)

type kbVersion struct {
	version string
}

func newKBVersion(raw string) kbVersion {
	// XXX Is this even useful/necessary?
	return kbVersion{
		version: raw,
	}
}

func (v *kbVersion) Compare(other *Version) (int, error) {
	if other.Format != KBFormat {
		return -1, fmt.Errorf("unable to compare kb to given format: %s", other.Format)
	}
	if other.rich.kbVer == nil {
		return -1, fmt.Errorf("given empty kbVersion object")
	}

	return other.rich.kbVer.compare(*v), nil
}

// Compare returns 0 if v == v2, 1 otherwise
func (v kbVersion) compare(v2 kbVersion) int {
	if reflect.DeepEqual(v, v2) {
		return 0
	}
	return 1
}

func (v kbVersion) String() string {
	return v.version
}
