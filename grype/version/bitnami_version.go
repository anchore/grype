package version

import (
	"fmt"
	"strings"

	bitnami "github.com/bitnami/go-version/pkg/version"

	hashiVer "github.com/anchore/go-version"
)

var _ Comparator = (*bitnamiVersion)(nil)

type bitnamiVersion struct {
	obj *hashiVer.Version
}

func newBitnamiVersion(raw string) (bitnamiVersion, error) {
	bv, err := bitnami.Parse(raw)
	if err != nil {
		fmtErr := err
		verObj, err := hashiVer.NewVersion(raw)
		if err != nil {
			return bitnamiVersion{}, invalidFormatError(BitnamiFormat, raw, fmtErr)
		}
		var segments []string
		for _, segment := range verObj.Segments() {
			segments = append(segments, fmt.Sprintf("%d", segment))
		}
		// drop any pre-release info
		raw = strings.Join(segments, ".")
	} else {
		raw = fmt.Sprintf("%d.%d.%d", bv.Major(), bv.Minor(), bv.Patch())
	}

	// We can't assume Bitnami revisions can potentially address a
	// known vulnerability given Bitnami package revisions use
	// exactly the same upstream source code used to create the
	// previous version. Then, we discard it.
	verObj, err := hashiVer.NewVersion(raw)
	if err != nil {
		return bitnamiVersion{}, invalidFormatError(BitnamiFormat, raw, err)
	}
	return bitnamiVersion{
		obj: verObj,
	}, nil
}

func (v bitnamiVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	bv, err := newBitnamiVersion(other.Raw)

	if err != nil {
		return 0, err
	}

	return v.obj.Compare(bv.obj), nil
}
