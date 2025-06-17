package version

import (
	"fmt"
	"regexp"
	"strings"

	hashiVer "github.com/anchore/go-version"
)

var _ Comparator = (*semanticVersion)(nil)

// semverPrereleaseNormalizer are meant to replace common pre-release suffixes with standard semver pre-release suffixes.
// this is primarily intended for to cover ruby packages such as activerecord and sprockets, which don't strictly
// follow semver, however, this can generally be applied to other cases using semver as well.
// note: this may result in missed matches for versioned betas
var semverPrereleaseNormalizer = strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc")

type semanticVersion struct {
	obj *hashiVer.Version
}

var versionStartsWithV = regexp.MustCompile(`^v\d+`)

func newSemanticVersion(raw string, strict bool) (semanticVersion, error) {
	clean := semverPrereleaseNormalizer.Replace(raw)

	var verObj *hashiVer.Version
	var err error
	if strict {
		// we still want v-prefix processing
		if versionStartsWithV.MatchString(clean) {
			clean = strings.TrimPrefix(clean, "v")
		}
		verObj, err = hashiVer.NewSemver(clean)
	} else {
		verObj, err = hashiVer.NewVersion(clean)
	}
	if err != nil {
		return semanticVersion{}, fmt.Errorf("unable to create semver obj: %w", err)
	}
	return semanticVersion{
		obj: verObj,
	}, nil
}

func (v semanticVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newSemanticVersion(other.Raw, false)
	if err != nil {
		return 0, err
	}
	return v.obj.Compare(o.obj), nil
}
