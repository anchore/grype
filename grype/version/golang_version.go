package version

import (
	"fmt"
	"regexp"
	"strings"

	hashiVer "github.com/anchore/go-version"
)

var _ Comparator = (*golangVersion)(nil)

// goGluedPrereleasePattern matches a version whose prerelease tag is glued directly onto the
// release with no "-" separator (e.g. "9.6.0b1"). Go modules never publish these — real tags are
// canonical semver ("v9.6.0-beta.1") — so such strings only reach us as non-canonical advisory
// data (e.g. a GHSA range bound). The tag begins with a letter right after the numeric version;
// a "-" (already-separated prerelease) or "+" (build metadata) does not match, so only otherwise
// unparseable versions are touched.
var goGluedPrereleasePattern = regexp.MustCompile(`^(v?\d+\.\d+(?:\.\d+)?)([a-zA-Z].*)$`)

type golangVersion struct {
	raw string
	obj *hashiVer.Version
}

func newGolangVersion(v string) (golangVersion, error) {
	if v == "(devel)" {
		return golangVersion{}, ErrUnsupportedVersion
	}

	// Invalid Semver fix ups

	// go stdlib is reported by syft as a go package with version like "go1.24.1"
	// other versions have "v" as a prefix, which the semver lib handles automatically
	fixedUp := strings.TrimPrefix(v, "go")

	// go1.24 creates non-dot separated build metadata fields, e.g. +incompatible+dirty
	// Fix up as per semver spec
	before, after, found := strings.Cut(fixedUp, "+")
	// insert the missing "-" before a glued-on prerelease tag (e.g. "9.6.0b1" -> "9.6.0-b1") so
	// non-canonical advisory version bounds compare instead of falling back to fuzzy matching.
	before = goGluedPrereleasePattern.ReplaceAllString(before, "$1-$2")
	if found {
		fixedUp = before + "+" + strings.ReplaceAll(after, "+", ".")
	} else {
		fixedUp = before
	}

	semver, err := hashiVer.NewSemver(fixedUp)
	if err != nil {
		return golangVersion{}, err
	}
	return golangVersion{
		raw: v,
		obj: semver,
	}, nil
}

func (v golangVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newGolangVersion(other.Raw)
	if err != nil {
		return 0, err
	}

	if o.raw == v.raw {
		return 0, nil
	}

	if o.raw == "(devel)" {
		return -1, fmt.Errorf("cannot compare a non-development version %q with a default development version of %q", v.raw, o.raw)
	}

	return v.compare(o), nil
}

func (v golangVersion) compare(o golangVersion) int {
	switch {
	case v.obj != nil && o.obj != nil:
		return v.obj.Compare(o.obj)
	case v.obj != nil && o.obj == nil:
		return 1
	case v.obj == nil && o.obj != nil:
		return -1
	default:
		return strings.Compare(v.raw, o.raw)
	}
}
