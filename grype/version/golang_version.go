package version

import (
	"fmt"
	"regexp"
	"strings"

	hashiVer "github.com/anchore/go-version"
)

var _ Comparator = (*golangVersion)(nil)

type golangVersion struct {
	raw              string
	semVer           *hashiVer.Version
	timestamp        string
	commitSHA        string
	incompatibleFlag bool
}

func (g golangVersion) Compare(version *Version) (int, error) {
	if version.Format != GolangFormat {
		return -1, fmt.Errorf("cannot compare %v to golang version", version.Format)
	}
	if version.rich.golangVersion == nil {
		return -1, fmt.Errorf("cannot compare version with nil golang version to golang version")
	}
	if version.rich.golangVersion.raw == g.raw {
		return 0, nil
	}

	return version.rich.golangVersion.compare(g), nil
}

func (g golangVersion) compare(o golangVersion) int {
	switch {
	case g.semVer != nil && o.semVer != nil:
		return g.semVer.Compare(o.semVer)
	case g.semVer != nil && o.semVer == nil:
		return 1
	case g.semVer == nil && o.semVer != nil:
		return -1
	default:
		return strings.Compare(g.timestamp, o.timestamp)
	}
}

var startsWithSemver = regexp.MustCompile(`(v|go){0,1}\d+\.\d+\.\d+`)

func newGolangVersion(v string) (*golangVersion, error) {
	if !startsWithSemver.MatchString(v) {
		return nil, fmt.Errorf("%s is not a go version", v)
	}
	result := &golangVersion{
		raw: v,
	}
	version, incompatible := strings.CutSuffix(v, "+incompatible")
	zeroZeroSuffix, untagged := strings.CutPrefix(v, "v0.0.0-")
	if untagged {
		parts := strings.Split(zeroZeroSuffix, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s is not a valid golang version", v)
		}
		result.timestamp = parts[0]
		result.commitSHA = parts[1]
		return result, nil
	}
	result.incompatibleFlag = incompatible

	if semver, err := hashiVer.NewSemver(strings.TrimPrefix(version, "v")); err == nil {
		result.semVer = semver
	}

	return result, nil
}
