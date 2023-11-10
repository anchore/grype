package version

import (
	"fmt"
	"regexp"
	"strings"

	hashiVer "github.com/anchore/go-version"
)

type golangVersion struct {
	raw              string
	semVer           *hashiVer.Version
	timestamp        string
	commitSHA        string
	incompatibleFlag bool
}

var startsWithSemver = regexp.MustCompile(`v\d+\.\d+\.\d+`)

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
