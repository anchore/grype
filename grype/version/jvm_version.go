package version

import (
	"fmt"
	"regexp"
	"strings"

	hashiVer "github.com/anchore/go-version"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
)

var _ Comparator = (*jvmVersion)(nil)

var (
	preJep223VersionPattern = regexp.MustCompile(`^1\.(?P<major>\d+)(\.(?P<minor>\d+)([_-](update)?(_)?(?P<patch>\d+))?(-(?P<prerelease>[^b][^-]+))?(-b(?P<build>\d+))?)?`)
	nonCompliantSemverIsh   = regexp.MustCompile(`^(?P<major>\d+)(\.(?P<minor>\d+)(\.(?P<patch>\d+))?([_-](update)?(_)?(?P<update>\d+))?(-(?P<prerelease>[^b][^-]+))?(-b(?P<build>\d+))?)?`)
)

type jvmVersion struct {
	isPreJep223 bool
	semVer      *hashiVer.Version
}

func newJvmVersion(raw string) (*jvmVersion, error) {
	isPreJep233 := strings.HasPrefix(raw, "1.")

	if isPreJep233 {
		// convert the pre-JEP 223 version to semver
		raw = convertPreJep223Version(raw)
	} else {
		raw = convertNonCompliantSemver(raw)
	}
	verObj, err := hashiVer.NewVersion(raw)
	if err != nil {
		return nil, fmt.Errorf("unable to create semver obj for JVM version: %w", err)
	}

	return &jvmVersion{
		isPreJep223: isPreJep233,
		semVer:      verObj,
	}, nil
}

func (v *jvmVersion) Compare(other *Version) (int, error) {
	if other.Format == JVMFormat {
		if other.rich.jvmVersion == nil {
			return -1, fmt.Errorf("given empty jvmVersion object")
		}
		return other.rich.jvmVersion.compare(*v), nil
	}

	if other.Format == SemanticFormat {
		if other.rich.semVer == nil {
			return -1, fmt.Errorf("given empty semVer object")
		}
		return other.rich.semVer.verObj.Compare(v.semVer), nil
	}

	return -1, NewUnsupportedFormatError(JVMFormat, other.Format)
}

func (v jvmVersion) compare(other jvmVersion) int {
	return v.semVer.Compare(other.semVer)
}

func convertNonCompliantSemver(version string) string {
	// if there is -update as a prerelease, and the patch version is missing or 0, then we should parse the prerelease
	// info that has the update value and extract the version. This should be used as the patch version.

	// 8.0-update302 --> 8.0.302
	// 8.0-update302-b08 --> 8.0.302+8
	// 8.0-update_302-b08 --> 8.0.302+8

	matches := internal.MatchNamedCaptureGroups(nonCompliantSemverIsh, version)
	if len(matches) == 0 {
		log.WithFields("version", version).Trace("unable to convert pre-JEP 223 JVM version")
		return version
	}

	// extract relevant parts from the matches
	majorVersion := trim0sFromLeft(matches["major"])
	minorVersion := trim0sFromLeft(matches["minor"])
	patchVersion := trim0sFromLeft(matches["patch"])
	update := trim0sFromLeft(matches["update"])
	preRelease := trim0sFromLeft(matches["prerelease"])
	build := trim0sFromLeft(matches["build"])

	if (patchVersion == "" || patchVersion == "0") && update != "" {
		patchVersion = update
	}

	return buildSemVer(majorVersion, minorVersion, patchVersion, preRelease, build)
}

func convertPreJep223Version(version string) string {
	// convert the following pre JEP 223 version strings to semvers
	// 1.8.0_302-b08 --> 8.0.302+8
	// 1.9.0-ea-b19  --> 9.0.0-ea+19
	// NOTE: this makes an assumption that the old update field is the patch version in semver...
	// this is NOT strictly in the spec, but for 1.8 this tends to be true (especially for temurin-based builds)
	version = strings.TrimSpace(version)

	matches := internal.MatchNamedCaptureGroups(preJep223VersionPattern, version)
	if len(matches) == 0 {
		log.WithFields("version", version).Trace("unable to convert pre-JEP 223 JVM version")
		return version
	}

	// extract relevant parts from the matches
	majorVersion := trim0sFromLeft(matches["major"])
	minorVersion := trim0sFromLeft(matches["minor"])
	patchVersion := trim0sFromLeft(matches["patch"])
	preRelease := trim0sFromLeft(matches["prerelease"])
	build := trim0sFromLeft(matches["build"])

	if patchVersion == "" {
		patchVersion = "0"
	}

	return buildSemVer(majorVersion, minorVersion, patchVersion, preRelease, build)
}
func buildSemVer(majorVersion, minorVersion, patchVersion, preRelease, build string) string {
	if minorVersion == "" {
		minorVersion = "0"
	}

	segs := []string{majorVersion, minorVersion}
	if patchVersion != "" {
		segs = append(segs, patchVersion)
	}

	var semver strings.Builder
	semver.WriteString(strings.Join(segs, "."))

	if preRelease != "" {
		semver.WriteString(fmt.Sprintf("-%s", preRelease))
	}
	if build != "" {
		semver.WriteString(fmt.Sprintf("+%s", build))
	}

	return semver.String()
}

func trim0sFromLeft(v string) string {
	if v == "0" {
		return v
	}
	return strings.TrimLeft(v, "0")
}
