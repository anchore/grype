package version

import (
	"fmt"

	mvnv "github.com/masahiro331/go-mvn-version"
)

type javaVersion struct {
	raw     string
	version mvnv.Version
}

func newJavaVersion(raw string) (*javaVersion, error) {
	ver, err := mvnv.NewVersion(raw)
	if err != nil {
		return nil, fmt.Errorf("could not generate new java version from: %s; %w", raw, err)
	}

	return &javaVersion{
		raw:     raw,
		version: ver,
	}, nil
}

// Compare returns 0 if j2 == j, 1 if j2 > j, and -1 if j2 < j.
// If an error returns the int value is -1
func (j *javaVersion) Compare(j2 *Version) (int, error) {
	if j2.Format != JavaFormat {
		return -1, fmt.Errorf("unable to compare java to given format: %s", j2.Format)
	}
	if j2.rich.javaVer == nil {
		return -1, fmt.Errorf("given empty javaVersion object")
	}

	submittedVersion := j2.rich.javaVer.version
	if submittedVersion.Equal(j.version) {
		return 0, nil
	}
	if submittedVersion.LessThan(j.version) {
		return -1, nil
	}
	if submittedVersion.GreaterThan(j.version) {
		return 1, nil
	}

	return -1, fmt.Errorf(
		"could not compare java versions: %v with %v",
		submittedVersion.String(),
		j.version.String())
}
