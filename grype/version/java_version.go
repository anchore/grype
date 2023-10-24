package version

import (
	"fmt"

	mvnv "github.com/masahiro331/go-mvn-version"
)

type javaVersion struct {
	version mvnv.Version
}

func newJavaVersion(raw string) (*javaVersion, error) {
	ver, err := mvnv.NewVersion(raw)
	if err != nil {
		return nil, fmt.Errorf("could not generate new java version from: %s; %w", raw, err)
	}

	return &javaVersion{
		version: ver,
	}, nil
}

// Compare returns 0 if j == j2, -1 if j < j2, and +1 if j > j2.
// If an error returns the int value is -1
func (j *javaVersion) Compare(j2 *Version) (int, error) {
	if j2.Format != JavaFormat {
		return -1, fmt.Errorf("unable to compare java to given format: %s", j2.Format)
	}
	if j2.rich.javaVer == nil {
		return -1, fmt.Errorf("given empty javaVersion object")
	}

	submittedVersion := j2.rich.javaVer.version
	if j.version.Equal(submittedVersion) {
		return 0, nil
	}
	if j.version.LessThan(submittedVersion) {
		return -1, nil
	}
	if j.version.GreaterThan(submittedVersion) {
		return 1, nil
	}

	return -1, fmt.Errorf(
		"could not compare java versions: %v with %v",
		submittedVersion.String(),
		j.version.String())
}
