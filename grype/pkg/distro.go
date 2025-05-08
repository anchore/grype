package pkg

import (
	"strings"

	"github.com/anchore/syft/syft/linux"
)

func createLinuxRelease(name string, version string) *linux.Release {
	var codename string

	// if there are no digits in the version, it is likely a codename
	if !strings.ContainsAny(version, "0123456789") {
		codename = version
		version = ""
	}

	return &linux.Release{
		Name:            name,
		ID:              name,
		IDLike:          []string{name},
		Version:         version,
		VersionCodename: codename,
	}
}

func parseDistroQualifier(value string) (string, string) {
	fields := strings.SplitN(value, "-", 2)
	switch len(fields) {
	case 2:
		return fields[0], fields[1]
	case 1:
		return fields[0], ""
	}
	return "", ""
}
