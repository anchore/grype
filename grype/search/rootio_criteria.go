package search

import (
	"strings"

	"github.com/anchore/grype/grype/vulnerability"
)

type RootIOCriteria struct {
	DistroName    string
	DistroVersion string
}

func (r RootIOCriteria) MatchesVulnerability(_ vulnerability.Vulnerability) (bool, string, error) {
	return true, "", nil
}

func (r RootIOCriteria) GetOSSpecifier() (name, major, minor, remaining string) {
	parts := strings.Split(r.DistroVersion, ".")
	name = "rootio-" + r.DistroName
	if len(parts) > 0 {
		major = parts[0]
	}
	if len(parts) > 1 {
		minor = parts[1]
	}
	if len(parts) > 2 {
		remaining = strings.Join(parts[2:], ".")
	}
	return
}
