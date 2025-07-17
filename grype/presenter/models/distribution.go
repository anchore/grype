package models

import (
	"github.com/anchore/grype/grype/distro"
)

// distribution provides information about a detected Linux distribution.
type distribution struct {
	Name    string   `json:"name"`    // Name of the Linux distribution
	Version string   `json:"version"` // Version of the Linux distribution (major or major.minor version)
	IDLike  []string `json:"idLike"`  // the ID_LIKE field found within the /etc/os-release file
}

// newDistribution creates a struct with the Linux distribution to be represented in JSON.
func newDistribution(d *distro.Distro) distribution {
	if d == nil {
		return distribution{}
	}

	return distribution{
		Name:    d.Name(),
		Version: d.Version,
		IDLike:  cleanIDLike(d.IDLike),
	}
}

func cleanIDLike(idLike []string) []string {
	if idLike == nil {
		return make([]string, 0)
	}
	return idLike
}
