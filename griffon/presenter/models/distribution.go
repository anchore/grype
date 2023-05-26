package models

import (
	"github.com/anchore/syft/syft/linux"
	"github.com/nextlinux/griffon/griffon/distro"
	"github.com/nextlinux/griffon/internal/log"
)

// distribution provides information about a detected Linux distribution.
type distribution struct {
	Name    string   `json:"name"`    // Name of the Linux distribution
	Version string   `json:"version"` // Version of the Linux distribution (major or major.minor version)
	IDLike  []string `json:"idLike"`  // the ID_LIKE field found within the /etc/os-release file
}

// newDistribution creates a struct with the Linux distribution to be represented in JSON.
func newDistribution(r *linux.Release) distribution {
	if r == nil {
		return distribution{}
	}

	// attempt to use the strong distro type (like the matchers do)
	d, err := distro.NewFromRelease(*r)
	if err != nil {
		log.Warnf("unable to determine linux distribution: %+v", err)

		// as a fallback use the raw release information
		return distribution{
			Name:    r.ID,
			Version: r.VersionID,
			IDLike:  cleanIDLike(r.IDLike),
		}
	}

	return distribution{
		Name:    d.Name(),
		Version: d.FullVersion(),
		IDLike:  cleanIDLike(d.IDLike),
	}
}

func cleanIDLike(idLike []string) []string {
	if idLike == nil {
		return make([]string, 0)
	}
	return idLike
}
