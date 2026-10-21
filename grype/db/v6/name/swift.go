package name

import (
	"fmt"

	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/stringutil"
	"github.com/anchore/packageurl-go"
)

type SwiftResolver struct {
}

func (r *SwiftResolver) Normalize(name string) string {
	// note we are not lowercasing since the DB is case-insensitive for name columns
	return name
}

// Names returns both the package name as catalogued and, when the purl carries
// a namespace, the repository path that names it.
//
// Syft names a Swift Package Manager package by its Package.resolved identity
// ("vapor") and carries the repository path only in the purl
// ("pkg:swift/github.com/vapor/vapor@4.0.0"). GitHub's Swift advisories are
// keyed on the full path, so searching by the identity alone reaches no record
// in the github:language:swift namespace and only NVD's CPE records survive.
//
// Both forms are kept: the identity still reaches any record keyed that way,
// and dropping it would be a silent behaviour change for packages catalogued
// without a purl.
func (r *SwiftResolver) Names(p grypePkg.Package) []string {
	names := stringutil.NewStringSet()

	if p.Name != "" {
		names.Add(r.Normalize(p.Name))
	}

	if p.PURL != "" {
		purl, err := packageurl.FromString(p.PURL)
		switch {
		case err != nil:
			log.Warnf("unable to resolve swift package identifier from purl=%q: %+v", p.PURL, err)
		case purl.Namespace != "":
			names.Add(r.Normalize(fmt.Sprintf("%s/%s", purl.Namespace, purl.Name)))
		}
	}

	return names.ToSlice()
}
