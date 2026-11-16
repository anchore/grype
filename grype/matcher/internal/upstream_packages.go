package internal

import (
	"slices"
	"strings"

	"github.com/anchore/grype/grype/internal/architecture"
	"github.com/anchore/grype/grype/pkg"
)

// UpstreamPackages returns the source packages to search a distro's data with on behalf of p, in
// addition to p itself (see pkg.UpstreamPackages):
//   - a package with no architecture, or a source package, finds the records of its own name for a
//     source package when it is searched itself, so its own source (see IsOwnSource) is not searched.
//   - a binary package only finds the records of its own name for its architecture, so a binary
//     that records no upstreams is also searched as a source package of its own name, which it is
//     built from (e.g. dpkg omits a Source that matches the binary).
func UpstreamPackages(p pkg.Package) []pkg.Package {
	// don't duplicate source searches:
	if p.Arch == "" || architecture.IsSource(p.Arch) {
		return slices.DeleteFunc(pkg.UpstreamPackages(p), func(u pkg.Package) bool { return IsOwnSource(u, p) })
	}
	// if we have a binary architecture and no upstreams, include a source architecture search of the same-named package:
	if !slices.ContainsFunc(p.Upstreams, func(u pkg.UpstreamPackage) bool { return u.Name != "" }) {
		self := p
		self.Upstreams = []pkg.UpstreamPackage{{Name: p.Name}}
		return pkg.UpstreamPackages(self)
	}
	return pkg.UpstreamPackages(p)
}

// IsOwnSource reports whether upstreamPkg, one of p's upstream packages, is the source package of p's
// own name and version. p's own search finds the records with no architecture at that version, so a
// search for its own source only adds the records for a source package (see
// search.ArchitectureCriteria.WithRequired). An upstream of p's name at another version is searched
// in full: a record can apply at one version and not the other.
func IsOwnSource(upstreamPkg, p pkg.Package) bool {
	return upstreamPkg.Name == p.Name && sameVersion(upstreamPkg.Version, p.Version)
}

// sameVersion reports whether an upstream's version is the package's own, allowing for an epoch the
// upstream omits (as source rpms do).
func sameVersion(upstreamVersion, pkgVersion string) bool {
	if upstreamVersion == pkgVersion {
		return true
	}
	if strings.Contains(upstreamVersion, ":") {
		return false
	}
	_, withoutEpoch, hasEpoch := strings.Cut(pkgVersion, ":")
	return hasEpoch && withoutEpoch == upstreamVersion
}
