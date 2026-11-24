package internal

import (
	"slices"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/internal/architecture"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
)

// IsSameUpstream returns true when upstreamPkg is "the same" as p
func IsSameUpstream(upstreamPkg, p pkg.Package) bool {
	return upstreamPkg.Name == p.Name && sameVersion(upstreamPkg.Version, p.Version)
}

// UpstreamPackages returns the source packages to search a distro's data with on behalf of p, in
// addition to p itself (see pkg.UpstreamPackages):
//   - a package with no architecture, or a source package, finds the records of its own name for a
//     source package when it is searched itself, so its own source (see IsSameUpstream) is not searched.
//   - a binary package only finds the records of its own name for its architecture, so a binary
//     that records no upstreams is also searched as a source package of its own name, which it is
//     built from (e.g. dpkg omits a Source that matches the binary).
func UpstreamPackages(p pkg.Package) []pkg.Package {
	// don't duplicate source searches. Only the canonical token is checked, not its spellings: those
	// are the DB alias table's to decide, and a miss only costs a redundant own-source search.
	if p.Arch == "" || p.Arch == architecture.ArchSource {
		return slices.DeleteFunc(pkg.UpstreamPackages(p), func(u pkg.Package) bool { return IsSameUpstream(u, p) })
	}
	// if we have a binary architecture and no upstreams, include a source architecture search of the same-named package:
	if !hasUpstreams(p) {
		p.Upstreams = []pkg.UpstreamPackage{{Name: p.Name}}
	}
	upstreams := pkg.UpstreamPackages(p)
	for i := range upstreams {
		if IsSameUpstream(upstreams[i], p) {
			inheritEpoch(&upstreams[i], p)
		}
	}
	return upstreams
}

// hasUpstreams indicates there are non-empty upstream records
func hasUpstreams(p pkg.Package) bool {
	return slices.ContainsFunc(p.Upstreams, func(u pkg.UpstreamPackage) bool { return u.Name != "" })
}

// sameVersion reports whether an upstream's version is the package's own, allowing for an epoch
// either side omits (as source rpms do, and rpm package versions may, recording it separately).
func sameVersion(upstreamVersion, pkgVersion string) bool {
	if upstreamVersion == "" {
		return true
	}
	uEpoch, u := splitEpoch(upstreamVersion)
	pEpoch, v := splitEpoch(pkgVersion)
	return u == v && (uEpoch == "" || pEpoch == "" || uEpoch == pEpoch)
}

// inheritEpoch gives the upstream version the same epoch as p, which a same-name source rpm of the
// same version-release shares. When p records no epoch, or the versions differ, the upstream is left
// without one for the configured missing epoch strategy to decide.
func inheritEpoch(upstreamPkg *pkg.Package, p pkg.Package) {
	if pkg.VersionFormat(p) != version.RpmFormat {
		return
	}
	if uEpoch, _ := splitEpoch(upstreamPkg.Version); uEpoch != "" {
		return
	}
	epoch, ver := splitEpoch(p.Version)
	if epoch == "" {
		if meta, ok := p.Metadata.(pkg.RpmMetadata); ok && meta.Epoch != nil {
			epoch = strconv.Itoa(*meta.Epoch)
		}
	}
	if epoch == "" || ver != upstreamPkg.Version {
		return
	}
	upstreamPkg.Version = epoch + ":" + ver
}

// splitEpoch splits an "epoch:version" string, returning an empty epoch when there is none.
func splitEpoch(v string) (epoch, rest string) {
	if e, r, ok := strings.Cut(v, ":"); ok {
		return e, r
	}
	return "", v
}
