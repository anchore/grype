// Package rootio detects whether a scanned package was published by Root IO
// (the rootio backport program), independently of any vulnerability-side
// qualifier logic. The result-side qualifier in grype/pkg/qualifier/rootio
// and the package-name fanout in grype/db/v6/name both consult these
// helpers; keeping detection here avoids a layering inversion where the
// name resolver would otherwise have to import a qualifier package for
// non-qualifier behavior.
package rootio

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// IsPackage reports whether p was produced by Root IO. Either the name
// prefix or the ecosystem-specific version-side token is sufficient on
// its own.
//
// Rootio ships under two coexisting models, often in the same image, and
// both must be detected:
//
//   - Prefixed:        `rootio-libssl3@3.1.8-r00073`,
//     `@rootio/semver@5.7.1-root.io.1`,
//     `rootio-libpam-modules@1.5.2-6+deb12u2.root.io.15`.
//     Both signals present.
//   - Upstream-named:  `libssl3@3.1.8-r00073`,
//     `sqlite-libs@3.41.2-r30074`,
//     `libpam-modules@1.5.2-6+deb12u1.root.io.4`.
//     Only the version-side token; the package name is
//     the upstream one.
//
// The version-side tokens are distinctive enough that accidental
// collisions are implausible:
//
//   - `-root.io.`, `.root.io.`, `+root.io.` — substring is unique by
//     construction; an upstream collision is not realistic.
//   - 5-digit `-rNNNNN` apk rev — real-world non-rootio Alpine packages
//     max out around two digits (e.g. `-r0` through `-r20` across the
//     stock-Alpine SBOMs we surveyed); a 5-digit rev counter is, in
//     practice, a rootio signal.
//
// Java is the only ecosystem with no observed version-side convention;
// detection relies on the `io.root.` groupID prefix alone.
func IsPackage(p pkg.Package) bool {
	if hasPrefix(p, p.Type) {
		return true
	}
	return hasVersionSuffix(p.Version, p.Type)
}

// StripPrefix removes the rootio-specific name prefix from a package name,
// returning the bare upstream name. The caller is expected to have first
// determined that p is a rootio package (e.g. via IsPackage); StripPrefix
// itself is name-only and does not look at metadata.
func StripPrefix(name string, pkgType syftPkg.Type) string {
	switch pkgType {
	case syftPkg.NpmPkg:
		if strings.HasPrefix(name, "@rootio/") {
			bare := strings.TrimPrefix(name, "@rootio/")
			// scoped packages were encoded with __ separator: babel__core -> @babel/core
			if idx := strings.Index(bare, "__"); idx > 0 {
				return fmt.Sprintf("@%s/%s", bare[:idx], bare[idx+2:])
			}
			return bare
		}
		return strings.TrimPrefix(name, "rootio-")

	case syftPkg.PythonPkg:
		// accept both rootio_ (canonical PyPI) and rootio- (PEP 503 normalized form)
		return strings.TrimPrefix(strings.TrimPrefix(name, "rootio-"), "rootio_")

	case syftPkg.JavaPkg:
		return strings.TrimPrefix(name, "io.root.")

	default:
		return strings.TrimPrefix(name, "rootio-")
	}
}

// hasPrefix reports whether the package's name (or, for Java, the
// Maven groupID held in JavaMetadata) carries a rootio prefix.
func hasPrefix(p pkg.Package, pkgType syftPkg.Type) bool {
	switch pkgType {
	case syftPkg.NpmPkg:
		// scoped (@rootio/x) or unscoped (rootio-x)
		return strings.HasPrefix(p.Name, "@rootio/") || strings.HasPrefix(p.Name, "rootio-")

	case syftPkg.ApkPkg, syftPkg.DebPkg:
		return strings.HasPrefix(p.Name, "rootio-")

	case syftPkg.PythonPkg:
		// rootio_ is the canonical PyPI form; after PEP 503 normalization
		// runs of [-_.] collapse to a single `-`, yielding rootio-. Accept both.
		return strings.HasPrefix(p.Name, "rootio_") || strings.HasPrefix(p.Name, "rootio-")

	case syftPkg.JavaPkg:
		// Syft emits Java packages with the artifactID alone in p.Name and the
		// Maven groupID in JavaMetadata.PomGroupID. The rootio marker (`io.root.`)
		// is a groupID prefix, so the metadata is the authoritative place to
		// look; the legacy `groupID:artifactID` form in p.Name is also accepted
		// for non-Syft callers that build packages by hand.
		if md, ok := p.Metadata.(pkg.JavaMetadata); ok && strings.HasPrefix(md.PomGroupID, "io.root.") {
			return true
		}
		return strings.HasPrefix(p.Name, "io.root.")

	default:
		return strings.HasPrefix(p.Name, "rootio-")
	}
}

// hasVersionSuffix reports whether version carries the rootio build-counter
// suffix for its ecosystem.
func hasVersionSuffix(version string, pkgType syftPkg.Type) bool {
	if version == "" {
		return false
	}

	switch pkgType {
	case syftPkg.NpmPkg:
		// semver prerelease: e.g. 5.7.1-root.io.1
		return strings.Contains(version, "-root.io.")

	case syftPkg.DebPkg:
		// dpkg version: e.g. 5.10.234-1.root.io.1 or 8:6.9.11.root.io.1
		return strings.Contains(version, ".root.io.")

	case syftPkg.PythonPkg:
		// PEP 440 local-version identifier: e.g. 2.31.0+root.io.1
		return strings.Contains(version, "+root.io.")

	case syftPkg.ApkPkg:
		// alpine apk packages don't share the `.root.io.N` suffix the other
		// ecosystems use. Rootio instead stamps a five-digit rev number on
		// each build, encoded as r<upstream_pkgrel><rootio_build_counter>
		// where the leading digit mirrors the upstream aports pkgrel rootio
		// forked from and the trailing four digits are rootio's internal
		// build counter. Examples (verified against aports/3.18-stable
		// history): sqlite-libs@3.41.2-r30074 sits on upstream r3,
		// rootio-openssh@9.3_p2-r20074 on upstream r2, rootio-krb5-libs
		// @1.20.2-r10077 on upstream r1, and the openssl trio at
		// 3.1.8-r00073 on upstream r0. Upstream apk pkgrels rarely exceed
		// single digits before pkgver bumps, so a 5-digit rev is reliably
		// a rootio signal in practice.
		return hasFiveDigitApkRev(version)

	case syftPkg.JavaPkg:
		// Java rootio packages are identified by groupID prefix; no version
		// convention has been observed.
		return false

	default:
		return false
	}
}

// hasFiveDigitApkRev reports whether an apk-format version ends with a rev
// counter of five or more digits. Extracted from hasVersionSuffix for
// readability.
func hasFiveDigitApkRev(version string) bool {
	idx := strings.LastIndex(version, "-r")
	if idx < 0 {
		return false
	}
	rev := version[idx+2:]
	if len(rev) < 5 {
		return false
	}
	for i := 0; i < len(rev); i++ {
		if rev[i] < '0' || rev[i] > '9' {
			return false
		}
	}
	return true
}
