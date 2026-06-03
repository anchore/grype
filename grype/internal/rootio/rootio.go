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

	syftPkg "github.com/anchore/syft/syft/pkg"
)

// IsPackage reports whether the package described by (name, version, pkgType,
// javaGroupID) was produced by Root IO. Either the name prefix or the
// ecosystem-specific version-side token is sufficient on its own.
//
// javaGroupID is consulted only when pkgType is JavaPkg / JenkinsPluginPkg —
// rootio identifies Java backports by the `io.root.` Maven groupID prefix
// rather than a name prefix. Callers without a groupID (e.g. when the
// underlying metadata doesn't carry one) may pass the empty string; detection
// then falls back to the rare `io.root.` name-prefix form.
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
func IsPackage(name, version string, pkgType syftPkg.Type, javaGroupID string) bool {
	if hasPrefix(name, pkgType, javaGroupID) {
		return true
	}
	return hasVersionSuffix(version, pkgType)
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

// AddPrefix is the inverse of StripPrefix: given an upstream (bare) name and a
// package type, return the rootio-prefixed name the rootio dataset keys its
// records under. If name already carries the rootio prefix, returns it
// unchanged. Returns the empty string when the prefixed form is ambiguous or
// the ecosystem has no canonical prefix.
//
// Rationale: rootio publishes NAKs under the prefixed name even when the
// scanned package is shipped under its upstream name (the "upstream-named"
// rootio model in IsPackage's doc comment). Without this reverse mapping, a
// scan of `libgcrypt20@1.10.1-3.root.io.2` (bare name + rootio version token)
// reaches the upstream Debian disclosure for `libgcrypt20` but cannot reach
// the rootio NAK keyed under `rootio-libgcrypt20`, so the NAK never fires.
func AddPrefix(name string, pkgType syftPkg.Type) string {
	if name == "" {
		return ""
	}
	switch pkgType {
	case syftPkg.NpmPkg:
		if strings.HasPrefix(name, "@rootio/") {
			return name
		}
		if strings.HasPrefix(name, "@") {
			// scoped packages: @babel/core -> @rootio/babel__core
			rest := strings.TrimPrefix(name, "@")
			slash := strings.Index(rest, "/")
			if slash <= 0 {
				return ""
			}
			return fmt.Sprintf("@rootio/%s__%s", rest[:slash], rest[slash+1:])
		}
		return "@rootio/" + name

	case syftPkg.PythonPkg:
		if strings.HasPrefix(name, "rootio-") || strings.HasPrefix(name, "rootio_") {
			return name
		}
		// PEP 503-normalized form is what the resolver searches by.
		return "rootio-" + name

	case syftPkg.JavaPkg:
		if strings.HasPrefix(name, "io.root.") {
			return name
		}
		return "io.root." + name

	default:
		if strings.HasPrefix(name, "rootio-") {
			return name
		}
		return "rootio-" + name
	}
}

// hasPrefix reports whether the package's name (or, for Java, the
// Maven groupID passed by the caller) carries a rootio prefix.
func hasPrefix(name string, pkgType syftPkg.Type, javaGroupID string) bool {
	switch pkgType {
	case syftPkg.NpmPkg:
		// scoped (@rootio/x) or unscoped (rootio-x)
		return strings.HasPrefix(name, "@rootio/") || strings.HasPrefix(name, "rootio-")

	case syftPkg.ApkPkg, syftPkg.DebPkg:
		return strings.HasPrefix(name, "rootio-")

	case syftPkg.PythonPkg:
		// rootio_ is the canonical PyPI form; after PEP 503 normalization
		// runs of [-_.] collapse to a single `-`, yielding rootio-. Accept both.
		return strings.HasPrefix(name, "rootio_") || strings.HasPrefix(name, "rootio-")

	case syftPkg.JavaPkg:
		// Syft emits Java packages with the artifactID alone in the name and the
		// Maven groupID in JavaMetadata.PomGroupID. The rootio marker (`io.root.`)
		// is a groupID prefix, so the metadata is the authoritative place to
		// look; the legacy `groupID:artifactID` form in the name is also accepted
		// for non-Syft callers that build packages by hand.
		if strings.HasPrefix(javaGroupID, "io.root.") {
			return true
		}
		return strings.HasPrefix(name, "io.root.")

	default:
		return strings.HasPrefix(name, "rootio-")
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
