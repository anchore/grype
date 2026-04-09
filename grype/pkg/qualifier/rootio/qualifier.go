package rootio

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// rootIO represents a Root IO package qualifier that implements the NAK (Negative Acknowledgment) pattern.
// When a vulnerability requires Root IO packages (required=true), this qualifier will suppress matches
// for standard packages that don't have Root IO fixes applied.
type rootIO struct {
	required bool // true if vulnerability requires Root IO package
}

// New creates a new Root IO qualifier.
// When required is true, the qualifier will only allow matches for Root IO packages.
func New(required bool) qualifier.Qualifier {
	return &rootIO{required: required}
}

// Satisfied implements the qualifier.Qualifier interface.
// It returns true if the package satisfies the Root IO requirement, false otherwise.
//
// NAK (Negative Acknowledgment) Pattern:
//   - If the vulnerability requires Root IO (required=true) but the package is NOT a Root IO package,
//     the match is suppressed (returns false).
//   - If the vulnerability doesn't require Root IO, or if the package IS a Root IO package,
//     the qualifier is satisfied (returns true) and normal version matching proceeds.
func (r rootIO) Satisfied(p pkg.Package) (bool, error) {
	if !r.required {
		// No Root IO requirement, qualifier doesn't apply
		return true, nil
	}

	// NAK Pattern: If vuln requires Root IO but package is NOT Root IO,
	// suppress the match
	if !IsRootIOPackage(p) {
		return false, nil
	}

	// Package IS Root IO, allow normal version matching
	return true, nil
}

// IsRootIOPackage detects if a package is a Root IO package by checking name prefixes and version suffixes.
// It uses multiple detection strategies to identify Root IO packages across different ecosystems.
func IsRootIOPackage(p pkg.Package) bool {
	// Strategy 1: Name prefix detection (most reliable)
	if hasRootIOPrefix(p.Name, p.Type) {
		return true
	}

	// Strategy 2: Version suffix detection
	if hasRootIOVersionSuffix(p.Version, p.Type) {
		return true
	}

	return false
}

// StripPrefix removes the rootio-specific name prefix from a package name,
// returning the bare upstream package name.
func StripPrefix(name string, pkgType syftPkg.Type) string {
	switch pkgType {
	case syftPkg.NpmPkg:
		if strings.HasPrefix(name, "@rootio/") {
			bare := strings.TrimPrefix(name, "@rootio/")
			// Scoped packages were encoded with __ separator: babel__core -> @babel/core
			if idx := strings.Index(bare, "__"); idx > 0 {
				return fmt.Sprintf("@%s/%s", bare[:idx], bare[idx+2:])
			}
			return bare
		}
		return strings.TrimPrefix(name, "rootio-")

	case syftPkg.PythonPkg:
		return strings.TrimPrefix(name, "rootio_")

	case syftPkg.JavaPkg:
		return strings.TrimPrefix(name, "io.root.")

	default:
		return strings.TrimPrefix(name, "rootio-")
	}
}

// hasRootIOPrefix checks if the package name has a Root IO prefix.
// Different ecosystems use different prefixes:
// - OS packages (Alpine, Debian, Ubuntu): "rootio-" prefix
// - NPM scoped packages: "@rootio/" prefix (e.g. "@rootio/express", "@rootio/babel__core")
// - NPM unscoped packages: "rootio-" prefix
// - PyPI packages: "rootio_" prefix (underscore, e.g. "rootio_requests")
// - Java/Maven packages: "io.root." prefix on groupId (e.g. "io.root.org.springframework:spring-core")
func hasRootIOPrefix(name string, pkgType syftPkg.Type) bool {
	switch pkgType {
	case syftPkg.NpmPkg:
		// NPM packages can be scoped (@rootio/package) or unscoped (rootio-package)
		return strings.HasPrefix(name, "@rootio/") || strings.HasPrefix(name, "rootio-")

	case syftPkg.ApkPkg, syftPkg.DebPkg, syftPkg.RpmPkg:
		// OS packages use rootio- prefix
		return strings.HasPrefix(name, "rootio-")

	case syftPkg.PythonPkg:
		// PyPI packages use rootio_ prefix (underscore, per PyPI naming convention)
		return strings.HasPrefix(name, "rootio_")

	case syftPkg.JavaPkg:
		// Maven packages use io.root. prefix on the groupId
		return strings.HasPrefix(name, "io.root.")

	default:
		// For unknown package types, check generic rootio- prefix
		return strings.HasPrefix(name, "rootio-")
	}
}

// hasRootIOVersionSuffix checks if the package version has a Root IO suffix.
// Different ecosystems use different version patterns:
// - NPM: "-root.io.N" suffix (semver prerelease, e.g., "5.7.1-root.io.1")
// - PyPI: "+root.io.N" suffix (PEP 440 local version identifier, e.g., "2.31.0+root.io.1")
// - Debian/Ubuntu: ".root.io.N" suffix (e.g., "5.10.234-1.root.io.1")
// - Alpine APK: "-r1007N" suffix where N is a digit (e.g., "2.38.1-r10071")
//
// Note: For high confidence, some ecosystems (Alpine, Debian, Ubuntu, PyPI) should have BOTH
// name prefix AND version suffix. This function returns true if the version pattern is found,
// but isRootIOPackage may require additional checks.
func hasRootIOVersionSuffix(version string, pkgType syftPkg.Type) bool {
	if version == "" {
		return false
	}

	switch pkgType {
	case syftPkg.NpmPkg:
		// NPM: "-root.io." pattern (semver prerelease identifier)
		// Example: "5.7.1-root.io.1" or "4.18.2-root.io.2"
		return strings.Contains(version, "-root.io.")

	case syftPkg.DebPkg:
		// Debian/Ubuntu: ".root.io." pattern
		// Example: "5.10.234-1.root.io.1" or "8:6.9.11.root.io.1"
		return strings.Contains(version, ".root.io.")

	case syftPkg.PythonPkg:
		// PyPI: "+root.io." pattern (PEP 440 local version identifier)
		// Example: "2.31.0+root.io.1"
		return strings.Contains(version, "+root.io.")

	case syftPkg.ApkPkg:
		// Alpine APK: "-r1007" pattern followed by a digit
		// Example: "2.38.1-r10071"
		// Note: Regular Alpine packages use "-r0", "-r1", etc., so we look for "-r1007" specifically
		if idx := strings.Index(version, "-r1007"); idx >= 0 {
			// Check if there's at least one more character after "-r1007"
			if idx+6 < len(version) {
				// Verify the next character is a digit
				nextChar := version[idx+6]
				return nextChar >= '0' && nextChar <= '9'
			}
		}
		return false

	case syftPkg.JavaPkg:
		// Java/Maven packages are identified by the "io.root." groupId prefix alone;
		// no version suffix convention has been defined.
		return false

	default:
		// Unknown package type - no version suffix detection
		return false
	}
}
