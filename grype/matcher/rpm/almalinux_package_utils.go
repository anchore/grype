package rpm

import (
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// extractSourceRPMName extracts the source RPM package name from an RPM package.
// For binary RPMs, this returns the source package name they were built from.
// For source RPMs, this returns the package name itself.
// For non-RPM packages, returns empty string.
func extractSourceRPMName(p pkg.Package) string {
	// Only process RPM packages
	if p.Type != syftPkg.RpmPkg {
		return ""
	}

	// First, check if this package has upstream information (source RPM)
	for _, upstream := range p.Upstreams {
		if upstream.Name != "" && upstream.Name != p.Name {
			return upstream.Name
		}
	}

	// If no upstream info, return the package name itself
	return p.Name
}

// getRelatedPackageNames returns all possible package names that could be related to the given package.
// This includes:
// 1. The package name itself
// 2. Source RPM name (if this is a binary package)
func getRelatedPackageNames(p pkg.Package) []string {
	names := []string{p.Name}

	// Add source RPM name if different from package name
	sourceRPMName := extractSourceRPMName(p)
	if sourceRPMName != "" && sourceRPMName != p.Name {
		names = append(names, sourceRPMName)
	}

	return names
}
