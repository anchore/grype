package rpm

import (
	"strings"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// extractSourceRPMName extracts the source RPM package name from an RPM package.
// For binary RPMs, this returns the source package name they were built from.
// For source RPMs, this returns the package name itself.
func extractSourceRPMName(p pkg.Package) string {
	// First, check if this package has upstream information (source RPM)
	for _, upstream := range p.Upstreams {
		if upstream.Name != "" && upstream.Name != p.Name {
			return upstream.Name
		}
	}

	// If no upstream info, check RPM metadata directly
	if _, ok := p.Metadata.(pkg.RpmMetadata); ok {
		// For packages that don't have upstream info but might be source packages themselves
		return p.Name
	}

	// Check if this might be a source package by looking at the package type or name patterns
	if p.Type == syftPkg.RpmPkg {
		return p.Name
	}

	return ""
}

// getRelatedPackageNames returns all possible package names that could be related to the given package.
// This includes:
// 1. The package name itself
// 2. Source RPM name (if this is a binary package)
// 3. Common binary package patterns derived from source name (if this appears to be a source package)
func getRelatedPackageNames(p pkg.Package) []string {
	names := []string{p.Name}

	sourceRPMName := extractSourceRPMName(p)
	if sourceRPMName != "" && sourceRPMName != p.Name {
		names = append(names, sourceRPMName)
	}

	// If this appears to be a source package, try to generate common binary package names
	if sourceRPMName == p.Name || len(p.Upstreams) == 0 {
		binaryNames := generateCommonBinaryPackageNames(p.Name)
		names = append(names, binaryNames...)
	}

	return names
}

// generateCommonBinaryPackageNames generates common binary package name patterns
// from a source package name. This is based on common RPM packaging conventions.
func generateCommonBinaryPackageNames(sourcePackageName string) []string {
	var names []string

	// Common patterns for binary packages derived from source packages
	patterns := []string{
		"%s-devel",     // development packages
		"%s-libs",      // library packages
		"%s-tools",     // tool packages
		"%s-utils",     // utility packages
		"%s-client",    // client packages
		"%s-server",    // server packages
		"%s-common",    // common packages
		"%s-doc",       // documentation packages
		"%s-debuginfo", // debug packages
		"lib%s",        // library packages with lib prefix
		"lib%s-devel",  // library development packages
	}

	// For Python packages, add specific patterns
	if strings.HasPrefix(sourcePackageName, "python") || strings.Contains(sourcePackageName, "python") {
		patterns = append(patterns, []string{
			"python3-%s",
			"python2-%s",
			"%s-python3",
			"%s-python2",
		}...)

		// Remove python prefix for some patterns
		if strings.HasPrefix(sourcePackageName, "python3-") {
			baseName := strings.TrimPrefix(sourcePackageName, "python3-")
			names = append(names, baseName)
		}
		if strings.HasPrefix(sourcePackageName, "python-") {
			baseName := strings.TrimPrefix(sourcePackageName, "python-")
			names = append(names, "python3-"+baseName)
		}
	}

	// Apply patterns to generate binary package names
	for _, pattern := range patterns {
		name := strings.ReplaceAll(pattern, "%s", sourcePackageName)
		names = append(names, name)
	}

	return names
}
