package rpm

import (
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// almaLinuxKnownLibraryGaps maps base package names to their library package names
// for cases where AlmaLinux advisories are missing library package entries that exist in RHEL.
//
// These gaps were identified through comprehensive audit of 2,668 AlmaLinux Security Advisories
// (see willtmp/alma-audit/FINDINGS.md for details). Only 8 cases (0.027% hit rate) were found
// where library packages are:
// 1. Present in corresponding RHSA but missing from ALSA
// 2. Available in AlmaLinux 8 repositories
// 3. Not debug/documentation packages
//
// TODO: Periodically check if AlmaLinux has fixed these gaps upstream and remove this workaround.
// Last audit: 2025-10-14
// Affected advisories: ALSA-2019:3706, ALSA-2020:5487, ALSA-2021:4386, ALSA-2021:4393,
//
//	ALSA-2021:4489, ALSA-2021:4587, ALSA-2022:0368, ALSA-2022:7928
var almaLinuxKnownLibraryGaps = map[string]string{
	"lua":                     "lua-libs",
	"pacemaker":               "pacemaker-libs",
	"gcc":                     "libgcc",
	"cups":                    "cups-libs",
	"rpm-build":               "rpm-build-libs",
	"device-mapper-multipath": "device-mapper-multipath-libs",
}

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
// 3. Known library packages for base packages (to handle AlmaLinux advisory gaps)
func getRelatedPackageNames(p pkg.Package) []string {
	names := []string{p.Name}

	// Add source RPM name if different from package name
	sourceRPMName := extractSourceRPMName(p)
	if sourceRPMName != "" && sourceRPMName != p.Name {
		names = append(names, sourceRPMName)
	}

	// Check for known library package gaps in AlmaLinux advisories
	// This handles cases where the base package is in the ALSA but the library package is missing
	if libraryPkg, exists := almaLinuxKnownLibraryGaps[p.Name]; exists {
		names = append(names, libraryPkg)
	}

	// Also check if this package is a library package and add the base package
	for basePkg, libraryPkg := range almaLinuxKnownLibraryGaps {
		if p.Name == libraryPkg {
			names = append(names, basePkg)
			break
		}
	}

	return names
}
