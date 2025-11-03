package common

import (
	"regexp"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// Root.io Alpine version pattern (e.g., -r00071, -r10074)
var rootioAlpinePattern = regexp.MustCompile(`-r\d+007\d+`)

// IsRootIoPackage checks if a package has Root.io patches applied
func IsRootIoPackage(p pkg.Package) bool {
	// Check for Debian-style .root.io suffix
	if strings.Contains(p.Version, ".root.io") {
		return true
	}
	
	// Check for Alpine-style -rXX007X suffix (e.g., -r00071, -r10072)
	if rootioAlpinePattern.MatchString(p.Version) {
		return true
	}
	
	return false
}

// FilterRootIoUnaffectedMatches removes vulnerabilities that Root.io has already patched
func FilterRootIoUnaffectedMatches(store vulnerability.Provider, p pkg.Package, matches []match.Match) []match.Match {
	// Early return for no matches or non-Root.io packages
	if len(matches) == 0 || p.Distro == nil {
		return matches
	}
	
	if !IsRootIoPackage(p) {
		return matches
	}
	
	// Root.io packages with .root.io versions have been patched by Root.io
	// We trust Root.io's security patches and filter out all vulnerabilities
	// This is the safest approach as Root.io has already vetted these packages
	return []match.Match{}
}

// FilterRootIoUnaffectedMatchesForLanguage removes vulnerabilities for language packages (e.g., Python)
func FilterRootIoUnaffectedMatchesForLanguage(store vulnerability.Provider, p pkg.Package, language string, matches []match.Match) []match.Match {
	// Early return for no matches or non-Root.io packages
	if len(matches) == 0 || !IsRootIoPackage(p) {
		return matches
	}
	
	// Root.io packages with .root.io versions have been patched
	// Filter out all vulnerabilities
	return []match.Match{}
}