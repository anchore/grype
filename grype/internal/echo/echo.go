// Package echo contains package-identification helpers shared by Echo OSV
// ingestion, package-name lookup, and runtime qualifiers.
package echo

import (
	"regexp"
)

const packageNamePrefix = "echo:"

var buildSuffix = regexp.MustCompile(`\+echo\.\d+$`)

// IsBuild reports whether version identifies an Echo-patched build.
func IsBuild(version string) bool {
	return buildSuffix.MatchString(version)
}

// PackageName returns the internal DB key for an Echo package. Echo keeps
// upstream names in artifacts, so the prefix exists only in Grype's database.
// It prevents older clients, which do not understand the Echo qualifier, from
// finding and applying Echo unaffected records to ordinary upstream packages.
func PackageName(name string) string {
	if name == "" {
		return ""
	}
	return packageNamePrefix + name
}
