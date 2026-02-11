package version

import (
	"fmt"
	"regexp"

	mvnv "github.com/masahiro331/go-mvn-version"
)

var _ Comparator = (*mavenVersion)(nil)

// javaRuntimeQualifierPattern matches .jreNN or .jdkNN suffixes (case-insensitive) at the end of version strings
var javaRuntimeQualifierPattern = regexp.MustCompile(`(?i)\.(jre|jdk)\d+$`)

type mavenVersion struct {
	raw string
	obj mvnv.Version
}

// stripJavaRuntimeQualifier removes .jreNN or .jdkNN suffixes from version strings.
// These are runtime-specific qualifiers that don't affect version comparison.
//
// The pattern matches 'jre' or 'jdk' (case-insensitive) followed by one or more digits
// at the END of the version string only. This means:
//   - Case-insensitive: Both .jre11 and .JRE11 will be stripped
//   - Requires digits: .jre or .jdk without numbers will NOT be stripped
//   - End-anchored: .jre11-SNAPSHOT or .jdk17.beta will NOT be stripped
//
// Examples:
//   - "12.10.2.jre11" -> "12.10.2" (stripped)
//   - "12.10.2.JRE11" -> "12.10.2" (stripped)
//   - "12.10.2.jdk17" -> "12.10.2" (stripped)
//   - "12.10.2.JDK17" -> "12.10.2" (stripped)
//   - "12.10.2" -> "12.10.2" (no change)
//   - "12.10.2.jre" -> "12.10.2.jre" (no digits, not stripped)
//   - "12.10.2.jre11-SNAPSHOT" -> "12.10.2.jre11-SNAPSHOT" (not at end, not stripped)
func stripJavaRuntimeQualifier(version string) string {
	return javaRuntimeQualifierPattern.ReplaceAllString(version, "")
}

func newMavenVersion(raw string) (mavenVersion, error) {
	// strip Java runtime qualifiers (e.g., .jre11, .jdk17) before parsing to ensure
	// versions like "12.10.2" and "12.10.2.jre11" are treated as equivalent for comparison.
	// The original raw version is preserved for display purposes.
	normalized := stripJavaRuntimeQualifier(raw)

	ver, err := mvnv.NewVersion(normalized)
	if err != nil {
		return mavenVersion{}, fmt.Errorf("could not generate new java version from: %s; %w", raw, err)
	}

	return mavenVersion{
		raw: raw,
		obj: ver,
	}, nil
}

// Compare returns 0 if other == j, 1 if other > j, and -1 if other < j.
// If an error is returned, the int value is -1
func (v mavenVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, fmt.Errorf("cannot compare nil version with %v", other)
	}

	o, err := newMavenVersion(other.Raw)
	if err != nil {
		return 0, err
	}
	return v.compare(o.obj)
}

func (v mavenVersion) compare(other mvnv.Version) (int, error) {
	if v.obj.Equal(other) {
		return 0, nil
	}
	if v.obj.LessThan(other) {
		return -1, nil
	}
	if v.obj.GreaterThan(other) {
		return 1, nil
	}

	return -1, fmt.Errorf(
		"could not compare java versions: %v with %v",
		other.String(),
		v.obj.String())
}
