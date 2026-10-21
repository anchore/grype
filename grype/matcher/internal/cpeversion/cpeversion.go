// Package cpeversion renders package and CPE versions in terms that can be compared with each other.
//
// A CPE spells a version the way NVD writes it, which is not always the way the package's own
// ecosystem does. Both the CPE search and the match detail it produces have to reconcile the two, and
// they live in different packages, so the rules are collected here rather than in either of them.
package cpeversion

import (
	"fmt"
	"strings"
)

// cpeAny and cpeNA are the CPE "any" and "not applicable" markers. Spelled out rather than taken from
// nvdtools so this package stays free of that dependency.
const (
	cpeAny = "*"
	cpeNA  = "-"
)

// Alpine drops the -rN build suffix from an apk version. CPE comparison treats the suffix as a
// pre-release, so 1.2.3-r21 would sort before 1.2.3 and fail a constraint its own package satisfies.
// For CPE purposes every build of 1.2.3 is 1.2.3; the alpine feed is what decides whether a later
// build fixed it.
func Alpine(version string) string {
	components := strings.Split(version, "-r")
	if len(components) == 2 {
		return components[0]
	}
	return version
}

// JVM folds a CPE's update field into its version. Pre-JEP-223 releases split a version across both
// fields: 1.8.0_351 appears as version "1.8.0" with update "update351", and comparing the version
// alone would place it before every update of the same release. Anything else is returned unchanged.
func JVM(version, cpeUpdate string) string {
	switch cpeUpdate {
	case "", cpeAny, cpeNA: // the update field says nothing
		return version
	}

	if !strings.HasPrefix(version, "1.") || strings.Contains(version, "_") {
		// not pre-JEP-223, or the version already carries its update
		return version
	}

	return fmt.Sprintf("%s_%s", version, strings.TrimPrefix(cpeUpdate, "update"))
}
