package versionutil

import (
	"regexp"
	"strings"
)

// match examples:
// >= 5.0.0
// <= 6.1.2.beta
// >= 5.0.0
// < 6.1
// > 5.0.0
// >=5
// <6
// the comma exclusion matters: clauses arrive both space separated and already comma
// separated (GHSA ranges are written ">= 1.0, < 2.0"), and without it the trailing comma is
// captured as part of the clause and the rejoin below emits ">=1.0,,<2.0".
var forceSemVerPattern = regexp.MustCompile(`[><=]+\s*[^<>=,]+`)

func EnforceSemVerConstraint(constraint string) string {
	constraint = CleanConstraint(constraint)
	if constraint == "" {
		return ""
	}
	return strings.ReplaceAll(strings.Join(forceSemVerPattern.FindAllString(constraint, -1), ", "), " ", "")
}

func AndConstraints(c ...string) string {
	return strings.Join(c, " ")
}

func OrConstraints(c ...string) string {
	return strings.Join(c, " || ")
}

func CleanConstraint(constraint string) string {
	if strings.ToLower(constraint) == "none" {
		return ""
	}
	return constraint
}
