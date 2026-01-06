package common

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
var forceSemVerPattern = regexp.MustCompile(`[><=]+\s*[^<>=]+`)

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
