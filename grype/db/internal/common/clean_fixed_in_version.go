package common

import "strings"

func CleanFixedInVersion(version string) string {
	switch strings.TrimSpace(strings.ToLower(version)) {
	case "none", "":
		return ""
	default:
		return version
	}
}
