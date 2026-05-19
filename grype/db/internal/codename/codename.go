package codename

import "strings"

func LookupOS(osName, majorVersion, minorVersion string) string {
	majorVersion = strings.TrimLeft(majorVersion, "0")
	if minorVersion != "0" {
		minorVersion = strings.TrimLeft(minorVersion, "0")
	}

	// try to find the most specific match (major and minor version)
	if versions, ok := normalizedOSCodenames[osName]; ok {
		if minorMap, ok := versions[majorVersion]; ok {
			if codename, ok := minorMap[minorVersion]; ok {
				return codename
			}
			// fall back to the least specific match (only major version, allowing for any minor version explicitly)
			if codename, ok := minorMap["*"]; ok {
				return codename
			}
		}
	}
	return ""
}
