package v2

import (
	"fmt"
)

const (
	NVDNamespace = "nvd"
)

func RecordSource(feed, group string) string {
	switch feed {
	case "github", "nvdv2":
		return group
	default:
		return fmt.Sprintf("%s:%s", feed, group)
	}
}

func NamespaceForFeedGroup(feed, group string) (string, error) {
	switch {
	case feed == "vulnerabilities":
		return group, nil
	case feed == "github":
		return group, nil
	case feed == "nvdv2" && group == "nvdv2:cves":
		return NVDNamespace, nil
	}
	return "", fmt.Errorf("feed=%q group=%q has no namespace mappings", feed, group)
}
