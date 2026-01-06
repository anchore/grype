package processors

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var schemaFilePattern = regexp.MustCompile(`schema([-_])(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)\.json`)

type version struct {
	Major int
	Minor int
	Patch int
}

func parseVersion(schemaURL string) (*version, error) {
	matches := schemaFilePattern.FindStringSubmatch(schemaURL)
	if matches == nil {
		return nil, fmt.Errorf("invalid version format in URL: %s", schemaURL)
	}

	v := &version{}
	for i, name := range schemaFilePattern.SubexpNames() {
		if name == "" {
			continue
		}
		value, err := strconv.Atoi(matches[i])
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %v", name, err)
		}
		switch name {
		case "major":
			v.Major = value
		case "minor":
			v.Minor = value
		case "patch":
			v.Patch = value
		}
	}

	return v, nil
}

func hasSchemaSegment(schemaURL string, segment string) bool {
	return strings.Contains(schemaURL, "/"+segment+"/")
}
