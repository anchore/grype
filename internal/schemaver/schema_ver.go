package schemaver

import (
	"fmt"
	"strconv"
	"strings"
)

type SchemaVer string

func New(model, revision, addition int) SchemaVer {
	return SchemaVer(fmt.Sprintf("%d.%d.%d", model, revision, addition))
}

func Parse(s string) (SchemaVer, error) {
	// must provide model.revision.addition
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid schema version format: %s", s)
	}
	// check that all parts are integers
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return "", fmt.Errorf("invalid schema version format: %s", s)
		}
	}
	return SchemaVer(s), nil
}

func (s SchemaVer) String() string {
	return string(s)
}

func (s SchemaVer) ModelPart() (int, bool) {
	v, ok := parseVersionPart(s, 0)
	if v == 0 {
		ok = false
	}
	return v, ok
}

func (s SchemaVer) RevisionPart() (int, bool) {
	return parseVersionPart(s, 1)
}

func (s SchemaVer) AdditionPart() (int, bool) {
	return parseVersionPart(s, 2)
}

func parseVersionPart(s SchemaVer, index int) (int, bool) {
	parts := strings.Split(string(s), ".")
	if len(parts) <= index {
		return 0, false
	}
	value, err := strconv.Atoi(parts[index])
	if err != nil {
		return 0, false
	}
	return value, true
}

func (s SchemaVer) LessThan(other SchemaVer) bool {
	return s.compare(other) < 0
}

func (s SchemaVer) GreaterOrEqualTo(other SchemaVer) bool {
	return s.compare(other) >= 0
}

func (s SchemaVer) compare(other SchemaVer) int {
	parts := strings.Split(string(s), ".")
	otherParts := strings.Split(string(other), ".")

	for i := 0; i < 3; i++ {
		v1 := 0
		if i < len(parts) {
			v1, _ = strconv.Atoi(parts[i])
		}

		v2 := 0
		if i < len(otherParts) {
			v2, _ = strconv.Atoi(otherParts[i])
		}

		if v1 < v2 {
			return -1
		} else if v1 > v2 {
			return 1
		}
	}

	return 0
}
