package schemaver

import (
	"fmt"
	"strconv"
	"strings"
)

type String string

func NewString(model, revision, addition int) String {
	return String(fmt.Sprintf("%d.%d.%d", model, revision, addition))
}

func ParseAsString(s string) (String, error) {
	// must provide model.revision.addition
	cleaned := strings.TrimSpace(s)
	parts := strings.Split(cleaned, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid schema version format: %s", s)
	}
	// check that all parts are integers
	for _, part := range parts {
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 {
			return "", fmt.Errorf("invalid schema version format: %s", s)
		}
	}
	return String(cleaned), nil
}

func (s String) String() string {
	return string(s)
}

func (s String) ModelPart() (int, bool) {
	v, ok := parseVersionPart(s, 0)
	if v == 0 {
		ok = false
	}
	return v, ok
}

func (s String) RevisionPart() (int, bool) {
	return parseVersionPart(s, 1)
}

func (s String) AdditionPart() (int, bool) {
	return parseVersionPart(s, 2)
}

func (s String) LessThan(other String) bool {
	return s.compare(other) < 0
}

func (s String) GreaterOrEqualTo(other String) bool {
	return s.compare(other) >= 0
}

func (s String) compare(other String) int {
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

func parseVersionPart(s String, index int) (int, bool) {
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
