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
