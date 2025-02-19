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
