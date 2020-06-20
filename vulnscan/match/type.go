package match

import "strings"

const (
	UnknownMatchType Type = iota
	ExactDirectMatch
	ExactIndirectMatch
	FuzzyMatch
)

type Type int

var typeStr = []string{
	"UnknownMatchType",
	"Exact-Direct Match",
	"Exact-Indirect Match",
	"Fuzzy Match",
}

func ParseType(userStr string) Type {
	switch strings.ToLower(userStr) {
	case strings.ToLower(ExactDirectMatch.String()):
		return ExactDirectMatch
	case strings.ToLower(ExactIndirectMatch.String()):
		return ExactIndirectMatch
	}
	return UnknownMatchType
}

func (f Type) String() string {
	if int(f) >= len(typeStr) || f < 0 {
		return typeStr[0]
	}

	return typeStr[f]
}
