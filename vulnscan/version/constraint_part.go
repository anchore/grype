package version

import (
	"fmt"
	"regexp"
	"strings"
)

var constraintPartPattern = regexp.MustCompile(`(?P<operator>[><=]*)\s*(?P<version>[^<>=\s,]+)`)

type constraintPart struct {
	operator Operator
	version  string
}

func splitConstraintPhrase(phrase string) ([]constraintPart, error) {
	// this implies that the returned set of constraint parts should be ANDed together
	if strings.Contains(phrase, "||") {
		return nil, fmt.Errorf("'||' operator (OR) is unsupported for constraints")
	}

	matches := constraintPartPattern.FindAllStringSubmatch(phrase, -1)
	pairs := make([]map[string]string, 0)
	for _, match := range matches {
		item := make(map[string]string)
		for i, name := range constraintPartPattern.SubexpNames() {
			if i != 0 && name != "" {
				item[name] = match[i]
			}
		}
		pairs = append(pairs, item)
	}

	result := make([]constraintPart, 0)
	for _, pair := range pairs {
		op, err := ParseOperator(pair["operator"])
		if err != nil {
			return nil, fmt.Errorf("bad operator parse: %+v", err)
		}
		result = append(result, constraintPart{
			operator: op,
			version:  pair["version"],
		})
	}

	return result, nil
}

func (c *constraintPart) Satisfied(comparison int) bool {
	switch c.operator {
	case EQ:
		return comparison == 0
	case GT:
		return comparison > 0
	case GTE:
		return comparison >= 0
	case LT:
		return comparison < 0
	case LTE:
		return comparison <= 0
	}
	return false
}
