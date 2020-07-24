package version

import (
	"fmt"
	"regexp"
	"strings"
)

// operator group only matches on range operators (GT, LT, GTE, LTE, E)
// version group matches on everything except for whitespace and operators (range or boolean)
var constraintPartPattern = regexp.MustCompile(`(?P<operator>[><=]*)\s*(?P<version>[^<>=\s,|]+)`)

type constraintUnit struct {
	rangeOperator operator
	version       string
}

func splitConstraintPhrase(phrase string) ([]constraintUnit, error) {
	// this implies that the returned set of constraint parts should be ANDed together
	if strings.Contains(phrase, "(") || strings.Contains(phrase, ")") {
		return nil, fmt.Errorf("version constraint groups are unsupported (use of parentheses)")
	}

	if strings.Contains(phrase, "||") {
		return nil, fmt.Errorf("version constraint part should not have an OR")
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

	result := make([]constraintUnit, 0)
	for _, pair := range pairs {
		op, err := parseOperator(pair["operator"])
		if err != nil {
			return nil, fmt.Errorf("unable to parse constraint operator: %+v", err)
		}
		result = append(result, constraintUnit{
			rangeOperator: op,
			version:       pair["version"],
		})
	}

	return result, nil
}

func (c *constraintUnit) Satisfied(comparison int) bool {
	switch c.rangeOperator {
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
	default:
		panic(fmt.Errorf("unknown operator: %s", c.rangeOperator))
	}
}
