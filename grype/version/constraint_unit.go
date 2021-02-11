package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/grype/internal"
)

// operator group only matches on range operators (GT, LT, GTE, LTE, E)
// version group matches on everything except for whitespace and operators (range or boolean)
var constraintPartPattern = regexp.MustCompile(`\s*(?P<operator>[><=]*)\s*(?P<version>.+)`)

type constraintUnit struct {
	rangeOperator operator
	version       string
}

func parseUnit(phrase string) (*constraintUnit, error) {
	match := internal.MatchCaptureGroups(constraintPartPattern, phrase)
	version, exists := match["version"]
	if !exists {
		return nil, nil
	}

	version = strings.Trim(version, " ")

	// version may have quotes, attempt to unquote it (ignore errors)
	unquoted, err := strconv.Unquote(version)
	if err == nil {
		version = unquoted
	}

	op, err := parseOperator(match["operator"])
	if err != nil {
		return nil, fmt.Errorf("unable to parse constraint operator=%q: %+v", match["operator"], err)
	}
	return &constraintUnit{
		rangeOperator: op,
		version:       version,
	}, nil
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
