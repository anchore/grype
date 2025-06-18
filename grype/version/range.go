package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/grype/internal/stringutil"
)

// operator group only matches on range operators (GT, LT, GTE, LTE, E)
// version group matches on everything except for whitespace and operators (range or boolean)
var constraintPartPattern = regexp.MustCompile(`\s*(?P<prefix>[^><=a-zA-Z0-9().'"]*)(?P<operator>[><=]*)\s*(?P<version>.+)`)

type rangeUnit struct {
	operator operator
	version  string
}

func parseRange(phrase string) (*rangeUnit, error) {
	match := stringutil.MatchCaptureGroups(constraintPartPattern, phrase)
	version, exists := match["version"]
	if !exists {
		return nil, nil
	}

	opStr := match["operator"]

	prefix := match["prefix"]

	if prefix != "" && opStr == "" {
		return nil, fmt.Errorf("constraint has an unprocessable prefix %q", prefix)
	}

	version = strings.Trim(version, " ")

	if err := validateVersion(version); err != nil {
		return nil, err
	}

	// version may have quotes, attempt to unquote it (ignore errors)
	unquoted, err := trimQuotes(version)
	if err == nil {
		version = unquoted
	}

	op, err := parseOperator(opStr)
	if err != nil {
		return nil, fmt.Errorf("unable to parse constraint operator=%q: %+v", match["operator"], err)
	}
	return &rangeUnit{
		operator: op,
		version:  version,
	}, nil
}

// trimQuotes will attempt to remove double quotes.
// If removing double quotes is unsuccessful, it will attempt to remove single quotes.
// If neither operation is successful, it will return an error.
func trimQuotes(s string) (string, error) {
	unquoted, err := strconv.Unquote(s)
	switch {
	case err == nil:
		return unquoted, nil
	case strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'"):
		return strings.Trim(s, "'"), nil
	default:
		return s, fmt.Errorf("string %s is not single or double quoted", s)
	}
}

func (c *rangeUnit) Satisfied(comparison int) bool {
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
	default:
		panic(fmt.Errorf("unknown operator: %s", c.operator))
	}
}

// validateVersion scans the version string and validates characters outside of quotes.
// invalid characters within quotes are allowed, but unbalanced quotes are not allowed.
func validateVersion(version string) error {
	var inQuotes bool
	var quoteChar rune

	for _, r := range version {
		switch {
		case !inQuotes && (r == '"' || r == '\''):
			// start of quoted section
			inQuotes = true
			quoteChar = r
		case inQuotes && r == quoteChar:
			// end of quoted section
			inQuotes = false
			quoteChar = 0
		case !inQuotes && strings.ContainsRune("><=", r):
			// invalid character outside of quotes
			return fmt.Errorf("version %q potentially is a version constraint expression (should not contain '><=' outside of quotes)", version)
		}
	}

	if inQuotes {
		return fmt.Errorf("version %q has unbalanced quotes", version)
	}

	return nil
}
