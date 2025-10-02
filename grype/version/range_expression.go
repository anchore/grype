package version

import (
	"bytes"
	"fmt"
	"strings"
	"text/scanner"
)

type simpleRangeExpression struct {
	Units [][]rangeUnit // only supports or'ing a group of and'ed groups
}

func parseRangeExpression(phrase string) (simpleRangeExpression, error) {
	orParts, err := scanExpression(phrase)
	if err != nil {
		return simpleRangeExpression{}, fmt.Errorf("unable to create constraint expression from=%q : %w", phrase, err)
	}

	orUnits := make([][]rangeUnit, len(orParts))
	var fuzzyErr error
	for orIdx, andParts := range orParts {
		andUnits := make([]rangeUnit, len(andParts))
		for andIdx, part := range andParts {
			unit, err := parseRange(part)
			if err != nil {
				return simpleRangeExpression{}, err
			}
			if unit == nil {
				return simpleRangeExpression{}, fmt.Errorf("unable to parse unit: %q", part)
			}
			andUnits[andIdx] = *unit
		}

		orUnits[orIdx] = andUnits
	}

	return simpleRangeExpression{
		Units: orUnits,
	}, fuzzyErr
}

func (c *simpleRangeExpression) satisfied(format Format, version *Version) (bool, error) {
	// If version has config embedded, use config-aware comparison
	if version != nil && version.Config.MissingEpochStrategy != "" && (format == RpmFormat || format == DebFormat) {
		return c.satisfiedWithConfig(format, version, version.Config)
	}

	oneSatisfied := false
	for i, andOperand := range c.Units {
		allSatisfied := true
		for j, andUnit := range andOperand {
			result, err := version.Compare(&Version{
				Format: format,
				Raw:    andUnit.Version,
			})
			if err != nil {
				return false, fmt.Errorf("uncomparable %T vs %q: %w", andUnit, version.String(), err)
			}
			unit := c.Units[i][j]

			if !unit.Satisfied(result) {
				allSatisfied = false
			}
		}

		oneSatisfied = oneSatisfied || allSatisfied
	}
	return oneSatisfied, nil
}

func (c *simpleRangeExpression) satisfiedWithConfig(format Format, version *Version, cfg ComparisonConfig) (bool, error) {
	oneSatisfied := false
	for i, andOperand := range c.Units {
		allSatisfied := true
		for j, andUnit := range andOperand {
			constraintVersion := &Version{
				Format: format,
				Raw:    andUnit.Version,
			}

			var result int
			var err error

			// Use config-aware comparison for RPM and Deb formats when config is provided
			if cfg.MissingEpochStrategy != "" && (format == RpmFormat || format == DebFormat) {
				result, err = compareWithConfig(version, constraintVersion, cfg)
			} else {
				result, err = version.Compare(constraintVersion)
			}

			if err != nil {
				return false, fmt.Errorf("uncomparable %T vs %q: %w", andUnit, version.String(), err)
			}
			unit := c.Units[i][j]

			if !unit.Satisfied(result) {
				allSatisfied = false
			}
		}

		oneSatisfied = oneSatisfied || allSatisfied
	}
	return oneSatisfied, nil
}

// compareWithConfig performs a version comparison using the provided configuration.
// This function extracts the comparator and calls CompareWithConfig if the comparator
// supports it (RPM and Deb versions).
func compareWithConfig(version *Version, constraintVersion *Version, cfg ComparisonConfig) (int, error) {
	comparator, err := version.getComparator(version.Format)
	if err != nil {
		return 0, err
	}

	// Check if the comparator supports config-aware comparison
	switch v := comparator.(type) {
	case rpmVersion:
		return v.CompareWithConfig(constraintVersion, cfg)
	case debVersion:
		return v.CompareWithConfig(constraintVersion, cfg)
	default:
		// Fall back to regular comparison for other formats
		return comparator.Compare(constraintVersion)
	}
}

func scanExpression(phrase string) ([][]string, error) {
	var scnr scanner.Scanner
	var orGroups [][]string // all versions a group of and'd groups or'd together
	var andGroup []string   // most current group of and'd versions
	var buf bytes.Buffer    // most current single version value
	var lastToken string

	captureVersionOperatorPair := func() {
		if buf.Len() > 0 {
			ver := buf.String()
			andGroup = append(andGroup, ver)
			buf.Reset()
		}
	}

	captureAndGroup := func() {
		if len(andGroup) > 0 {
			orGroups = append(orGroups, andGroup)
			andGroup = nil
		}
	}

	scnr.Init(strings.NewReader(phrase))

	scnr.Error = func(*scanner.Scanner, string) {
		// scanner has the ability to invoke a callback upon tokenization errors. By default, if no handler is provided
		// then errors are printed to stdout. This handler is provided to suppress this output.

		// Suppressing these errors is not a problem in this case since the scanExpression function should see all tokens
		// and accumulate them as part of a version value if it is not a token of interest. The text/scanner splits on
		// a pre-configured set of "common" tokens (which we cannot provide). We are only interested in a sub-set of
		// these tokens, thus allow for input that would seemingly be invalid for this common set of tokens.
		// For example, the scanner finding `3.e` would interpret this as a float with no valid exponent. However,
		// this function accumulates all tokens into the version component (and versions are not guaranteed to have
		// valid tokens).
	}

	tokenRune := scnr.Scan()
	for tokenRune != scanner.EOF {
		currentToken := scnr.TokenText()
		switch {
		case currentToken == ",":
			captureVersionOperatorPair()
		case currentToken == "|" && lastToken == "|":
			captureVersionOperatorPair()
			captureAndGroup()
		case currentToken == "(" || currentToken == ")":
			return nil, fmt.Errorf("parenthetical expressions are not supported yet")
		case currentToken != "|":
			buf.Write([]byte(currentToken))
		}
		lastToken = currentToken
		tokenRune = scnr.Scan()
	}
	captureVersionOperatorPair()
	captureAndGroup()

	return orGroups, nil
}
