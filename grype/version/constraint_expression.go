package version

import (
	"bytes"
	"fmt"
	"strings"
	"text/scanner"
)

type constraintExpression struct {
	units       [][]constraintUnit // only supports or'ing a group of and'ed groups
	comparators [][]Comparator     // only supports or'ing a group of and'ed groups
}

func newConstraintExpression(phrase string, genFn comparatorGenerator) (constraintExpression, error) {
	orParts, err := scanExpression(phrase)
	if err != nil {
		return constraintExpression{}, fmt.Errorf("unable to create constraint expression from=%q : %w", phrase, err)
	}

	orUnits := make([][]constraintUnit, len(orParts))
	orComparators := make([][]Comparator, len(orParts))

	for orIdx, andParts := range orParts {
		andUnits := make([]constraintUnit, len(andParts))
		andComparators := make([]Comparator, len(andParts))
		for andIdx, part := range andParts {
			unit, err := parseUnit(part)
			if err != nil {
				return constraintExpression{}, err
			}
			if unit == nil {
				return constraintExpression{}, fmt.Errorf("unable to parse unit: %q", part)
			}
			andUnits[andIdx] = *unit

			comparator, err := genFn(*unit)
			if err != nil {
				return constraintExpression{}, fmt.Errorf("failed to create comparator for '%s': %w", unit, err)
			}
			andComparators[andIdx] = comparator
		}

		orUnits[orIdx] = andUnits
		orComparators[orIdx] = andComparators
	}

	return constraintExpression{
		units:       orUnits,
		comparators: orComparators,
	}, nil
}

func (c *constraintExpression) satisfied(other *Version) (bool, error) {
	oneSatisfied := false
	for i, andOperand := range c.comparators {
		allSatisfied := true
		for j, andUnit := range andOperand {
			result, err := andUnit.Compare(other)
			if err != nil {
				return false, fmt.Errorf("uncomparable %+v %+v: %w", andUnit, other, err)
			}
			unit := c.units[i][j]

			if !unit.Satisfied(result) {
				allSatisfied = false
			}
		}

		oneSatisfied = oneSatisfied || allSatisfied
	}
	return oneSatisfied, nil
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
