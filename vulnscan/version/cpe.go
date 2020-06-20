package version

import (
	"fmt"
	"regexp"
	"strings"
	"github.com/umisama/go-cpe"
)

const (
	cpeUrlPrefix = "cpe:/"
	cpeFsPrefix  = "cpe:2.3:"
	cpeFsPrefixRegex = "cpe:2.3:.*"
	cpeWildcard = "*"
)

var cpeOps = []string{">", ">=", "=", "<", "<="}
var cpeConstraintRegexp *regexp.Regexp

func init() {
	cpeConstraintRegexp = regexp.MustCompile(fmt.Sprintf(`^\s*(%s)\s*(%s)\s*$`, strings.Join(cpeOps, "|"), cpeFsPrefixRegex))
}

type Cpe23Constraint struct {
	cpe *cpe.Item
	check string // The check to run (e.g. <=, <, =, >, >=)
}


type cpeConstraint struct {
	raw string
	constraints []Cpe23Constraint
}


// Create a CPE constraint from a single string. Expects a format like: "< cpe:2.3:a:vendor:product:versionA...., > cpe:2.3:a:vendor:product:versionB:..." which effectively encodes "< A, > B"
func newCpeConstraint(constStr string) (cpeConstraint, error) {
	var err error

	// Split into individual constraints
	constraintStrings := strings.Split(constStr, ",")

	cpeConstraints := make([]Cpe23Constraint, len(constraintStrings))
	checkString := "="
	cpeStr := ""

	for i, cs := range constraintStrings {
		// Parse the check if found. If none, assume '='
		parsed := cpeConstraintRegexp.FindStringSubmatch(cs)
		count := len(parsed)
		switch count {
		case 0:
			//error
			checkString = parsed[0]
			cpeStr = parsed[1]
		case 1:
			checkString = parsed[0]
			cpeStr = parsed[1]
		default:
			break
		}

		cpeConstraints[i].check = checkString
		cpeConstraints[i].cpe, err = cpe.NewItemFromFormattedString(cpeStr)
		if err != nil {
			return cpeConstraint{}, err
		}
	}

	return cpeConstraint{
		raw: constStr,
		constraints: cpeConstraints,
	}, err
}

func (c cpeConstraint) supported(format Format) bool {
	return format == Cpe23Format || format == DpkgFormat || format == SemanticFormat
}

func (c cpeConstraint) String() string {
	return fmt.Sprintf("%s (cpe)", c.raw)
}

func (c cpeConstraint) Satisfied(version *Version) (bool, error) {
	var targetCpe *cpe.Item
	var err error

	if !c.supported(version.Format) {
		return false, fmt.Errorf("(cpe23) unsupported format: %s", version.Format)
	}

	switch(version.Format) {
	case Cpe23Format:
		return matchCpeToCpe(c, version.rich.cpeVer)

	case DpkgFormat:
		targetCpe = cpe.NewItem()
		if err = targetCpe.SetPart(cpe.Application); err != nil {
			return false, err
		}
		if err = targetCpe.SetVersion(cpe.NewStringAttr(version.rich.dpkgVer.String())); err != nil {
			return false, err
		}
		//Dpkg will not have a TargetSoftware field
	case SemanticFormat:
		targetCpe = cpe.NewItem()
		if err = targetCpe.SetPart(cpe.Application); err != nil {
			return false, err
		}
		if err = targetCpe.SetVersion(cpe.NewStringAttr(version.rich.semVer.String())); err != nil {
			return false, err
		}
		// Semver may have a target, should add here or support selection by ecosystem upstream in match process (e.g. part of name selection)
	}

	return false, nil
}

func matchCpeToCpe(constraint *cpeConstraint, targetCpe *cpe.Item) (bool, error){
	targetCpe, err = cpe.NewItemFromFormattedString(version.Raw)
	if err != nil {
		return false, err
	}

	for _, constraint := range c.constraints{
		// TODO: update these to reflect a better comparison (< should take the version number comparison into consideration)
		switch(constraint.check) {
		case "=":
			if ! cpe.CheckEqual(targetCpe, constraint.cpe) {
				return false, nil
			}
		case "<":
			if ! cpe.CheckSubset(targetCpe, constraint.cpe) {
				return false, nil
			}
		}
	}
}
