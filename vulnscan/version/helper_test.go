package version

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type testCase struct {
	version    string
	constraint string
	satisfied  bool
	createErr  error
	constErr   error
	checkErr   error
}

func (c *testCase) name() string {
	return fmt.Sprintf("ver='%s'const='%s'", c.version, strings.ReplaceAll(c.constraint, " ", ""))
}

func (c *testCase) assert(t *testing.T, format Format, constraint Constraint) {
	verObj, err := NewVersion(c.version, format)
	if !errors.Is(err, c.createErr) {
		t.Fatalf("unexpected create error: '%+v'!='%+v'", err, c.createErr)
	}

	isVulnerable, err := constraint.Satisfied(verObj)
	if !errors.Is(err, c.checkErr) {
		t.Fatalf("unexpected check error: '%+v'!='%+v'", err, c.checkErr)
	}

	if isVulnerable != c.satisfied {
		t.Errorf("unexpected constraint check result: expected %+v, got %+v", c.satisfied, isVulnerable)
	}

}
