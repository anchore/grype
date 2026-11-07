package search

import (
	"fmt"

	"github.com/anchore/grype/grype/vulnerability"
)

var _ vulnerability.Criteria = (*RuleCriteria)(nil)

// RuleCriteria marks a search a search rule added, without constraining results. Priority ranks the
// records the search finds against those of other searches for the same package.
type RuleCriteria struct {
	Priority int
}

// ByRule returns criteria marking a search added by a search rule of the given priority.
func ByRule(priority int) vulnerability.Criteria {
	return &RuleCriteria{Priority: priority}
}

func (c RuleCriteria) MatchesVulnerability(_ vulnerability.Vulnerability) (bool, string, error) {
	return true, "", nil
}

func (c RuleCriteria) Summarize() string {
	return fmt.Sprintf("added by a search rule (priority %d)", c.Priority)
}
