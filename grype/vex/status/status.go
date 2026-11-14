package status

import "slices"

type Status string

// VEX statuses as defined by CISA
// https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf
//
// Different VEX implementation can use different names to refer to them
const (
	NotAffected        Status = "not_affected"
	Affected           Status = "affected"
	Fixed              Status = "fixed"
	UnderInvestigation Status = "under_investigation"
)

// AugmentList returns the VEX statuses that augment results
func AugmentList() []Status {
	return []Status{Affected, UnderInvestigation}
}

// IgnoreList returns the VEX statuses that should be ignored by default
func IgnoreList() []Status {
	return []Status{Fixed, NotAffected}
}

// AllowedFilterStatuses returns the statuses FilterMatches may suppress.
// The base set is IgnoreList (fixed, not_affected). Any AugmentList status
// present in optIn (for example from vex-add or an explicit ignore rule) is
// also allowed, so under_investigation / affected can be filtered when the
// user opts in.
func AllowedFilterStatuses(optIn []Status) []Status {
	allowed := append([]Status{}, IgnoreList()...)
	for _, s := range optIn {
		if slices.Contains(AugmentList(), s) && !slices.Contains(allowed, s) {
			allowed = append(allowed, s)
		}
	}
	return allowed
}
