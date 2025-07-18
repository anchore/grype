package status

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

// IgnoreList returns the VEX statuses that should be ignored
func IgnoreList() []Status {
	return []Status{Fixed, NotAffected}
}
