package csaf

import vexStatus "github.com/anchore/grype/grype/vex/status"

type status string

const (
	firstAffected      status = "first_affected"
	firstFixed         status = "first_fixed"
	fixed              status = "fixed"
	knownAffected      status = "known_affected"
	knownNotAffected   status = "known_not_affected"
	lastAffected       status = "last_affected"
	recommended        status = "recommended"
	underInvestigation status = "under_investigation"
)

// matchesVexStatus returns true if the given CSAF status matches the given VEX status.
func matchesVexStatus(csafStatus status, status vexStatus.Status) bool {
	// CSAF implementation has slightly different, richer statuses than the original VEX proposed by CISA
	switch csafStatus {
	case firstAffected, knownAffected, lastAffected, recommended:
		return status == vexStatus.Affected
	case firstFixed, fixed:
		return status == vexStatus.Fixed
	case knownNotAffected:
		return status == vexStatus.NotAffected
	case underInvestigation:
		return status == vexStatus.UnderInvestigation
	default:
		return false
	}
}
