package v6

import "github.com/anchore/grype/internal/log"

// logDroppedVulnerability is a hook called when vulnerabilities are dropped from consideration in a vulnerability Provider,
// this offers a convenient location to set a breakpoint
func logDroppedVulnerability(vulnerabilityID string, reason any, context ...any) {
	log.WithFields(
		"vulnerability", vulnerabilityID,
		"reason", reason,
		"context", context,
	).Trace("dropped vulnerability")
}
