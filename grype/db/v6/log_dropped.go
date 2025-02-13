package v6

import (
	"github.com/anchore/go-logger"
	"github.com/anchore/grype/internal/log"
)

// logDroppedVulnerability is a hook called when vulnerabilities are dropped from consideration in a vulnerability Provider,
// this offers a convenient location to set a breakpoint
func logDroppedVulnerability(vuln string, reason any, fields logger.Fields) {
	fields["reason"] = reason
	fields["vulnerability"] = vuln

	log.WithFields(fields).Trace("dropped vulnerability")
}
