package monitor

import (
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype/grype/vulnerability"
)

type Matching struct {
	PackagesProcessed         progress.Monitorable
	VulnerabilitiesDiscovered progress.Monitorable
	Fixed                     progress.Monitorable
	BySeverity                map[vulnerability.Severity]progress.Monitorable
}
