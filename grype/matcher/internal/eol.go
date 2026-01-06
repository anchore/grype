package internal

import (
	"time"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// EOLStatus represents the end-of-life status of a distro
type EOLStatus struct {
	IsEOL    bool       // true if the distro is past its EOL date
	IsEOAS   bool       // true if the distro is past its EOAS date
	EOLDate  *time.Time // the EOL date, if known
	EOASDate *time.Time // the EOAS date, if known
}

// CheckDistroEOL checks if the given distro is past its end-of-life date.
// Returns EOLStatus with the status and dates. If the provider doesn't support
// EOL checking or the distro has no EOL data, returns a zero EOLStatus.
func CheckDistroEOL(provider vulnerability.Provider, d *distro.Distro) EOLStatus {
	if d == nil {
		return EOLStatus{}
	}

	checker, ok := provider.(vulnerability.EOLChecker)
	if !ok {
		log.Trace("vulnerability provider does not support EOL checking")
		return EOLStatus{}
	}

	eolDate, eoasDate, err := checker.GetOperatingSystemEOL(d)
	if err != nil {
		log.WithFields("distro", d.String(), "error", err).Debug("failed to get EOL status for distro")
		return EOLStatus{}
	}

	now := time.Now()
	status := EOLStatus{
		EOLDate:  eolDate,
		EOASDate: eoasDate,
	}

	if eolDate != nil && now.After(*eolDate) {
		status.IsEOL = true
	}

	if eoasDate != nil && now.After(*eoasDate) {
		status.IsEOAS = true
	}

	return status
}

// IsDistroEOL is a convenience function that returns true if the distro is past its EOL date.
func IsDistroEOL(provider vulnerability.Provider, d *distro.Distro) bool {
	return CheckDistroEOL(provider, d).IsEOL
}
