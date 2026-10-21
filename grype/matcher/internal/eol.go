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
// Returns EOLStatus with the status and dates. If neither the provider nor the
// OS release file has EOL data for the distro, returns a zero EOLStatus.
func CheckDistroEOL(provider vulnerability.Provider, d *distro.Distro) EOLStatus {
	if d == nil {
		return EOLStatus{}
	}

	eolDate, eoasDate := providerEOLDates(provider, d)

	// the SUPPORT_END date from the OS release file covers distros the vulnerability data has no
	// record for, such as those derived from a distro that is itself tracked.
	if eolDate == nil {
		eolDate = d.SupportEnd
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

func providerEOLDates(provider vulnerability.Provider, d *distro.Distro) (eolDate, eoasDate *time.Time) {
	checker, ok := provider.(vulnerability.EOLChecker)
	if !ok {
		log.Trace("vulnerability provider does not support EOL checking")
		return nil, nil
	}

	eolDate, eoasDate, err := checker.GetOperatingSystemEOL(d)
	if err != nil {
		log.WithFields("distro", d.String(), "error", err).Debug("failed to get EOL status for distro")
		return nil, nil
	}

	return eolDate, eoasDate
}

// IsDistroEOL is a convenience function that returns true if the distro is past its EOL date.
func IsDistroEOL(provider vulnerability.Provider, d *distro.Distro) bool {
	return CheckDistroEOL(provider, d).IsEOL
}
