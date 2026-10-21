package internal

import (
	"github.com/anchore/grype/grype/vulnerability"
)

// FixAvailabilityForVersions selects the fix availability entries that describe one of the given fix versions. This is
// used when a matcher fuses fixes from several records into one (e.g. extended support overlays), so that the resulting
// record carries the availability of the fixes it reports, not of the fixes it replaced. When multiple entries describe
// the same fix version, the earliest date is kept.
func FixAvailabilityForVersions(fixVersions []string, candidates []vulnerability.FixAvailable) []vulnerability.FixAvailable {
	if len(fixVersions) == 0 {
		return nil
	}

	byVersion := make(map[string]vulnerability.FixAvailable)
	for _, a := range candidates {
		if a.Date.IsZero() {
			// a zero date is treated as no date (see the presenter), so it must not displace a dated entry
			continue
		}
		existing, ok := byVersion[a.Version]
		if !ok || a.Date.Before(existing.Date) {
			byVersion[a.Version] = a
		}
	}

	var out []vulnerability.FixAvailable
	for _, v := range fixVersions {
		if a, ok := byVersion[v]; ok {
			out = append(out, a)
		}
	}
	return out
}
