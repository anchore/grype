package internal

import (
	"fmt"

	"github.com/anchore/grype/grype/pkg/qualifier/rpmarch"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

// SourceOrUnspecifiedArch returns a criterion that drops vulnerability entries tagged with
// any rpm arch other than "src". Entries with no rpmarch qualifier (older databases or
// providers that don't distinguish source from binary) pass through unchanged, so existing
// upstream-indirected matching against source-granularity advisories keeps working.
//
// Pass this criterion only on upstream-search code paths in the RPM matcher. Direct-match
// paths must NOT use it: a binary-tagged entry is the canonical hit when scanning that
// exact binary RPM by name.
func SourceOrUnspecifiedArch() vulnerability.Criteria {
	return search.ByFunc(func(vuln vulnerability.Vulnerability) (bool, string, error) {
		for _, q := range vuln.PackageQualifiers {
			ra, ok := q.(interface{ Arch() string })
			if !ok {
				continue
			}
			a := ra.Arch()
			if a == "" || a == rpmarch.ArchSource {
				continue
			}
			return false, fmt.Sprintf("rpm arch %q is not source; not eligible for upstream-indirected match", a), nil
		}
		return true, "", nil
	})
}
