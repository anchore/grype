package match

import (
	"fmt"

	"github.com/gohugoio/hashstructure"

	"github.com/anchore/grype/grype/pkg"
)

// Fingerprint is the identity of a finding: one vulnerability, from one source, on one package.
// Matches that share a fingerprint are the same finding and are reported as one match, however many
// database records produced them -- see Match.Merge for how records that disagree are reconciled.
type Fingerprint struct {
	vulnerabilityID        string
	vulnerabilityNamespace string
	packageID              pkg.ID // note: this encodes package name, version, type, location
}

func (m Fingerprint) String() string {
	return fmt.Sprintf("Fingerprint(vuln=%q namespace=%q package=%q)", m.vulnerabilityID, m.vulnerabilityNamespace, m.packageID)
}

func (m Fingerprint) ID() string {
	f, err := hashstructure.Hash(&m, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%x", f)
}
