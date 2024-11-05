package match

import (
	"fmt"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/grype/grype/pkg"
)

type Fingerprint struct {
	coreFingerprint
	vulnerabilityFixes string
}

type coreFingerprint struct {
	vulnerabilityID        string
	vulnerabilityNamespace string
	packageID              pkg.ID // note: this encodes package name, version, type, location
}

func (m Fingerprint) String() string {
	return fmt.Sprintf("Fingerprint(vuln=%q namespace=%q fixes=%q package=%q)", m.vulnerabilityID, m.vulnerabilityNamespace, m.vulnerabilityFixes, m.packageID)
}

func (m Fingerprint) ID() string {
	f, err := hashstructure.Hash(&m, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%x", f)
}
