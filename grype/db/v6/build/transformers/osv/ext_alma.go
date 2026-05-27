package osv

import "github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"

// almaEcosystemSpecific is the typed view of AlmaLinux's
// affected[].ecosystem_specific block. Alma is the only provider currently
// observed populating these fields; if another provider starts emitting
// rpm_modularity, lift the type into osvmodel.
type almaEcosystemSpecific struct {
	// RpmModularity carries the RPM stream modularity (e.g. "nodejs:18") that
	// becomes a PackageQualifier on the emitted DB row. Present on ~63% of
	// alma 8 records; empty elsewhere.
	RpmModularity string `json:"rpm_modularity,omitempty"`
}

func almaEcoExt(affected osvmodel.Affected) almaEcosystemSpecific {
	var ext almaEcosystemSpecific
	osvmodel.DecodeAll(affected.EcosystemSpecific, &ext)
	return ext
}
