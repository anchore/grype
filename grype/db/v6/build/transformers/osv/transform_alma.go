package osv

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/codename"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

const almaLinux = "almalinux"

// almaStrategy handles AlmaLinux Security Advisory (ALSA) and AlmaLinux Bug
// Advisory (ALBA) records. Alma OSV records are *advisories* (NAK semantics):
// they describe versions that are explicitly fixed, not vulnerable ranges.
//
// Alma-specific decisions:
//   - CVEs live primarily in `related` (sometimes also `aliases`); the
//     vulnerability blob's Aliases is the union of both.
//   - Ecosystem is always "AlmaLinux:<version>"; package type is always RPM;
//     OS metadata is extracted from the ecosystem string.
//   - Packages may carry `ecosystem_specific.rpm_modularity` (~63% of alma 8
//     records); this becomes the RpmModularity qualifier.
//   - ADVISORY-type references get their refID set to the record ID so
//     consumers can link back to the specific advisory.
type almaStrategy struct{}

func (almaStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "ALSA-") || strings.HasPrefix(id, "ALBA-") || strings.HasPrefix(id, "ALEA-")
}

func (almaStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	// alma puts CVEs in `related` for the dominant shape; merge into aliases.
	aliases := append([]string{}, vuln.Aliases...)
	aliases = append(aliases, vuln.Related...)

	in := []any{
		db.VulnerabilityHandle{
			Name:          vuln.ID,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			Status:        db.VulnerabilityActive,
			ModifiedDate:  &vuln.Modified,
			PublishedDate: &vuln.Published,
			BlobValue: &db.VulnerabilityBlob{
				ID:          vuln.ID,
				Description: vuln.Details,
				References:  almaReferences(vuln),
				Aliases:     aliases,
				Severities:  severities,
			},
		},
	}

	for _, uph := range almaUnaffectedPackages(vuln) {
		in = append(in, uph)
	}
	return transformers.NewEntries(in...), nil
}

func almaReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refID := ""
		if ref.Type == osvmodel.ReferenceAdvisory {
			refID = vuln.ID
		}
		refs = append(refs, db.Reference{
			ID:   refID,
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func almaUnaffectedPackages(vuln unmarshal.OSVVulnerability) []db.UnaffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var uphs []db.UnaffectedPackageHandle
	for _, affected := range vuln.Affected {
		uphs = append(uphs, db.UnaffectedPackageHandle{
			Package:         almaPackage(affected.Package),
			OperatingSystem: almaOSFromEcosystem(affected.Package.Ecosystem),
			BlobValue:       almaUnaffectedBlob(vuln, affected),
		})
	}
	sort.Sort(internal.ByUnaffectedPackage(uphs))
	return uphs
}

func almaUnaffectedBlob(vuln unmarshal.OSVVulnerability, affected osvmodel.Affected) *db.PackageBlob {
	var ranges []db.Range
	for _, r := range affected.Ranges {
		ranges = append(ranges, getGrypeUnaffectedRangesFromRange(r, almaRangeType(r.Type))...)
	}

	var qualifiers *db.PackageQualifiers
	if mod := extractRpmModularity(affected); mod != "" {
		qualifiers = &db.PackageQualifiers{RpmModularity: &mod}
	}

	// PackageBlob.CVEs currently mirrors un-augmented vuln.Aliases (preserving
	// historical behavior; this surfaces as nil for the dominant alma shape
	// where CVEs are only in `related`). Functionally low-impact: the only
	// runtime read site is getRelatedVulnerabilities, which already sees the
	// same CVEs via VulnerabilityBlob.Aliases (the augmented list) and dedups.
	return &db.PackageBlob{
		CVEs:       vuln.Aliases,
		Ranges:     ranges,
		Qualifiers: qualifiers,
	}
}

func almaPackage(p osvmodel.Package) *db.Package {
	return &db.Package{
		Ecosystem: pkg.RpmPkg.String(),
		Name:      name.Normalize(p.Name, pkg.RpmPkg),
	}
}

// almaRangeType maps an OSV range type to the grype version-format string for
// AlmaLinux records. ECOSYSTEM ranges describe RPM versions ("rpm" format);
// other OSV types fall through to the default mapping. AlmaLinux records in
// practice only use ECOSYSTEM, but the fallback is here so unexpected shapes
// don't silently become "unknown".
func almaRangeType(t osvmodel.RangeType) string {
	if t == osvmodel.RangeEcosystem {
		return pkg.RpmPkg.String()
	}
	return defaultRangeType(t)
}

// extractRpmModularity reads ecosystem_specific.rpm_modularity from an OSV
// affected entry. Only alma emits this in the OSV records we currently
// consume; other strategies don't have a use for it.
func extractRpmModularity(affected osvmodel.Affected) string {
	if affected.EcosystemSpecific == nil {
		return ""
	}
	v, ok := affected.EcosystemSpecific["rpm_modularity"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func almaOSFromEcosystem(ecosystem string) *db.OperatingSystem {
	parts := strings.SplitN(ecosystem, ":", 2)
	if len(parts) < 2 {
		return nil
	}
	osVersion := parts[1]

	versionFields := strings.Split(osVersion, ".")
	if len(versionFields) == 0 || versionFields[0] == "" {
		return nil
	}

	major := versionFields[0]
	if _, err := strconv.Atoi(major[0:1]); err != nil {
		// Non-numeric version → label-version path.
		return &db.OperatingSystem{
			Name:         almaLinux,
			LabelVersion: osVersion,
			Codename:     codename.LookupOS(almaLinux, "", ""),
		}
	}

	var minor string
	if len(versionFields) > 1 {
		minor = versionFields[1]
	}
	return &db.OperatingSystem{
		Name:         almaLinux,
		MajorVersion: major,
		MinorVersion: minor,
		Codename:     codename.LookupOS(almaLinux, major, minor),
	}
}
