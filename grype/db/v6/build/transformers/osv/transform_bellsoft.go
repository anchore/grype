package osv

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

// bellsoftStrategy handles BELL-* records from BellSoft's vulnerability database.
// BellSoft records describe *affected* version ranges of upstream components
// (apache, node, spark, etc.) packaged by BellSoft.
//
// BellSoft-specific decisions:
//   - CVE refs are in `upstream` field
//   - Package type comes from the PURL (always present, e.g. pkg:apk/alpaquita/apache).
//   - Ecosystem stays as "BellSoft" — there is no underlying distro.
//   - No qualifiers are emitted. `database_specific.cpes` is intentionally
//     dropped: the bellsoft matcher never queries by CPE, the platform CPE
//     qualifier is a runtime no-op for application CPEs, and CPEs without
//     ecosystem context produce noisy matches.
type bellsoftStrategy struct{}

func (bellsoftStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "BELL-")
}

func (bellsoftStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

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
				References:  bellsoftReferences(vuln),
				Aliases:     vuln.Aliases,
				Severities:  severities,
			},
		},
	}

	for _, aph := range bellsoftAffectedPackages(vuln) {
		in = append(in, aph)
	}
	return transformers.NewEntries(in...), nil
}

func bellsoftReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func bellsoftAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r, bellsoftRangeType(r.Type))...)
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			Package: bellsoftPackage(affected.Package),
			BlobValue: &db.PackageBlob{
				CVEs:   vuln.Aliases, // FIXME: should be `vuln.Upstream`
				Ranges: ranges,
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

func bellsoftPackage(p models.Package) *db.Package {
	pkgType := pkg.TypeFromPURL(p.Purl)
	return &db.Package{
		Ecosystem: string(p.Ecosystem),
		Name:      name.Normalize(p.Name, pkgType),
	}
}

// bellsoftRangeType maps an OSV range type to the grype version-format string
// for BellSoft records. SEMVER ranges describe apk-flavored semver
// (separate version comparator); other OSV types fall through to the default.
func bellsoftRangeType(t models.RangeType) string {
	if t == models.RangeSemVer {
		return "apk"
	}
	return defaultRangeType(t)
}
