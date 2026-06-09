package osv

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

// bitnamiStrategy handles BIT-* records from Bitnami's vulnerability database.
// Bitnami records describe *affected* version ranges of upstream components
// (apache, node, spark, etc.) packaged by Bitnami.
//
// Bitnami-specific decisions:
//   - CVEs are in `aliases` directly; no `related` augmentation.
//   - Package type comes from the PURL (always present, e.g. pkg:bitnami/apache).
//   - Ecosystem stays as "Bitnami" — there is no underlying distro.
//   - No qualifiers are emitted. `database_specific.cpes` is intentionally
//     dropped: the bitnami matcher never queries by CPE, the platform CPE
//     qualifier is a runtime no-op for application CPEs, and CPEs without
//     ecosystem context produce noisy matches.
type bitnamiStrategy struct{}

func (bitnamiStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "BIT-")
}

func (bitnamiStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
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
				References:  bitnamiReferences(vuln),
				Aliases:     vuln.Aliases,
				Severities:  severities,
			},
		},
	}

	for _, aph := range bitnamiAffectedPackages(vuln) {
		in = append(in, aph)
	}
	return transformers.NewEntries(in...), nil
}

func bitnamiReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func bitnamiAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r, bitnamiRangeType(r.Type))...)
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			Package: bitnamiPackage(affected.Package),
			BlobValue: &db.PackageBlob{
				CVEs:   vuln.Aliases,
				Ranges: ranges,
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

func bitnamiPackage(p osvmodel.Package) *db.Package {
	pkgType := pkg.TypeFromPURL(p.Purl)
	return &db.Package{
		Ecosystem: p.Ecosystem,
		Name:      name.Normalize(p.Name, pkgType),
	}
}

// bitnamiRangeType maps an OSV range type to the grype version-format string
// for Bitnami records. SEMVER ranges describe bitnami-flavored semver
// (separate version comparator); other OSV types fall through to the default.
func bitnamiRangeType(t osvmodel.RangeType) string {
	if t == osvmodel.RangeSemVer {
		return "bitnami"
	}
	return defaultRangeType(t)
}
