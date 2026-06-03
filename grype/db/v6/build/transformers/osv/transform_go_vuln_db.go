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

// govulndbStrategy handles GO-* records from the Go vulnerability database
// (vuln.go.dev). These records describe *affected* version ranges of Go
// modules — both regular modules (github.com/foo/bar, golang.org/x/net) and
// the special "stdlib" and "toolchain" pseudo-modules. Records are
// disclosures (vulnerable ranges), not NAKs.
//
// Govulndb-specific decisions:
//   - CVEs and GHSAs are in `aliases` directly; the schema has no `related`
//     field, so no augmentation.
//   - Ecosystem is always "Go"; mapped to the syft go-module package type so
//     the matcher reaches these records via its standard ecosystem-name
//     search.
//   - Range type is always SEMVER; mapped to "go" so the runtime parses
//     constraints as GolangFormat (which handles Go pseudo-versions like
//     v0.0.0-<timestamp>-<commit>).
//   - `ecosystem_specific.imports` (symbol-level reachability info) is
//     intentionally dropped: grype matches at module granularity and has no
//     way to use per-symbol vulnerability info today.
//   - References pass through with their OSV type as a tag; refID is left
//     empty (the GO records' references don't include the canonical advisory
//     page in `references` — that lives in `database_specific.url`, which we
//     don't synthesize a reference for).
type govulndbStrategy struct{}

func (govulndbStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "GO-")
}

func (govulndbStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
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
				References:  govulndbReferences(vuln),
				Aliases:     vuln.Aliases,
				Severities:  severities,
			},
		},
	}

	for _, aph := range govulndbAffectedPackages(vuln) {
		in = append(in, aph)
	}
	return transformers.NewEntries(in...), nil
}

func govulndbReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func govulndbAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r, govulndbRangeType(r.Type))...)
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			Package: govulndbPackage(affected.Package),
			BlobValue: &db.PackageBlob{
				CVEs:   vuln.Aliases,
				Ranges: ranges,
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

func govulndbPackage(p models.Package) *db.Package {
	return &db.Package{
		Ecosystem: string(pkg.GoModulePkg),
		Name:      name.Normalize(p.Name, pkg.GoModulePkg),
	}
}

// govulndbRangeType maps an OSV range type to the grype version-format string
// for Go records. SEMVER maps to "go" so the runtime parses constraints with
// the Go-flavored comparator (it understands v0.0.0-<timestamp>-<hash>
// pseudo-versions, which generic semver does not). Other OSV types fall
// through to the default mapping; in practice govulndb only emits SEMVER.
func govulndbRangeType(t models.RangeType) string {
	if t == models.RangeSemVer {
		return "go"
	}
	return defaultRangeType(t)
}
