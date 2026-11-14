package osv

import (
	"fmt"
	"sort"
	"strings"
	"time"

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

// ocamlStrategy handles OSEC-* records from the OCaml security advisories
// (https://github.com/ocaml/security-advisories, OSV records from the
// generated-osv branch, provided by the vunnel "ocaml" provider).
// OCaml specifics:
//   - aliases hold CVEs directly; no `related` augmentation.
//   - ecosystem is "opam" → syft opam package type, found by the matcher's
//     ecosystem-name search.
//   - ECOSYSTEM ranges use the opam version ordering → "opam" format.
//   - records carry an extra `affected` entry without a package that only holds
//     GIT ranges (commits in the upstream repository); it can't be matched
//     against a package and is dropped, as are other non-opam entries.
//   - references pass through, OSV type as tag.
type ocamlStrategy struct{}

func (ocamlStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "OSEC-")
}

func (ocamlStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	affected := ocamlAffectedPackages(vuln)
	if len(affected) == 0 {
		// no affected opam packages: emitting just the vulnerability handle would
		// write an orphaned record that can never match a package, so skip it.
		return nil, nil
	}

	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	// withdrawn advisories must not match: Status=Rejected plus WithdrawnDate,
	// which the matcher's OnlyNonWithdrawnVulnerabilities filter skips.
	status := db.VulnerabilityActive
	var withdrawnDate *time.Time
	if !vuln.Withdrawn.IsZero() {
		status = db.VulnerabilityRejected
		withdrawnDate = &vuln.Withdrawn
	}

	in := []any{
		db.VulnerabilityHandle{
			Name:          vuln.ID,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			Status:        status,
			ModifiedDate:  &vuln.Modified,
			PublishedDate: &vuln.Published,
			WithdrawnDate: withdrawnDate,
			BlobValue: &db.VulnerabilityBlob{
				ID:          vuln.ID,
				Description: vuln.Details,
				References:  ocamlReferences(vuln),
				Aliases:     vuln.Aliases,
				Severities:  severities,
			},
		},
	}

	for _, aph := range affected {
		in = append(in, aph)
	}
	return transformers.NewEntries(in...), nil
}

func ocamlReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func ocamlAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		if !strings.EqualFold(affected.Package.Ecosystem, string(pkg.OpamPkg)) || affected.Package.Name == "" {
			continue
		}
		var ranges []db.Range
		for _, r := range affected.Ranges {
			if r.Type != osvmodel.RangeEcosystem {
				continue
			}
			ranges = append(ranges, getGrypeRangesFromRange(r, strings.ToLower(string(pkg.OpamPkg)))...)
		}
		if len(ranges) == 0 {
			continue
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			Package: &db.Package{
				Ecosystem: string(pkg.OpamPkg),
				Name:      name.Normalize(affected.Package.Name, pkg.OpamPkg),
			},
			BlobValue: &db.PackageBlob{
				CVEs:   vuln.Aliases,
				Ranges: ranges,
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}
