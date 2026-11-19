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
// generated-osv branch, provided by the vunnel "ocamlsec" provider).
// OCaml specifics:
//   - aliases hold the CVE and GHSA ids directly. Unlike alma and rootio,
//     `related` is not merged into the aliases: it lists other OSEC advisories
//     (e.g. OSEC-2026-18 → OSEC-2026-01), not identifiers of this one.
//   - ecosystem is "opam" → syft opam package type, found by the matcher's
//     ecosystem-name search.
//   - ECOSYSTEM ranges use the opam version ordering → "opam" format. As for
//     govulndb, a lone introduced:0 yields no ranges, so grype treats every
//     version as vulnerable (an advisory without a fix yet).
//   - records carry an extra `affected` entry without a package that only holds
//     GIT ranges (commits in the upstream repository); it can't be matched
//     against a package and is dropped, as are other non-opam entries.
//   - references pass through, OSV type as tag, preceded by the advisory page
//     from database_specific.human_link: many records have no references at
//     all, and grype reports the first reference as the data source.
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
	advisoryURL := ocamlAdvisoryURL(vuln)
	if advisoryURL != "" {
		refs = append(refs, db.Reference{
			ID:   vuln.ID,
			URL:  advisoryURL,
			Tags: []string{string(osvmodel.ReferenceAdvisory)},
		})
	}
	for _, ref := range vuln.References {
		if ref.URL == advisoryURL {
			continue
		}
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

// ocamlAdvisoryURL returns the advisory page of the record
// (database_specific.human_link, e.g.
// https://github.com/ocaml/security-advisories/tree/main/advisories/2026/OSEC-2026-01.md),
// or "" if there is none.
func ocamlAdvisoryURL(vuln unmarshal.OSVVulnerability) string {
	link, _ := vuln.DatabaseSpecific["human_link"].(string)
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, "https://") && !strings.HasPrefix(link, "http://") {
		return ""
	}
	return link
}

func ocamlAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		if !strings.EqualFold(affected.Package.Ecosystem, string(pkg.OpamPkg)) || affected.Package.Name == "" {
			continue
		}
		var ranges []db.Range
		hasEcosystemRange := false
		for _, r := range affected.Ranges {
			if r.Type != osvmodel.RangeEcosystem {
				continue
			}
			hasEcosystemRange = true
			ranges = append(ranges, getGrypeRangesFromRange(r, string(pkg.OpamPkg))...)
		}
		// no ranges means every version is vulnerable, so keep the package only if
		// the empty ranges come from an ECOSYSTEM range (e.g. a lone introduced:0)
		if !hasEcosystemRange {
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
