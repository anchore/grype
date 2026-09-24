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
)

// cpanEcosystem is both the syft package type and the grype version-format
// string for Perl distributions.
//
// TODO: use string(pkg.CpanPkg) once the syft release carrying it is vendored.
const cpanEcosystem = "cpan"

// cpansaStrategy handles CPANSA-* records from the CPAN Security Advisory
// database (github.com/briandfoy/cpan-security-advisory), shaped into OSV by
// vunnel's `cpan` provider. CPANSA specifics:
//   - the advisory subject is a CPAN *distribution* ("DBD-SQLite", "libwww-perl",
//     and "perl" itself), never a module, so names map straight onto the syft
//     `cpan` package type.
//   - distribution names are case sensitive and are used verbatim: no
//     name.Normalize call here, and no resolver is registered for `cpan` in
//     grype/db/v6/name. `JSON-MaybeXS` must not match `json-maybexs`.
//   - CPANSA's freeform range strings are resolved against each distribution's
//     published release list at provider time, so what arrives here is ordinary
//     bounded OSV windows. Ranges are tagged "cpan" so the Perl comparator
//     evaluates them; Perl version ordering is decimal-fraction based
//     (1.2 > 1.10) and no other format gets it right.
//   - aliases hold CVEs when one exists. Many advisories have none at all and
//     are only ever reachable under their CPANSA id.
//   - references pass through with the OSV type as the tag; CPANSA emits only
//     WEB references, so there is no ADVISORY reference to key a refID off of.
//   - CPANSA has no withdrawal concept, so every record is emitted active.
type cpansaStrategy struct{}

func (cpansaStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "CPANSA-")
}

func (cpansaStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	affected := cpansaAffectedPackages(vuln)
	if len(affected) == 0 {
		// no affected packages: emitting just the vulnerability handle would write
		// an orphaned record that can never match a package, so skip the advisory.
		return nil, nil
	}

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
				References:  cpansaReferences(vuln),
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

func cpansaReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

// cpansaAffectedPackages builds one handle per affected distribution. A single
// CPANSA id can span several distributions (CPANSA-ExtUtils-ParseXS-2016-1238
// covers both ExtUtils-ParseXS and perl), and upstream also collapses dozens of
// separate version windows under one id, which arrive as multiple windows on one
// distribution rather than as duplicate handles.
func cpansaAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		aphs = append(aphs, db.AffectedPackageHandle{
			Package: cpansaPackage(affected.Package),
			BlobValue: &db.PackageBlob{
				CVEs:   vuln.Aliases,
				Ranges: cpansaRanges(affected.Ranges),
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

// cpansaPackage maps an OSV package onto the syft `cpan` type, keeping the
// distribution name exactly as CPANSA wrote it.
func cpansaPackage(p osvmodel.Package) *db.Package {
	return &db.Package{
		Ecosystem: cpanEcosystem,
		Name:      p.Name,
	}
}

func cpansaRanges(ranges []osvmodel.Range) []db.Range {
	var out []db.Range
	for _, r := range ranges {
		// range type is always ECOSYSTEM from this provider, and "ecosystem" as a
		// grype format string parses to UnknownFormat, whose fuzzy comparison
		// mis-orders Perl decimal versions. Tag "cpan" unconditionally.
		out = append(out, getGrypeRangesFromRange(r, cpanEcosystem)...)
	}
	return out
}
