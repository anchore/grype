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
	"github.com/anchore/grype/grype/internal/lightwell"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// lightwellStrategy handles RHLW-* records from Red Hat Lightwell
// (github.com/project-lightwell/lightwell-osv). Lightwell backports upstream
// security fixes into an existing library version and republishes it with a
// remediation suffix (e.g. woodstox-core 6.0.3 -> 6.0.3.rhlw-00001). Each
// record covers one remediated release, so these records are *advisories*
// (NAK semantics): they suppress the upstream GHSA/NVD disclosures that still
// flag the Lightwell build, since it orders below the upstream fix version.
//
// Lightwell-specific decisions:
//   - The fixed CVEs and GHSAs live in `upstream` (`aliases` and `related` are
//     unused today, but merged in case they appear). The union becomes the
//     vulnerability blob's Aliases and the UnaffectedPackageHandle CVEs, so the
//     language matcher's NAK identity-match removes the upstream disclosure by
//     its own GHSA ID as well as by CVE.
//   - Ecosystem is "Red Hat Lightwell:<ecosystem>"; package names are the
//     upstream coordinates (no prefix), so no name fanout is needed.
//   - Each emitted package handle carries the LightwellBaseVersion qualifier.
//     A record's unaffected range is open-ended (>= the remediated build), and
//     Lightwell builds of a higher base version line order above it without
//     necessarily carrying the fix, so the qualifier pins the record to its own
//     line. It also keeps the record from clearing non-Lightwell builds.
//   - The base version is derived from the remediated version's suffix rather
//     than trusted from database_specific.lightwell.backport_base_version, which
//     upstream has been observed to fill with the remediated version itself.
//   - ADVISORY-typed references point at the upstream CVE/GHSA pages, not at
//     the Lightwell advisory, so refID stays empty.
type lightwellStrategy struct{}

const lightwellEcosystemPrefix = "Red Hat Lightwell:"

func (lightwellStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "RHLW-")
}

func (lightwellStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	aliases := append([]string{}, vuln.Aliases...)
	aliases = append(aliases, vuln.Related...)
	aliases = append(aliases, vuln.Upstream...)

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
				References:  lightwellReferences(vuln),
				Aliases:     aliases,
				Severities:  severities,
			},
		},
	}

	for _, uph := range lightwellUnaffectedPackages(vuln, aliases) {
		in = append(in, uph)
	}
	return transformers.NewEntries(in...), nil
}

func lightwellReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func lightwellUnaffectedPackages(vuln unmarshal.OSVVulnerability, aliases []string) []db.UnaffectedPackageHandle {
	var uphs []db.UnaffectedPackageHandle
	for _, affected := range vuln.Affected {
		ecosystem := affected.Package.Ecosystem
		pkgType := lightwellPackageType(ecosystem)
		if pkgType == "" {
			log.WithFields("id", vuln.ID, "ecosystem", ecosystem, "package", affected.Package.Name).
				Warn("lightwell record uses an unsupported ecosystem; skipping (add a case to lightwellPackageType to enable)")
			continue
		}

		baseVersion := lightwellBaseVersion(affected)
		if baseVersion == "" {
			// without a base version line the record would clear every
			// Lightwell build at or above the fix, across all lines
			log.WithFields("id", vuln.ID, "package", affected.Package.Name).
				Warn("lightwell record has no determinable base version; skipping")
			continue
		}

		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeUnaffectedRangesFromRange(r, lightwellRangeType(pkgType))...)
		}

		uphs = append(uphs, db.UnaffectedPackageHandle{
			Package: &db.Package{
				Ecosystem: pkgType.String(),
				Name:      name.Normalize(affected.Package.Name, pkgType),
			},
			BlobValue: &db.PackageBlob{
				CVEs:   aliases,
				Ranges: ranges,
				Qualifiers: &db.PackageQualifiers{
					LightwellBaseVersion: &baseVersion,
				},
			},
		})
	}
	sort.Sort(internal.ByUnaffectedPackage(uphs))
	return uphs
}

// lightwellPackageType resolves the grype package type from the scoped
// "Red Hat Lightwell:<ecosystem>" string. Records don't consistently carry a
// PURL qualifier set we could rely on instead, and a non-prefixed ecosystem on
// an RHLW-* record is upstream drift we want surfaced, not coerced.
func lightwellPackageType(ecosystem string) pkg.Type {
	rest, ok := strings.CutPrefix(ecosystem, lightwellEcosystemPrefix)
	if !ok {
		return ""
	}
	switch strings.ToLower(rest) {
	case "maven":
		return pkg.JavaPkg
	case "pypi":
		return pkg.PythonPkg
	}
	return ""
}

// lightwellRangeType maps to the version format of the package's ecosystem.
// Lightwell only publishes ECOSYSTEM ranges, whose generic "ecosystem" format
// can't order the remediation suffixes against upstream versions.
func lightwellRangeType(pkgType pkg.Type) string {
	switch pkgType {
	case pkg.JavaPkg:
		return "maven"
	case pkg.PythonPkg:
		return "python"
	}
	return "unknown"
}

// lightwellBaseVersion returns the upstream version the affected package's
// remediated build line was backported from, preferring the suffix of the
// fixed version over database_specific.lightwell.backport_base_version.
func lightwellBaseVersion(affected osvmodel.Affected) string {
	for _, r := range affected.Ranges {
		for _, e := range r.Events {
			if base, ok := lightwell.BaseVersion(e.Fixed); ok {
				return base
			}
		}
	}

	lw, ok := affected.DatabaseSpecific["lightwell"].(map[string]any)
	if !ok {
		return ""
	}
	base, _ := lw["backport_base_version"].(string)
	if stripped, ok := lightwell.BaseVersion(base); ok {
		return stripped
	}
	return base
}
