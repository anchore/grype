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
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

type chainguardStrategy struct{}

// Matches identifies CG OSV records by their "CGA-" prefix
func (chainguardStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "CGA-")
}

// Transform CG OSV records into grype DB entries. CG OSV records specify the range of vulnerable versions
// for a given vulnerability
func (chainguardStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	aliases := vuln.Aliases
	in := []any{
		db.VulnerabilityHandle{
			Name:          vuln.ID,
			Status:        db.VulnerabilityActive,
			PublishedDate: &vuln.Published,
			ModifiedDate:  &vuln.Modified,
			WithdrawnDate: nil,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			BlobValue: &db.VulnerabilityBlob{
				ID:          vuln.ID,
				Assigners:   nil,
				Description: vuln.Details,
				References:  cgReferences(vuln),
				// cg puts CVEs in `upstream`, so we append those
				Aliases:    append(aliases, vuln.Upstream...),
				Severities: severities,
			},
		},
	}

	for _, uph := range cgAffectedPackages(vuln) {
		in = append(in, uph)
	}
	return transformers.NewEntries(in...), nil
}

// cgReferences convert OSV references into grype DB references
func cgReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
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

// cgAffectedPackages converts OSV affected packages into grype DB affected package handles. CG OSV records
// specify the range of vulnerable versions for a given vulnerability, so we convert those ranges into grype
// DB ranges and attach them to the affected package handle blob.
func cgAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	aliases := vuln.Aliases
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r, cgRangeType(r.Type))...)
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			OperatingSystem: cgOperatingSystem(string(affected.Package.Ecosystem)),
			Package: &db.Package{
				Ecosystem: string(affected.Package.Ecosystem),
				Name:      name.Normalize(affected.Package.Name, pkg.TypeFromPURL(affected.Package.Purl)),
			},
			BlobValue: &db.PackageBlob{
				// cg puts CVEs in `upstream`, so we append those
				CVEs:       append(aliases, vuln.Upstream...),
				Ranges:     ranges,
				Qualifiers: cgGetQualifiers(affected),
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

// cgRangeType maps an OSV range type to the grype version-format string.
// ECOSYSTEM ranges describe APK versions ("apk" format); all other range
// types fall back to the default mapping. CG OSV records should all use
// ECOSYSTEM, but the fallback is here so unexpected shapes don't silently
// become "unknown".
func cgRangeType(t osvmodel.RangeType) string {
	if t == osvmodel.RangeEcosystem {
		// TODO is this correct? We do use APK I believe
		return pkg.ApkPkg.String()
	}
	return defaultRangeType(t)
}

// cgGetQualifiers extracts qualifiers from the affected package's PURL. CG OSV records
// may specify an "arch" qualifier in the PURL, which we extract and store in the grype
// DB PackageQualifiers. If the PURL is malformed, empty, or carries no "arch" qualifier,
// returns nil.
func cgGetQualifiers(affected osvmodel.Affected) *db.PackageQualifiers {
	if affected.Package.Purl == "" {
		return nil
	}
	purl, err := packageurl.FromString(affected.Package.Purl)
	if err != nil {
		return nil
	}
	for _, q := range purl.Qualifiers {
		// if we have a purl with an "arch" qualifier, we want to pull that out and
		// store it in the qualifiers for this affected package
		if q.Key == "arch" && q.Value != "" {
			arch := q.Value
			return &db.PackageQualifiers{
				Architecture: &arch,
			}
		}
	}
	return nil
}

// cgOperatingSystem maps the OSV ecosystem string to a grype DB OperatingSystem row.
// CG OSV advisories can carry affected entries across multiple apk-based distros
// (Chainguard, Wolfi). Each becomes its own OS row so apk-distro matchers can find
// them via the operating_systems table + operating_system_specifier_overrides.
// Returns nil if the ecosystem is not a known apk distro — caller skips that entry.
func cgOperatingSystem(ecosystem string) *db.OperatingSystem {
	lower := strings.ToLower(ecosystem)
	switch lower {
	case "chainguard", "wolfi":
		return &db.OperatingSystem{
			Name:         lower,
			ReleaseID:    lower,
			LabelVersion: "rolling",
		}
	}
	return nil
}
