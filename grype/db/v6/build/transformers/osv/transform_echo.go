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
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// echoStrategy handles ECHO-* records from Echo's OSV feed. Echo ships patched
// builds of upstream language packages (PyPI/npm/Maven) identified by a
// "+echo.N" version suffix. These records are *advisories* (NAK semantics):
// they describe the version range carrying Echo's fix so the upstream disclosure
// is suppressed on the patched build.
type echoStrategy struct{}

func (echoStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "ECHO-")
}

func (echoStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	// Echo records may carry the upstream CVE in either `aliases` or `related`;
	// merge both so the full CVE set rides on the vulnerability blob and on each
	// unaffected package handle (lets the language matcher cross-reference the
	// Echo NAK to the upstream GHSA/NVD disclosure for the same CVE).
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
				References:  echoReferences(vuln),
				Aliases:     aliases,
				Severities:  severities,
			},
		},
	}

	for _, uph := range echoUnaffectedPackages(vuln, aliases) {
		in = append(in, uph)
	}
	return transformers.NewEntries(in...), nil
}

func echoReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
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

func echoUnaffectedPackages(vuln unmarshal.OSVVulnerability, aliases []string) []db.UnaffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	echoOnly := true
	var uphs []db.UnaffectedPackageHandle
	for _, affected := range vuln.Affected {
		ecosystem := affected.Package.Ecosystem
		pkgType := echoPackageType(ecosystem)
		if pkgType == "" {
			// OS-level "Echo" entries (no language suffix) are owned by the
			// echo OS provider; any other ecosystem is upstream drift. The
			// vunnel echo-osv provider already filters to language ecosystems,
			// so this is defensive — skip rather than emit an unusable entry.
			log.WithFields("id", vuln.ID, "ecosystem", ecosystem, "package", affected.Package.Name).
				Trace("echo record uses a non-language ecosystem; skipping (handled by the echo OS provider, or add a case to echoPackageType)")
			continue
		}

		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeUnaffectedRangesFromRange(r, defaultRangeType(r.Type))...)
		}

		uphs = append(uphs, db.UnaffectedPackageHandle{
			Package: echoPackage(affected.Package, pkgType),
			BlobValue: &db.PackageBlob{
				CVEs:   aliases,
				Ranges: ranges,
				// Gate the NAK to actual Echo builds: the unaffected range is
				// open-ended (">= X+echo.1"), which on an upstream-named package
				// would otherwise leak onto plain higher versions (e.g. a plain
				// "26.1" that is still vulnerable upstream). The echo runtime
				// qualifier requires the scanned package to carry the "+echo.N"
				// suffix, so non-Echo packages don't match this NAK.
				Qualifiers: &db.PackageQualifiers{Echo: &echoOnly},
			},
		})
	}
	sort.Sort(internal.ByUnaffectedPackage(uphs))
	return uphs
}

// echoPackageType resolves the grype package type from the OSV ecosystem
// string. Every Echo language ecosystem is prefixed "Echo:":
//
//	"Echo:PyPi", "Echo:npm", "Echo:Maven"
//
// OS-level "Echo" entries (no language suffix) and any unrecognized ecosystem
// return "" and are skipped by the caller. The suffix match is case-insensitive
// (the feed uses "PyPi"; OSV/osv.dev use "PyPI").
func echoPackageType(ecosystem string) pkg.Type {
	rest, ok := strings.CutPrefix(ecosystem, "Echo:")
	if !ok || rest == "" {
		return ""
	}
	switch strings.ToLower(rest) {
	case "pypi", "python", "pip":
		return pkg.PythonPkg
	case "npm":
		return pkg.NpmPkg
	case "maven", "java":
		return pkg.JavaPkg
	}
	return ""
}

// echoPackage builds the db.Package, keeping the upstream package name verbatim
// from the OSV record. Ecosystem is canonicalized to the grype package-type string
// and the name is normalized per package type (e.g. PEP 503 for PythonPkg).
func echoPackage(p osvmodel.Package, pkgType pkg.Type) *db.Package {
	return &db.Package{
		Ecosystem: pkgType.String(),
		Name:      name.Normalize(p.Name, pkgType),
	}
}
