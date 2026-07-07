package osv

import (
	"fmt"
	"sort"
	"strconv"
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

// bellsoftStrategy handles BELL-* records from BellSoft's vulnerability database.
// BellSoft records describe *affected* apk version ranges for packages shipped
// in BellSoft's distros: Alpaquita Linux and BellSoft Hardened Containers.
//
// BellSoft-specific decisions:
//   - CVE refs live in the `upstream` field (aliases/related are empty); it
//     feeds both the vulnerability blob's Aliases and each package blob's CVEs.
//   - These are distro packages (like alpine secdb), not application packages
//     (like bitnami). Every affected entry carries an OperatingSystem derived
//     from the OSV ecosystem string ("Alpaquita:23", "BellSoft Hardened
//     Containers:stream", ...) so the apk matcher's distro search can find them.
//     Package.Ecosystem is the apk package-type string, taken from the PURL.
//   - apk-flavored versions (e.g. 2.7.2-r0) compare with the apk comparator.
//   - No qualifiers or CPEs are emitted; the apk matcher finds these records by
//     distro + package name, never by CPE.
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
				Aliases:     vuln.Upstream,
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
		os := bellsoftOSFromEcosystem(affected.Package.Ecosystem)
		if os == nil {
			// A BellSoft record keyed to an ecosystem we don't recognize would
			// produce a DB entry with no OS — unreachable by the apk matcher's
			// distro search. Skip with a warning so the drift is visible rather
			// than silently emitting dead records.
			log.WithFields("id", vuln.ID, "ecosystem", affected.Package.Ecosystem, "package", affected.Package.Name).
				Warn("bellsoft record uses an unrecognized ecosystem; skipping (add a case to bellsoftOSFromEcosystem to enable)")
			continue
		}

		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r, bellsoftRangeType(r.Type))...)
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			Package:         bellsoftPackage(affected.Package),
			OperatingSystem: os,
			BlobValue: &db.PackageBlob{
				CVEs:   vuln.Upstream,
				Ranges: ranges,
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

func bellsoftPackage(p osvmodel.Package) *db.Package {
	pkgType := pkg.TypeFromPURL(p.Purl)
	return &db.Package{
		Ecosystem: pkgType.String(),
		Name:      name.Normalize(p.Name, pkgType),
	}
}

// bellsoftOSFromEcosystem derives operating-system metadata from a BellSoft OSV
// ecosystem string. BellSoft records are keyed by distro (like alpine secdb),
// so every affected package needs an OperatingSystem for the apk matcher's
// distro search to reach it.
//
// The ecosystem shape is "<distro>:<version>", mapped to the grype distro type
// string so it matches a scanned distro's ID:
//
//   - "Alpaquita:23"                        → alpaquita, major version 23
//   - "Alpaquita:stream"                    → alpaquita, rolling label "stream"
//   - "BellSoft Hardened Containers:stream" → bellsoft-hardened-containers, label "stream"
//
// A numeric version is a release major; a non-numeric one (e.g. "stream") is a
// rolling label. Unrecognized ecosystems return nil so the caller can skip them.
func bellsoftOSFromEcosystem(ecosystem string) *db.OperatingSystem {
	base, ver, ok := strings.Cut(ecosystem, ":")
	if !ok || ver == "" {
		return nil
	}

	var osName string
	switch base {
	case "Alpaquita":
		osName = "alpaquita"
	case "BellSoft Hardened Containers":
		osName = "bellsoft-hardened-containers"
	default:
		return nil
	}

	if _, err := strconv.Atoi(ver); err == nil {
		return &db.OperatingSystem{Name: osName, MajorVersion: ver}
	}
	return &db.OperatingSystem{Name: osName, LabelVersion: ver}
}

// bellsoftRangeType maps an OSV range type to the grype version-format string
// for BellSoft records. BellSoft packages are Alpaquita/BHC apk packages, so
// both SEMVER and ECOSYSTEM ranges carry apk-formatted versions (e.g. 2.7.2-r0)
// and must be compared with the apk comparator. Other OSV types fall through to
// the default mapping.
func bellsoftRangeType(t osvmodel.RangeType) string {
	switch t {
	case osvmodel.RangeSemVer, osvmodel.RangeEcosystem:
		return "apk"
	default:
		return defaultRangeType(t)
	}
}
