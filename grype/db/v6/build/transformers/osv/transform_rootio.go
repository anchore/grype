package osv

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/codename"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// rootioStrategy handles ROOT-* records from the Root IO vulnerability
// database. Root IO ships backported security fixes for upstream OS and
// language packages; their OSV records describe versions that have the
// backport applied. These records are *advisories* (NAK semantics): they
// suppress upstream disclosures on packages where the rootio fix has landed.
//
// Rootio-specific decisions:
//   - The ID prefix distinguishes the sub-domain:
//     ROOT-OS-<distro>-<version>-CVE-* → distro package (apk/deb) with OS
//     metadata; ROOT-APP-<ecosystem>-CVE-* → language package (npm/python/java).
//   - CVEs may live in `aliases`, `related`, or both. The vulnerability blob's
//     Aliases is the union; the same union is used for UnaffectedPackageHandle
//     CVEs so the distro matcher's NAK identity-match works across name
//     boundaries (rootio NAK on `rootio-openssl` suppresses upstream disclosure
//     on `openssl` via the shared CVE alias).
//   - Every emitted package handle carries `Qualifiers.RootIO=true` so the
//     runtime rootio qualifier can apply the NAK pattern: vulnerabilities
//     flagged rootio-only do not match non-rootio packages.
//   - ADVISORY-typed references get their refID set to the record ID.
type rootioStrategy struct{}

func (rootioStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "ROOT-")
}

func (rootioStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	// Rootio NAK records may carry the upstream CVE in either `aliases` or
	// `related`; merge both so the full CVE set rides on the vulnerability blob.
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
				References:  rootioReferences(vuln),
				Aliases:     aliases,
				Severities:  severities,
			},
		},
	}

	for _, uph := range rootioUnaffectedPackages(vuln, aliases) {
		in = append(in, uph)
	}
	return transformers.NewEntries(in...), nil
}

func rootioReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refID := ""
		if ref.Type == models.ReferenceAdvisory {
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

func rootioUnaffectedPackages(vuln unmarshal.OSVVulnerability, aliases []string) []db.UnaffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	rootIO := true
	var uphs []db.UnaffectedPackageHandle
	for _, affected := range vuln.Affected {
		ecosystem := string(affected.Package.Ecosystem)
		pkgType := rootioPackageType(ecosystem)
		if pkgType == "" {
			// rootio ships occasional records for ecosystems the transformer
			// hasn't been taught about (Go, NuGet). Storing them would emit
			// DB entries the matcher can't use; skip with a warning so the
			// drift is visible.
			log.WithFields("id", vuln.ID, "ecosystem", ecosystem, "package", affected.Package.Name).
				Warn("rootio record uses an unsupported ecosystem; skipping (add a case to rootioPackageType to enable)")
			continue
		}

		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeUnaffectedRangesFromRange(r, defaultRangeType(r.Type))...)
		}

		uphs = append(uphs, db.UnaffectedPackageHandle{
			Package:         rootioPackage(affected.Package, pkgType),
			OperatingSystem: rootioOSFromEcosystem(ecosystem),
			BlobValue: &db.PackageBlob{
				// CVEs uses the augmented alias list so the distro matcher's
				// disclosures.Remove(naks) identity-match across name boundaries
				// (e.g. rootio-openssl NAK suppresses upstream openssl disclosure
				// via the shared CVE).
				CVEs:   aliases,
				Ranges: ranges,
				Qualifiers: &db.PackageQualifiers{
					RootIO: &rootIO,
				},
			},
		})
	}
	sort.Sort(internal.ByUnaffectedPackage(uphs))
	return uphs
}

// rootioPackageType resolves the grype package type from the OSV ecosystem
// string. Root IO records don't carry PURLs (verified empirically against
// the full vunnel rootio cache), so this is the only signal.
//
// Every Root IO ecosystem is prefixed with `Root:`:
//
//   - language: "Root:npm", "Root:PyPI", "Root:Maven"
//   - OS: "Root:Alpine:<ver>", "Root:Debian:<ver>", "Root:Ubuntu:<ver>"
//
// Inputs without the `Root:` prefix return empty (the caller skips them with
// a warning); a non-Root-prefixed ecosystem on a ROOT-* record is upstream
// drift we want surfaced, not silently coerced.
func rootioPackageType(ecosystem string) pkg.Type {
	rest, ok := strings.CutPrefix(ecosystem, "Root:")
	if !ok || rest == "" {
		return ""
	}
	switch strings.ToLower(rest) {
	case "npm":
		return pkg.NpmPkg
	case "pypi", "python", "pip":
		return pkg.PythonPkg
	case "maven", "java":
		return pkg.JavaPkg
	}
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	switch strings.ToLower(parts[0]) {
	case "alpine":
		return pkg.ApkPkg
	case "debian", "ubuntu":
		return pkg.DebPkg
	}
	return ""
}

// rootioPackage builds the db.Package, leaving the rootio-prefixed name from
// the OSV record verbatim (e.g. "rootio-util-linux", "@rootio/semver"); the
// matcher fans out to the bare upstream name at lookup time via
// db/v6/name.PackageNames, so without the prefix the NAK record could not
// reach upstream disclosures keyed under the unprefixed name.
//
// Ecosystem is canonicalized to the grype package-type string (e.g.
// "PyPI" → "python", "Alpine:3.18" → "apk"). Name is normalized per the
// package type (e.g. PEP 503 for PythonPkg).
func rootioPackage(p models.Package, pkgType pkg.Type) *db.Package {
	ecosystem := string(p.Ecosystem)
	if pkgType != "" {
		ecosystem = pkgType.String()
	}
	return &db.Package{
		Ecosystem: ecosystem,
		Name:      name.Normalize(p.Name, pkgType),
	}
}

// rootioOSFromEcosystem extracts OS metadata for ROOT-OS-* records. Returns
// nil for ROOT-APP-* records (ecosystem without an `<os>:<version>` tail,
// e.g. "Root:npm").
//
// Expects the raw `Root:<os>:<version>` shape from the Root IO API
// (`Root:Debian:12`, `Root:Ubuntu:22.04`, `Root:Alpine:3.18`). Anything
// without the `Root:` prefix returns nil.
//
// Supported OS ecosystems: Alpine, Debian, Ubuntu. AlmaLinux is handled by
// the alma strategy (rootio doesn't ship AlmaLinux backports today).
func rootioOSFromEcosystem(ecosystem string) *db.OperatingSystem {
	rest, ok := strings.CutPrefix(ecosystem, "Root:")
	if !ok {
		return nil
	}
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) < 2 {
		return nil
	}
	osName := strings.ToLower(parts[0])
	switch osName {
	case "alpine", "debian", "ubuntu":
		// supported, fall through
	default:
		return nil
	}

	versionFields := strings.Split(parts[1], ".")
	major := versionFields[0]
	if _, err := strconv.Atoi(major); err != nil {
		return nil
	}

	var minor string
	if len(versionFields) > 1 {
		minor = versionFields[1]
	}
	return &db.OperatingSystem{
		Name:         osName,
		MajorVersion: major,
		MinorVersion: minor,
		Codename:     codename.LookupOS(osName, major, minor),
	}
}
