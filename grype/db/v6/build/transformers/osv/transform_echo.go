package osv

import (
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
	internalecho "github.com/anchore/grype/grype/internal/echo"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// echoStrategy handles ECHO-* records from Echo's OSV feed for patched
// language packages (PyPI/npm/Maven/Go) identified by a "+echo.N" version
// suffix. These records are *advisories* (NAK semantics): they describe the
// version range carrying Echo's fix so the upstream disclosure is suppressed
// on the patched build.
type echoStrategy struct{}

func (echoStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "ECHO-")
}

func (echoStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	// Echo records may carry the upstream CVE in either `aliases` or `related`;
	// merge both so the full CVE set rides on the vulnerability blob and on each
	// unaffected package handle (lets the language matcher cross-reference the
	// Echo NAK to the upstream GHSA/NVD disclosure for the same CVE).
	handle, aliases, err := newAdvisoryVulnerabilityHandle(vuln, state, echoReferences(vuln))
	if err != nil {
		return nil, err
	}

	in := []any{handle}

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
	duplicatePackages := duplicateEchoPackageKeys(vuln.Affected)
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

		echoPkg := echoPackage(affected.Package, pkgType)
		if echoPkg == nil {
			log.WithFields("id", vuln.ID, "ecosystem", ecosystem, "package", affected.Package.Name).
				Warn("echo record uses an invalid package name; skipping package")
			continue
		}
		if _, duplicate := duplicatePackages[echoPackageKey(echoPkg)]; duplicate {
			log.WithFields("id", vuln.ID, "ecosystem", ecosystem, "package", affected.Package.Name).
				Warn("echo record repeats a package in multiple affected entries; skipping package")
			continue
		}

		ranges, ok := echoUnaffectedRanges(affected, pkgType)
		if !ok {
			// An unbounded NAK with no fix would match every version, while
			// flattening multiple vulnerability windows into open-ended ranges
			// could suppress a later reintroduced vulnerability. Echo records
			// currently use one introduced-at-zero/fixed window; reject other
			// shapes until their complements can be represented safely.
			log.WithFields("id", vuln.ID, "ecosystem", ecosystem, "package", affected.Package.Name).
				Warn("echo record uses an unsupported affected range; skipping package")
			continue
		}

		uphs = append(uphs, db.UnaffectedPackageHandle{
			Package: echoPkg,
			BlobValue: &db.PackageBlob{
				CVEs:   aliases,
				Ranges: ranges,
				// Defense in depth: the internal echo-prefixed package key keeps
				// this NAK invisible to old clients, while the runtime qualifier
				// independently requires a scanned "+echo.N" build.
				Qualifiers: &db.PackageQualifiers{Echo: &echoOnly},
			},
		})
	}
	sort.Sort(internal.ByUnaffectedPackage(uphs))
	return uphs
}

func duplicateEchoPackageKeys(affectedEntries []osvmodel.Affected) map[string]struct{} {
	counts := make(map[string]int)
	for _, affected := range affectedEntries {
		pkgType := echoPackageType(affected.Package.Ecosystem)
		if pkgType == "" {
			continue
		}
		echoPkg := echoPackage(affected.Package, pkgType)
		if echoPkg != nil {
			counts[echoPackageKey(echoPkg)]++
		}
	}

	duplicates := make(map[string]struct{})
	for key, count := range counts {
		if count > 1 {
			duplicates[key] = struct{}{}
		}
	}
	return duplicates
}

func echoPackageKey(p *db.Package) string {
	return strings.ToLower(p.Ecosystem + "\x00" + p.Name)
}

func echoUnaffectedRanges(affected osvmodel.Affected, pkgType pkg.Type) ([]db.Range, bool) {
	if len(affected.Versions) != 0 {
		return nil, false
	}
	if len(affected.Ranges) != 1 {
		return nil, false
	}

	r := affected.Ranges[0]
	if r.Type != osvmodel.RangeEcosystem && r.Type != osvmodel.RangeSemVer {
		return nil, false
	}
	if len(r.Events) != 2 {
		return nil, false
	}

	introduced, fixed := r.Events[0], r.Events[1]
	if introduced.Introduced != "0" ||
		introduced.Fixed != "" ||
		introduced.LastAffected != "" ||
		introduced.Limit != "" {
		return nil, false
	}
	if fixed.Fixed == "" ||
		fixed.Introduced != "" ||
		fixed.LastAffected != "" ||
		fixed.Limit != "" ||
		!validEchoFixedVersion(fixed.Fixed, pkgType) {
		return nil, false
	}

	// Keep the stored constraint format unknown so it is evaluated using the
	// scanned package's ecosystem. npm and Go Echo builds then select the
	// Echo-aware comparator, while Python and Maven retain native semantics.
	ranges := getGrypeUnaffectedRangesFromRange(r, "ecosystem")
	return ranges, len(ranges) == 1
}

func validEchoFixedVersion(raw string, pkgType pkg.Type) bool {
	if !internalecho.IsBuild(raw) ||
		strings.TrimSpace(raw) != raw ||
		strings.ContainsAny(raw, " \t\r\n<>=|,&()") {
		return false
	}

	format := grypePkg.VersionFormat(grypePkg.Package{Version: raw, Type: pkgType})
	if pkgType == pkg.NpmPkg || pkgType == pkg.GoModulePkg {
		format = version.EchoFormat
	}
	return version.New(raw, format).Validate() == nil
}

// echoPackageType resolves the grype package type from the OSV ecosystem
// string. Every Echo language ecosystem is prefixed "Echo:":
//
//	"Echo:PyPi", "Echo:npm", "Echo:Maven", "Echo:Go"
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
	case "go", "golang":
		return pkg.GoModulePkg
	}
	return ""
}

// echoPackage builds the db.Package with an internal echo-prefixed key. New
// clients add that key only when scanning a "+echo.N" package; old clients
// search only the upstream name and therefore cannot misapply the NAK after
// silently discarding the unknown Echo qualifier. The upstream name is first
// normalized per package type (e.g. PEP 503 for PythonPkg). Invalid names,
// including Maven names without the required group:artifact shape, return nil.
func echoPackage(p osvmodel.Package, pkgType pkg.Type) *db.Package {
	if p.Name == "" {
		return nil
	}
	if pkgType == pkg.JavaPkg {
		group, artifact, ok := strings.Cut(p.Name, ":")
		if !ok || group == "" || artifact == "" || strings.Contains(artifact, ":") {
			return nil
		}
	}

	normalized := name.Normalize(p.Name, pkgType)
	return &db.Package{
		Ecosystem: pkgType.String(),
		Name:      internalecho.PackageName(normalized),
	}
}
