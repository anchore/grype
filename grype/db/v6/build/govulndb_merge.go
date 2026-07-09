package v6

import (
	"fmt"
	"strings"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// This file reconciles the overlap between govulndb (GO-*) records and the GHSA
// records they alias. Both feeds describe the same advisories for most
// golang.org/x/* and third-party modules, but only govulndb carries per-symbol
// reachability (ecosystem_specific.imports).

// Writing both leads to reported false positives where GHSAs are surfaced without
// considering the symbol context.
//
// During the streaming pass the merger holds back Go-ecosystem GHSA entries and
// all govulndb entries; at Close time handleEntry runs per GO record:
//   - each GHSA affected package whose name matches the GO record's module path
//     (records sometimes list sub-packages like golang.org/x/net/http2 as separate affected packages)
//     is patched with the matching go-imports qualifier, and the amendment is recorded on the GHSA
//     blob's Modifications.
//   - a GO affected package whose module is present on any aliased GHSA is
//     dropped from the GO record. The GO record itself is written
//     only if affected packages remain; otherwise it is dropped. Stdlib always
//     remains: no GHSA names the "stdlib" module. The closest any comes is
//     GHSA-4v7x-pqxf-cx7m, which lists stdlib package paths (net/http) as
//     affected packages — those rows are patched with symbols but never cover.
//
// Version-range differences between the two feeds are mostly ignored: the
// GHSA's ranges win. Disagreements stem from modules that do not follow Go
// module versioning (odd tags, unversioned module paths, fixes backported to
// release branches semver ranges cannot express) and the GHSA ranges are
// usually the better ones. The one exception is a GHSA range pinned to a Go
// pseudo-version whose govulndb record carries the same fix in the module's
// real tag versioning — see replaceGHSAPseudoVersionRanges.

// goVulnDBMerger holds back the Go-ecosystem entries that participate in the
// govulndb↔GHSA reconciliation and, at Close time, reconciles the overlap and
// returns the entries to write. It owns none of the writer's concerns
// (batching, severity fill, fix-date validation): the writer feeds it entries
// via hold and writes back whatever reconcile returns.
type goVulnDBMerger struct {
	// goGHSAEntries holds back Go-ecosystem GHSA entries (keyed by lowercase
	// GHSA ID, with goGHSAOrder preserving arrival order for deterministic
	// writes) and govulndbEntries holds back GO-* entries, so the govulndb↔GHSA
	// overlap can be reconciled regardless of provider processing order.
	goGHSAEntries   map[string]*transformers.RelatedEntries
	goGHSAOrder     []string
	govulndbEntries []*transformers.RelatedEntries
}

func newGoVulnDBMerger() *goVulnDBMerger {
	return &goVulnDBMerger{
		goGHSAEntries: make(map[string]*transformers.RelatedEntries),
	}
}

// hold diverts entries that participate in the govulndb↔GHSA reconciliation
// into the held collections, returning true when the entry was held (and so
// must not be batched yet).
func (m *goVulnDBMerger) hold(entry transformers.RelatedEntries) bool {
	if entry.VulnerabilityHandle == nil {
		return false
	}
	name := strings.ToLower(entry.VulnerabilityHandle.Name)
	switch {
	case strings.HasPrefix(name, "go-"):
		m.govulndbEntries = append(m.govulndbEntries, &entry)
		return true
	case strings.HasPrefix(name, "ghsa-") && hasGoModulePackages(entry):
		if _, exists := m.goGHSAEntries[name]; exists {
			// a second Go-ecosystem record with the same GHSA ID should not happen;
			// write it through rather than silently replacing the held one. This is a
			// deliberate exception to write-once: the duplicate lands in the DB alongside
			// the held copy so the bad input is visible rather than silently merged.
			log.WithFields("id", entry.VulnerabilityHandle.Name).Warn("duplicate go-ecosystem GHSA record; skipping govulndb reconciliation for it")
			return false
		}
		m.goGHSAEntries[name] = &entry
		m.goGHSAOrder = append(m.goGHSAOrder, name)
		return true
	}
	return false
}

// hasGoModulePackages reports whether any related affected package is in the Go
// module ecosystem.
func hasGoModulePackages(entry transformers.RelatedEntries) bool {
	for _, rel := range entry.Related {
		if aph, ok := rel.(db.AffectedPackageHandle); ok && aph.Package != nil && aph.Package.Ecosystem == string(pkg.GoModulePkg) {
			return true
		}
	}
	return false
}

// reconcile reconciles all held govulndb entries against the held GHSA entries
// and returns the entries to write, in deterministic order: the (patched) GHSA
// entries first (in arrival order), then the surviving govulndb entries. The
// merger's held state is reset before returning. Called once from Close; the
// writer persists the returned entries through its own batching path.
func (m *goVulnDBMerger) reconcile() []transformers.RelatedEntries {
	var surviving []*transformers.RelatedEntries
	for _, entry := range m.govulndbEntries {
		if m.handleEntry(entry) {
			surviving = append(surviving, entry)
		} else {
			log.WithFields("id", entry.VulnerabilityHandle.Name).Trace("dropping govulndb record fully covered by GHSA records")
		}
	}

	out := make([]transformers.RelatedEntries, 0, len(m.goGHSAOrder)+len(surviving))
	for _, key := range m.goGHSAOrder {
		out = append(out, *m.goGHSAEntries[key])
	}
	for _, entry := range surviving {
		out = append(out, *entry)
	}

	m.govulndbEntries = nil
	m.goGHSAEntries = make(map[string]*transformers.RelatedEntries)
	m.goGHSAOrder = nil
	return out
}

// handleEntry reconciles one govulndb record against the held GHSA records it
// aliases: patching matching GHSA affected packages with the record's
// go-imports qualifiers (recording amendments) and pruning covered affected
// packages from the GO record. Returns whether the GO record should still be
// written.
func (m *goVulnDBMerger) handleEntry(entry *transformers.RelatedEntries) bool {
	handle := entry.VulnerabilityHandle

	// unwrap first, so that every return path below leaves only plain handles on the entry
	replacements := unwrapGoVulnDBPackages(entry)

	if handle.BlobValue == nil {
		return true
	}
	if handle.Status == db.VulnerabilityRejected {
		// withdrawn advisories must not contribute symbol data; they are still
		// written (as rejected) so the withdrawal is represented
		return true
	}

	ghsaKeys := ghsaAliasKeys(handle.BlobValue.Aliases)
	if len(ghsaKeys) == 0 {
		return true
	}

	changesByGHSA := make(map[string][]string)
	var remaining []any
	remainingPackages := 0
	for i, rel := range entry.Related {
		aph, ok := rel.(db.AffectedPackageHandle)
		if !ok || aph.Package == nil {
			remaining = append(remaining, rel)
			continue
		}
		if m.reconcilePackage(aph, replacements[i], ghsaKeys, changesByGHSA) {
			log.WithFields("id", handle.Name, "package", aph.Package.Name).Trace("dropping govulndb affected package covered by a GHSA record")
			continue
		}
		remaining = append(remaining, rel)
		remainingPackages++
	}

	url := goVulnDBAdvisoryURL(handle.Name)
	for _, key := range ghsaKeys {
		changes := changesByGHSA[key]
		if len(changes) == 0 {
			continue
		}
		blob := m.goGHSAEntries[key].VulnerabilityHandle.BlobValue
		blob.Modifications = append(blob.Modifications, db.Modification{URL: url, Changes: changes})
	}

	entry.Related = remaining
	return remainingPackages > 0
}

// unwrapGoVulnDBPackages replaces any transformer merge-context wrappers on the entry with
// their plain affected package handles — the wrapper must never reach the write batches — and
// returns the pseudo-version replacement context, keyed by index into entry.Related.
func unwrapGoVulnDBPackages(entry *transformers.RelatedEntries) map[int]transformers.GoVulnDBAffectedPackage {
	replacements := make(map[int]transformers.GoVulnDBAffectedPackage)
	for i, rel := range entry.Related {
		wrapped, ok := rel.(transformers.GoVulnDBAffectedPackage)
		if !ok {
			continue
		}
		entry.Related[i] = wrapped.Handle
		if wrapped.PseudoVersionFix != "" && len(wrapped.CustomRanges) > 0 {
			replacements[i] = wrapped
		}
	}
	return replacements
}

// ghsaAliasKeys returns the lowercase GHSA IDs among the given aliases.
func ghsaAliasKeys(aliases []string) []string {
	var keys []string
	for _, alias := range aliases {
		if a := strings.ToLower(alias); strings.HasPrefix(a, "ghsa-") {
			keys = append(keys, a)
		}
	}
	return keys
}

// reconcilePackage patches every active aliased GHSA with one GO affected package's
// symbols — and its pseudo-version range replacement, when the transformer provided one (a zero
// wrapped value carries neither) — collecting amendment descriptions into changesByGHSA.
// Reports whether any GHSA covers the package's module.
func (m *goVulnDBMerger) reconcilePackage(aph db.AffectedPackageHandle, wrapped transformers.GoVulnDBAffectedPackage, ghsaKeys []string, changesByGHSA map[string][]string) (covered bool) {
	for _, key := range ghsaKeys {
		held := m.goGHSAEntries[key]
		if held == nil {
			continue
		}
		if held.VulnerabilityHandle.Status == db.VulnerabilityRejected {
			// a withdrawn GHSA never matches, so it can neither carry the
			// symbols nor cover the GO package — treating it as a merge
			// target would silently erase the advisory (e.g. GHSAs GitHub
			// withdrew as duplicates while the GO record stays active)
			continue
		}
		moduleMatched, changes := patchGHSAWithGoImports(held, aph)
		if len(wrapped.CustomRanges) > 0 {
			changes = append(changes, replaceGHSAPseudoVersionRanges(held, aph, wrapped)...)
		}
		covered = covered || moduleMatched
		changesByGHSA[key] = append(changesByGHSA[key], changes...)
	}
	return covered
}

// patchGHSAWithGoImports patches the held GHSA entry's affected packages with
// the go-imports qualifier from one govulndb affected package. A GHSA package
// named after the module receives all of its imports; a GHSA package named
// after one of the import paths (a sub-package listed separately, e.g.
// golang.org/x/net/http2) receives just that import. Returns whether the module
// itself is an affected package on the GHSA — which is what makes the govulndb
// package "covered" — and a description of each amendment actually made.
func patchGHSAWithGoImports(held *transformers.RelatedEntries, goAPH db.AffectedPackageHandle) (moduleMatched bool, changes []string) {
	moduleName := goAPH.Package.Name
	var goImports []db.GoImport
	if goAPH.BlobValue != nil && goAPH.BlobValue.Qualifiers != nil {
		goImports = goAPH.BlobValue.Qualifiers.GoImports
	}

	for _, rel := range held.Related {
		ghsaAPH, ok := rel.(db.AffectedPackageHandle)
		if !ok || ghsaAPH.Package == nil || ghsaAPH.BlobValue == nil {
			continue
		}

		// name comparisons are case-insensitive to match grype's own package
		// equality semantics (packages are stored and matched collate nocase),
		// e.g. a GHSA row for github.com/Kava-Labs/kava and the govulndb module
		// github.com/kava-labs/kava resolve to the same package at match time
		var toAdd []db.GoImport
		if strings.EqualFold(ghsaAPH.Package.Name, moduleName) {
			moduleMatched = true
			toAdd = goImports
		} else {
			for _, imp := range goImports {
				if strings.EqualFold(ghsaAPH.Package.Name, imp.Path) {
					toAdd = append(toAdd, imp)
				}
			}
		}

		for _, imp := range addGoImports(ghsaAPH.BlobValue, toAdd) {
			changes = append(changes, fmt.Sprintf("added vulnerable go symbols for import %s to affected package %s", imp.Path, ghsaAPH.Package.Name))
		}
	}
	return moduleMatched, changes
}

// replaceGHSAPseudoVersionRanges swaps a GHSA affected package's pseudo-version range for the
// govulndb record's custom_ranges equivalent in the module's real (tag) versioning.
//
// Modules that don't follow Go module versioning get GHSA ranges pinned to the pseudo-version
// of the fix commit (e.g. GHSA-4c49-9fpc-hc3v: lxd "<0.0.0-20240708073652-5a492a3f0036"). Real
// tagged releases like lxd v5.21.1 sort far ABOVE any v0.0.0-… pseudo-version, so such a range
// can never match a real tag — a guaranteed false negative. govulndb carries the same fix in
// tag space in ecosystem_specific.custom_ranges ("<5.21.2" for GO-2024-3312), and the
// transformer forwards that pairing on the wrapper (see pseudoVersionReplacement).
//
// Deliberately conservative, mirroring the branch spec:
//   - the GHSA package must carry exactly one range — with more we cannot know which range
//     pairs with which custom window, so it is left alone
//   - that range's fix must be the exact pseudo-version the GO record's standard range carried;
//     the embedded commit hash pins both feeds to the same fix commit, so the two ranges are
//     the same window expressed in two version spaces
//
// Amendments are reported back so the caller records them on the GHSA blob's Modifications.
func replaceGHSAPseudoVersionRanges(held *transformers.RelatedEntries, goAPH db.AffectedPackageHandle, wrapped transformers.GoVulnDBAffectedPackage) (changes []string) {
	for _, rel := range held.Related {
		ghsaAPH, ok := rel.(db.AffectedPackageHandle)
		if !ok || ghsaAPH.Package == nil || ghsaAPH.BlobValue == nil {
			continue
		}
		if !strings.EqualFold(ghsaAPH.Package.Name, goAPH.Package.Name) {
			continue
		}
		if len(ghsaAPH.BlobValue.Ranges) != 1 {
			continue
		}
		rng := ghsaAPH.BlobValue.Ranges[0]
		if rng.Fix == nil || rng.Fix.Version != wrapped.PseudoVersionFix {
			continue
		}
		replacement := append([]db.Range(nil), wrapped.CustomRanges...)
		for i := range replacement {
			// custom_ranges carry no fix-availability data, so keep the GHSA's original fix
			// date on the replacement — dropping it would fail failOnMissingFixDate builds
			// and lose the date from db search output. Copy the Fix rather than mutating it:
			// the wrapper's ranges are shared across every GHSA row this wrapper patches.
			if replacement[i].Fix == nil || replacement[i].Fix.Detail != nil {
				continue
			}
			fix := *replacement[i].Fix
			fix.Detail = rng.Fix.Detail
			replacement[i].Fix = &fix
		}
		ghsaAPH.BlobValue.Ranges = replacement
		changes = append(changes, fmt.Sprintf("replaced pseudo-version range %q with %q for affected package %s",
			rng.Version.Constraint, rangeConstraints(wrapped.CustomRanges), ghsaAPH.Package.Name))
	}
	return changes
}

// rangeConstraints renders the ranges' version constraints as a single OR-joined string, for
// amendment messages.
func rangeConstraints(ranges []db.Range) string {
	var constraints []string
	for _, r := range ranges {
		constraints = append(constraints, r.Version.Constraint)
	}
	return strings.Join(constraints, " || ")
}

// addGoImports appends the given imports to the blob's go-imports qualifier,
// skipping paths already present (e.g. from a second affected entry for the same
// module with a disjoint version window). Returns the imports actually added.
func addGoImports(blob *db.PackageBlob, imports []db.GoImport) []db.GoImport {
	if len(imports) == 0 {
		return nil
	}
	existing := make(map[string]bool)
	if blob.Qualifiers != nil {
		for _, imp := range blob.Qualifiers.GoImports {
			existing[imp.Path] = true
		}
	}
	var added []db.GoImport
	for _, imp := range imports {
		if existing[imp.Path] {
			continue
		}
		existing[imp.Path] = true
		added = append(added, imp)
	}
	if len(added) == 0 {
		return nil
	}
	if blob.Qualifiers == nil {
		blob.Qualifiers = &db.PackageQualifiers{}
	}
	blob.Qualifiers.GoImports = append(blob.Qualifiers.GoImports, added...)
	return added
}

// goVulnDBAdvisoryURL returns the canonical vuln.go.dev JSON document for a
// GO-* advisory ID, used as the amendment source URL.
func goVulnDBAdvisoryURL(id string) string {
	return fmt.Sprintf("https://vuln.go.dev/ID/%s.json", id)
}
