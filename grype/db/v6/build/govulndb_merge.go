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
// reachability (ecosystem_specific.imports). Writing both would surface the same
// CVE twice — once symbol-filtered, once not — undoing the false-positive
// reduction the go-imports qualifier provides.
//
// During the streaming pass the writer holds back Go-ecosystem GHSA entries and
// all govulndb entries; at Close time handleGoVulnDBEntry runs per GO record:
//   - each GHSA affected package whose name matches the GO record's module path
//     (or one of its import paths — GHSAs sometimes list sub-packages like
//     golang.org/x/net/http2 as separate affected packages) is patched with the
//     matching go-imports qualifier, and the amendment is recorded on the GHSA
//     blob's Modifications.
//   - a GO affected package whose module is present on any aliased GHSA is
//     covered: it is dropped from the GO record. The GO record itself is written
//     only if affected packages remain (stdlib always remains — GHSA never
//     covers it — as do modules the GHSA lacks); otherwise it is dropped.
//
// Coverage intentionally ignores version-range differences between the two
// feeds: the GHSA's ranges win. Where they disagree materially (a govulndb
// package that is open-ended while the GHSA is bounded), the package is not
// following Go module versioning correctly and the GHSA ranges are usually the
// better ones.
//
// Reconciling at Close makes the merge independent of provider processing order.

// holdForGoVulnDBMerge diverts entries that participate in the govulndb↔GHSA
// reconciliation into the writer's held collections, returning true when the
// entry was held (and so must not be batched yet).
func (w *writer) holdForGoVulnDBMerge(entry transformers.RelatedEntries) bool {
	if entry.VulnerabilityHandle == nil {
		return false
	}
	name := strings.ToLower(entry.VulnerabilityHandle.Name)
	switch {
	case strings.HasPrefix(name, "go-"):
		w.govulndbEntries = append(w.govulndbEntries, &entry)
		return true
	case strings.HasPrefix(name, "ghsa-") && hasGoModulePackages(entry):
		if _, exists := w.goGHSAEntries[name]; exists {
			// a second Go-ecosystem record with the same GHSA ID should not happen;
			// write it through rather than silently replacing the held one
			log.WithFields("id", entry.VulnerabilityHandle.Name).Warn("duplicate go-ecosystem GHSA record; skipping govulndb reconciliation for it")
			return false
		}
		w.goGHSAEntries[name] = &entry
		w.goGHSAOrder = append(w.goGHSAOrder, name)
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

// flushGoVulnDBMerge reconciles all held govulndb entries against the held GHSA
// entries, then writes the (patched) GHSA entries and surviving govulndb entries
// through the normal batching path. Called once from Close.
func (w *writer) flushGoVulnDBMerge() error {
	var surviving []*transformers.RelatedEntries
	for _, entry := range w.govulndbEntries {
		if w.handleGoVulnDBEntry(entry) {
			surviving = append(surviving, entry)
		} else {
			log.WithFields("id", entry.VulnerabilityHandle.Name).Trace("dropping govulndb record fully covered by GHSA records")
		}
	}

	for _, key := range w.goGHSAOrder {
		if err := w.writeEntryToBatch(*w.goGHSAEntries[key]); err != nil {
			return fmt.Errorf("unable to write held GHSA entry %q: %w", key, err)
		}
	}
	for _, entry := range surviving {
		if err := w.writeEntryToBatch(*entry); err != nil {
			return fmt.Errorf("unable to write held govulndb entry %q: %w", entry.VulnerabilityHandle.Name, err)
		}
	}

	w.govulndbEntries = nil
	w.goGHSAEntries = make(map[string]*transformers.RelatedEntries)
	w.goGHSAOrder = nil
	return nil
}

// handleGoVulnDBEntry reconciles one govulndb record against the held GHSA
// records it aliases: patching matching GHSA affected packages with the record's
// go-imports qualifiers (recording amendments) and pruning covered affected
// packages from the GO record. Returns whether the GO record should still be
// written.
func (w *writer) handleGoVulnDBEntry(entry *transformers.RelatedEntries) bool {
	handle := entry.VulnerabilityHandle
	if handle.BlobValue == nil {
		return true
	}
	if handle.Status == db.VulnerabilityRejected {
		// withdrawn advisories must not contribute symbol data; they are still
		// written (as rejected) so the withdrawal is represented
		return true
	}

	var ghsaKeys []string
	for _, alias := range handle.BlobValue.Aliases {
		if a := strings.ToLower(alias); strings.HasPrefix(a, "ghsa-") {
			ghsaKeys = append(ghsaKeys, a)
		}
	}
	if len(ghsaKeys) == 0 {
		return true
	}

	changesByGHSA := make(map[string][]string)
	var remaining []any
	remainingPackages := 0
	for _, rel := range entry.Related {
		aph, ok := rel.(db.AffectedPackageHandle)
		if !ok || aph.Package == nil {
			remaining = append(remaining, rel)
			continue
		}
		covered := false
		for _, key := range ghsaKeys {
			held := w.goGHSAEntries[key]
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
			covered = covered || moduleMatched
			changesByGHSA[key] = append(changesByGHSA[key], changes...)
		}
		if covered {
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
		blob := w.goGHSAEntries[key].VulnerabilityHandle.BlobValue
		blob.Modifications = append(blob.Modifications, db.Modification{URL: url, Changes: changes})
	}

	entry.Related = remaining
	return remainingPackages > 0
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

		var toAdd []db.GoImport
		if ghsaAPH.Package.Name == moduleName {
			moduleMatched = true
			toAdd = goImports
		} else {
			for _, imp := range goImports {
				if ghsaAPH.Package.Name == imp.Path {
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
