package v6

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/syft/syft/pkg"
)

func goModuleAPH(name string, imports ...db.GoImport) db.AffectedPackageHandle {
	var qualifiers *db.PackageQualifiers
	if len(imports) > 0 {
		qualifiers = &db.PackageQualifiers{GoImports: imports}
	}
	return db.AffectedPackageHandle{
		Package: &db.Package{Ecosystem: string(pkg.GoModulePkg), Name: name},
		BlobValue: &db.PackageBlob{
			Qualifiers: qualifiers,
		},
	}
}

func goVulnEntry(id string, aliases []string, aphs ...db.AffectedPackageHandle) transformers.RelatedEntries {
	entry := transformers.RelatedEntries{
		VulnerabilityHandle: &db.VulnerabilityHandle{
			Name:       id,
			ProviderID: "govulndb",
			Provider:   &db.Provider{ID: "govulndb"},
			Status:     db.VulnerabilityActive,
			BlobValue:  &db.VulnerabilityBlob{ID: id, Aliases: aliases},
		},
	}
	for _, aph := range aphs {
		entry.Related = append(entry.Related, aph)
	}
	return entry
}

func ghsaEntry(id string, aphs ...db.AffectedPackageHandle) transformers.RelatedEntries {
	entry := transformers.RelatedEntries{
		VulnerabilityHandle: &db.VulnerabilityHandle{
			Name:       id,
			ProviderID: "github",
			Provider:   &db.Provider{ID: "github"},
			Status:     db.VulnerabilityActive,
			BlobValue:  &db.VulnerabilityBlob{ID: id},
		},
	}
	for _, aph := range aphs {
		entry.Related = append(entry.Related, aph)
	}
	return entry
}

// newMergeTestWriter returns a writer suitable for exercising the hold and
// reconcile logic in isolation: no store is attached, and the batch thresholds
// are high enough that nothing tries to touch one.
func newMergeTestWriter() *writer {
	return &writer{
		providerCache:   make(map[string]db.Provider),
		severityCache:   make(map[string]db.Severity),
		goGHSAEntries:   make(map[string]*transformers.RelatedEntries),
		parentBatchSize: 10000,
		childBatchSize:  10000,
	}
}

func heldGHSA(t *testing.T, w *writer, id string) *transformers.RelatedEntries {
	t.Helper()
	held := w.goGHSAEntries[id]
	require.NotNil(t, held, "expected GHSA %q to be held", id)
	return held
}

func affectedPackageNames(entry transformers.RelatedEntries) []string {
	var names []string
	for _, rel := range entry.Related {
		if aph, ok := rel.(db.AffectedPackageHandle); ok && aph.Package != nil {
			names = append(names, aph.Package.Name)
		}
	}
	return names
}

func goImportsOf(t *testing.T, entry *transformers.RelatedEntries, pkgName string) []db.GoImport {
	t.Helper()
	for _, rel := range entry.Related {
		aph, ok := rel.(db.AffectedPackageHandle)
		if !ok || aph.Package == nil || aph.Package.Name != pkgName {
			continue
		}
		if aph.BlobValue == nil || aph.BlobValue.Qualifiers == nil {
			return nil
		}
		return aph.BlobValue.Qualifiers.GoImports
	}
	t.Fatalf("affected package %q not found on entry %q", pkgName, entry.VulnerabilityHandle.Name)
	return nil
}

func TestHoldForGoVulnDBMerge(t *testing.T) {
	tests := []struct {
		name     string
		entry    transformers.RelatedEntries
		wantHold bool
	}{
		{
			name:     "govulndb record is held",
			entry:    goVulnEntry("GO-2022-0969", nil, goModuleAPH("stdlib")),
			wantHold: true,
		},
		{
			name:     "go-ecosystem GHSA is held",
			entry:    ghsaEntry("GHSA-69cg-p879-7622", goModuleAPH("golang.org/x/net")),
			wantHold: true,
		},
		{
			name: "non-go GHSA flows through",
			entry: ghsaEntry("GHSA-aaaa-bbbb-cccc", db.AffectedPackageHandle{
				Package:   &db.Package{Ecosystem: "npm", Name: "lodash"},
				BlobValue: &db.PackageBlob{},
			}),
			wantHold: false,
		},
		{
			name: "nvd CVE record flows through",
			entry: transformers.RelatedEntries{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:      "CVE-2022-27664",
					BlobValue: &db.VulnerabilityBlob{ID: "CVE-2022-27664"},
				},
			},
			wantHold: false,
		},
		{
			name:     "entry without a vulnerability handle flows through",
			entry:    transformers.RelatedEntries{},
			wantHold: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newMergeTestWriter()
			assert.Equal(t, tt.wantHold, w.holdForGoVulnDBMerge(tt.entry))
		})
	}

	t.Run("duplicate go-ecosystem GHSA is not held twice", func(t *testing.T) {
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-69cg-p879-7622", goModuleAPH("golang.org/x/net"))))
		assert.False(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-69cg-p879-7622", goModuleAPH("golang.org/x/net"))))
		assert.Len(t, w.goGHSAOrder, 1)
	})
}

func TestHandleGoVulnDBEntry(t *testing.T) {
	xnetImports := []db.GoImport{{Path: "golang.org/x/net/http2", Symbols: []string{"Server.ServeConn", "serverConn.goAway"}}}
	stdlibImports := []db.GoImport{{Path: "net/http", Symbols: []string{"ListenAndServe"}}}
	gjsonImports := []db.GoImport{{Path: "github.com/tidwall/gjson", Symbols: []string{"Get", "GetBytes"}}}

	t.Run("mixed stdlib and x record: x covered by GHSA, stdlib remains", func(t *testing.T) {
		// GO-2022-0969 shape: the GHSA lists both the module and the http2
		// sub-package as separate affected packages (the "bad news" case); the
		// stdlib package is absent from GHSA and must survive on the GO record.
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-69cg-p879-7622",
			goModuleAPH("golang.org/x/net"),
			goModuleAPH("golang.org/x/net/http2"),
		)))

		entry := goVulnEntry("GO-2022-0969", []string{"CVE-2022-27664", "GHSA-69cg-p879-7622"},
			goModuleAPH("stdlib", stdlibImports...),
			goModuleAPH("golang.org/x/net", xnetImports...),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		require.True(t, keep, "stdlib remains, so the GO record must be written")
		assert.Equal(t, []string{"stdlib"}, affectedPackageNames(entry))

		held := heldGHSA(t, w, "ghsa-69cg-p879-7622")
		// module-named GHSA package gets all imports; sub-package-named one gets its own import
		assert.Equal(t, xnetImports, goImportsOf(t, held, "golang.org/x/net"))
		assert.Equal(t, xnetImports, goImportsOf(t, held, "golang.org/x/net/http2"))

		mods := held.VulnerabilityHandle.BlobValue.Modifications
		require.Len(t, mods, 1)
		assert.Equal(t, "https://vuln.go.dev/ID/GO-2022-0969.json", mods[0].URL)
		assert.Equal(t, []string{
			"added vulnerable go symbols for import golang.org/x/net/http2 to affected package golang.org/x/net",
			"added vulnerable go symbols for import golang.org/x/net/http2 to affected package golang.org/x/net/http2",
		}, mods[0].Changes)
	})

	t.Run("fully covered record across multiple GHSAs is dropped", func(t *testing.T) {
		// GO-2021-0265 shape: one module, two GHSA aliases; both get patched and
		// the GO record has nothing left to say. GO-2022-0536 is the same fan-out
		// with both GHSAs active in the real data (distinct CVEs sharing one GO
		// record); both siblings receive the record's full symbol set.
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-c9gm-7rfj-8w5h", goModuleAPH("github.com/tidwall/gjson"))))
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-ppj4-34rq-v8j9", goModuleAPH("github.com/tidwall/gjson"))))

		entry := goVulnEntry("GO-2021-0265", []string{"CVE-2021-42248", "GHSA-c9gm-7rfj-8w5h", "GHSA-ppj4-34rq-v8j9"},
			goModuleAPH("github.com/tidwall/gjson", gjsonImports...),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.False(t, keep, "fully covered GO record must be dropped")
		for _, id := range []string{"ghsa-c9gm-7rfj-8w5h", "ghsa-ppj4-34rq-v8j9"} {
			held := heldGHSA(t, w, id)
			assert.Equal(t, gjsonImports, goImportsOf(t, held, "github.com/tidwall/gjson"))
			require.Len(t, held.VulnerabilityHandle.BlobValue.Modifications, 1, "GHSA %s", id)
		}
	})

	t.Run("aliased GHSA absent from the build leaves the record intact", func(t *testing.T) {
		w := newMergeTestWriter()
		entry := goVulnEntry("GO-2021-0265", []string{"GHSA-c9gm-7rfj-8w5h"},
			goModuleAPH("github.com/tidwall/gjson", gjsonImports...),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.True(t, keep)
		assert.Equal(t, []string{"github.com/tidwall/gjson"}, affectedPackageNames(entry))
	})

	t.Run("record without GHSA aliases is untouched", func(t *testing.T) {
		w := newMergeTestWriter()
		entry := goVulnEntry("GO-2024-0001", []string{"CVE-2024-0001"}, goModuleAPH("example.com/mod"))
		assert.True(t, w.handleGoVulnDBEntry(&entry))
		assert.Equal(t, []string{"example.com/mod"}, affectedPackageNames(entry))
	})

	t.Run("withdrawn record patches nothing and is still written", func(t *testing.T) {
		// the GO-withdrawn/GHSA-active shape (canonically GO-2022-0617 / GHSA-qh36-44jv-c8xj,
		// the only such pair in the wild): the rejected GO record must not contribute symbol
		// data, and the active GHSA stays as published
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-c9gm-7rfj-8w5h", goModuleAPH("github.com/tidwall/gjson"))))

		entry := goVulnEntry("GO-2021-0265", []string{"GHSA-c9gm-7rfj-8w5h"},
			goModuleAPH("github.com/tidwall/gjson", gjsonImports...),
		)
		entry.VulnerabilityHandle.Status = db.VulnerabilityRejected
		keep := w.handleGoVulnDBEntry(&entry)

		assert.True(t, keep, "withdrawn records are written (as rejected), not dropped")
		held := heldGHSA(t, w, "ghsa-c9gm-7rfj-8w5h")
		assert.Nil(t, goImportsOf(t, held, "github.com/tidwall/gjson"), "withdrawn records must not contribute symbols")
		assert.Empty(t, held.VulnerabilityHandle.BlobValue.Modifications)
	})

	t.Run("withdrawn GHSA is neither patched nor allowed to cover", func(t *testing.T) {
		// GitHub withdraws GHSAs (e.g. as duplicate advisories) while the GO
		// record stays active — 24 such pairs in the wild, e.g. GO-2021-0142 /
		// GHSA-q6gq-997w-f55g and this test's GO-2021-0265 / GHSA-c9gm-7rfj-8w5h.
		// A rejected record never matches, so letting it
		// cover the GO package would erase the advisory entirely; the module is
		// covered only when an ACTIVE GHSA lists it.
		w := newMergeTestWriter()
		withdrawn := ghsaEntry("GHSA-c9gm-7rfj-8w5h", goModuleAPH("github.com/tidwall/gjson"))
		withdrawn.VulnerabilityHandle.Status = db.VulnerabilityRejected
		require.True(t, w.holdForGoVulnDBMerge(withdrawn))

		entry := goVulnEntry("GO-2021-0265", []string{"GHSA-c9gm-7rfj-8w5h"},
			goModuleAPH("github.com/tidwall/gjson", gjsonImports...),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.True(t, keep, "a module covered only by withdrawn GHSAs must stay on the GO record")
		assert.Equal(t, []string{"github.com/tidwall/gjson"}, affectedPackageNames(entry))
		held := heldGHSA(t, w, "ghsa-c9gm-7rfj-8w5h")
		assert.Nil(t, goImportsOf(t, held, "github.com/tidwall/gjson"))
		assert.Empty(t, held.VulnerabilityHandle.BlobValue.Modifications)
	})

	t.Run("alternate-name GHSA package is not patched and does not cover", func(t *testing.T) {
		// GO-2024-2826 shape: the GHSA also lists the same project under
		// github.com/vitessio/vitess (upstream-tag version space); only the
		// name-matched package participates in the merge.
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-649x-hxfx-57j2",
			goModuleAPH("vitess.io/vitess"),
			goModuleAPH("github.com/vitessio/vitess"),
		)))

		vitessImports := []db.GoImport{{Path: "vitess.io/vitess/go/vt/vtgate/evalengine", Symbols: []string{"NewLiteralString"}}}
		entry := goVulnEntry("GO-2024-2826", []string{"GHSA-649x-hxfx-57j2"},
			goModuleAPH("vitess.io/vitess", vitessImports...),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.False(t, keep, "the module itself is on the GHSA, so the GO record is covered")
		held := heldGHSA(t, w, "ghsa-649x-hxfx-57j2")
		assert.Equal(t, vitessImports, goImportsOf(t, held, "vitess.io/vitess"))
		assert.Nil(t, goImportsOf(t, held, "github.com/vitessio/vitess"), "alternate-name package keeps module-granularity matching")
	})

	t.Run("major-version module the GHSA collapsed survives on the GO record", func(t *testing.T) {
		// GO-2025-4004 shape: GHSA lists only github.com/lxc/lxd; the GO record's
		// separate /v6 module has no GHSA counterpart and must be written.
		//
		// This deliberately does NOT dedupe /vN major-version variants against the base
		// module (the GO-2025-3540 / go-redis shape): at match time a /vN-pathed package
		// only matches a /vN-named row, so dropping the variant because the base module is
		// on the GHSA would be a guaranteed false negative for /vN packages. Coverage is
		// decided per exact affected.package.name (case-insensitive), per the decision that
		// a govulndb package the aliased GHSA lacks is always kept.
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-w2hg-2v4p-vmh6", goModuleAPH("github.com/lxc/lxd"))))

		entry := goVulnEntry("GO-2025-4004", []string{"GHSA-w2hg-2v4p-vmh6"},
			goModuleAPH("github.com/lxc/lxd"),
			goModuleAPH("github.com/lxc/lxd/v6"),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.True(t, keep)
		assert.Equal(t, []string{"github.com/lxc/lxd/v6"}, affectedPackageNames(entry))
	})

	t.Run("covered package without symbols leaves no modification", func(t *testing.T) {
		// unreviewed records rarely carry symbols; the dedup (drop the GO package) still
		// applies, but the GHSA is not modified — including its ranges, which stay exactly
		// as published even when the two feeds disagree (the GO-2024-2924 /
		// GHSA-7jp9-vgmq-c8r5 shape: the GHSA has the better range and govulndb adds nothing)
		w := newMergeTestWriter()
		ghsaRange := db.Range{
			Version: db.Version{Type: "go", Constraint: "<1.9.3"},
			Fix:     &db.Fix{Version: "1.9.3", State: db.FixedStatus},
		}
		ghsaAPH := goModuleAPH("github.com/tidwall/gjson")
		ghsaAPH.BlobValue.Ranges = []db.Range{ghsaRange}
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-c9gm-7rfj-8w5h", ghsaAPH)))

		entry := goVulnEntry("GO-2021-0265", []string{"GHSA-c9gm-7rfj-8w5h"},
			goModuleAPH("github.com/tidwall/gjson"),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.False(t, keep)
		held := heldGHSA(t, w, "ghsa-c9gm-7rfj-8w5h")
		assert.Nil(t, goImportsOf(t, held, "github.com/tidwall/gjson"))
		assert.Empty(t, held.VulnerabilityHandle.BlobValue.Modifications)
		gotAPH, ok := held.Related[0].(db.AffectedPackageHandle)
		require.True(t, ok)
		assert.Equal(t, []db.Range{ghsaRange}, gotAPH.BlobValue.Ranges, "GHSA ranges must stay as published")
	})

	t.Run("sub-package-only GHSA match patches but does not cover", func(t *testing.T) {
		// the path-hiding shape (canonically GO-2024-2687 / GHSA-4v7x-pqxf-cx7m, where the
		// GHSA lists 3 affected packages against govulndb's 2 because sub-packages hide as
		// import paths under ecosystem_specific): if a GHSA lists only the sub-package,
		// dropping the GO record's module package would leave module-named packages
		// matching nothing
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-69cg-p879-7622", goModuleAPH("golang.org/x/net/http2"))))

		entry := goVulnEntry("GO-2022-0969", []string{"GHSA-69cg-p879-7622"},
			goModuleAPH("golang.org/x/net", xnetImports...),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.True(t, keep, "module not on the GHSA -> not covered")
		assert.Equal(t, []string{"golang.org/x/net"}, affectedPackageNames(entry))
		held := heldGHSA(t, w, "ghsa-69cg-p879-7622")
		assert.Equal(t, xnetImports, goImportsOf(t, held, "golang.org/x/net/http2"))
		require.Len(t, held.VulnerabilityHandle.BlobValue.Modifications, 1)
	})

	t.Run("stdlib import-path rows on a GHSA are patched but never cover stdlib", func(t *testing.T) {
		// GO-2024-2687 / GHSA-4v7x-pqxf-cx7m shape: the GHSA lists stdlib's
		// net/http import path as package rows (twice — one per stdlib version
		// window) alongside the x/net module and its http2 sub-package. The
		// net/http rows are patched with the stdlib symbols via the import-path
		// match, but no GHSA row is named "stdlib", so the stdlib package is not
		// covered and stays on the GO record; the x/net module is covered.
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-4v7x-pqxf-cx7m",
			goModuleAPH("net/http"),
			goModuleAPH("golang.org/x/net/http2"),
			goModuleAPH("net/http"),
			goModuleAPH("golang.org/x/net"),
		)))

		netHTTPImports := []db.GoImport{{Path: "net/http", Symbols: []string{"ServeContent", "ServeFile"}}}
		entry := goVulnEntry("GO-2024-2687", []string{"CVE-2023-45288", "GHSA-4v7x-pqxf-cx7m"},
			goModuleAPH("stdlib", netHTTPImports...),
			goModuleAPH("golang.org/x/net", xnetImports...),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		require.True(t, keep, "stdlib is never dropped: no GHSA row is named stdlib")
		assert.Equal(t, []string{"stdlib"}, affectedPackageNames(entry))

		held := heldGHSA(t, w, "ghsa-4v7x-pqxf-cx7m")
		// every row got its matching symbols: both net/http rows from the stdlib
		// package's import, the module and sub-package rows from x/net's
		var netHTTPRows int
		for _, rel := range held.Related {
			aph := rel.(db.AffectedPackageHandle)
			if aph.Package.Name == "net/http" {
				netHTTPRows++
				assert.Equal(t, netHTTPImports, aph.BlobValue.Qualifiers.GoImports)
			}
		}
		assert.Equal(t, 2, netHTTPRows)
		assert.Equal(t, xnetImports, goImportsOf(t, held, "golang.org/x/net"))
		assert.Equal(t, xnetImports, goImportsOf(t, held, "golang.org/x/net/http2"))

		mods := held.VulnerabilityHandle.BlobValue.Modifications
		require.Len(t, mods, 1)
		assert.Len(t, mods[0].Changes, 4, "one change per patched row")
	})

	t.Run("name matching is case-insensitive, like grype's package matching", func(t *testing.T) {
		// GO-2022-0760 shape: the GHSA row is github.com/Kava-Labs/kava while the
		// govulndb module is github.com/kava-labs/kava. Packages are stored and
		// matched collate nocase, so at match time these are the same package —
		// the merge must treat them as the same too, or the GHSA row would keep
		// matching binaries unfiltered while the GO package is also written.
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-f92v-grc2-w2fg", goModuleAPH("github.com/Kava-Labs/kava"))))

		kavaImports := []db.GoImport{{Path: "github.com/kava-labs/kava/app", Symbols: []string{"NewApp"}}}
		entry := goVulnEntry("GO-2022-0760", []string{"GHSA-f92v-grc2-w2fg"},
			goModuleAPH("github.com/kava-labs/kava", kavaImports...),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.False(t, keep, "case-insensitively matched module must be covered")
		held := heldGHSA(t, w, "ghsa-f92v-grc2-w2fg")
		assert.Equal(t, kavaImports, goImportsOf(t, held, "github.com/Kava-Labs/kava"))
	})

	t.Run("repeated module entries dedupe imports and changes", func(t *testing.T) {
		// some records list the same module twice with disjoint version windows;
		// the GHSA package must not accumulate duplicate imports or changes
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-c9gm-7rfj-8w5h", goModuleAPH("github.com/tidwall/gjson"))))

		entry := goVulnEntry("GO-2021-0265", []string{"GHSA-c9gm-7rfj-8w5h"},
			goModuleAPH("github.com/tidwall/gjson", gjsonImports...),
			goModuleAPH("github.com/tidwall/gjson", gjsonImports...),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.False(t, keep)
		held := heldGHSA(t, w, "ghsa-c9gm-7rfj-8w5h")
		assert.Equal(t, gjsonImports, goImportsOf(t, held, "github.com/tidwall/gjson"))
		mods := held.VulnerabilityHandle.BlobValue.Modifications
		require.Len(t, mods, 1)
		assert.Len(t, mods[0].Changes, 1)
	})
}

// TestGoVulnDBPseudoVersionRangeReplacement covers the spec's pseudo-version reconciliation,
// using the real shape of GO-2024-3312 / GHSA-4c49-9fpc-hc3v (lxd, CVE-2024-6156):
//
//	GHSA-4c49-9fpc-hc3v range:      <0.0.0-20240708073652-5a492a3f0036   (pseudo-version)
//	GO-2024-3312 standard range:    <0.0.0-20240708073652-5a492a3f0036   (same pseudo-version)
//	GO-2024-3312 custom_ranges:     <5.21.2                              (real tag versioning)
//
// LXD does not follow Go module versioning (its releases are not go-module tags), so GitHub pins
// the advisory to the pseudo-version of the fix commit. Under semver ordering every real tagged
// release (v5.21.1, v5.21.0, …) sorts far ABOVE v0.0.0-… pseudo-versions, which means the GHSA
// range as published can never match a real tagged version — a guaranteed false negative for any
// SBOM that reports the tag. govulndb carries the same fix in tag space in custom_ranges, and
// the transformer forwards the pairing on the GoVulnDBAffectedPackage wrapper (see
// pseudoVersionReplacement). Here the merge must swap the GHSA's range for the tag-space window.
//
// The replacement preconditions come straight from the branch spec and are deliberately strict:
//
//  1. the GO record's standard range must carry the exact pseudo-version the GHSA is pinned to
//     (the commit hash pins both feeds to the same fix commit — same window, two version
//     spaces). Checked via Fix.Version equality with the wrapper's PseudoVersionFix.
//  2. exactly one range on each side (one standard + one custom on the GO record, enforced by
//     the transformer; one range on the GHSA package, enforced here). With more, the
//     standard↔custom pairing is ambiguous and we must leave the GHSA alone.
//
// Everything else about the merge is unchanged: the module is still covered (the GO package is
// still dropped), symbols are still patched, and the replacement is recorded on the GHSA blob's
// Modifications audit trail.
func TestGoVulnDBPseudoVersionRangeReplacement(t *testing.T) {
	const pseudoFix = "0.0.0-20240708073652-5a492a3f0036"

	// the GHSA range carries a fix-availability date from vunnel; custom_ranges never do, so
	// the replacement must retain the GHSA's date (failOnMissingFixDate builds reject fixed
	// ranges without one)
	fixDate := time.Date(2024, time.December, 9, 0, 0, 0, 0, time.UTC)
	ghsaFixDetail := &db.FixDetail{Available: &db.FixAvailability{Date: &fixDate, Kind: "first-observed"}}

	pseudoRange := db.Range{
		Version: db.Version{Type: "go", Constraint: "<" + pseudoFix},
		Fix:     &db.Fix{Version: pseudoFix, State: db.FixedStatus, Detail: ghsaFixDetail},
	}
	tagRange := db.Range{
		Version: db.Version{Type: "go", Constraint: "<5.21.2"},
		Fix:     &db.Fix{Version: "5.21.2", State: db.FixedStatus},
	}
	tagRangeWithGHSADate := db.Range{
		Version: db.Version{Type: "go", Constraint: "<5.21.2"},
		Fix:     &db.Fix{Version: "5.21.2", State: db.FixedStatus, Detail: ghsaFixDetail},
	}
	lxdImports := []db.GoImport{{Path: "github.com/canonical/lxd/lxd", Symbols: []string{"allowProjectResourceList"}}}

	ghsaLxdAPH := func(ranges ...db.Range) db.AffectedPackageHandle {
		aph := goModuleAPH("github.com/canonical/lxd")
		aph.BlobValue.Ranges = ranges
		return aph
	}
	// the GO blob carries the union of both windows (see mergeWithCustom); which one came from
	// custom_ranges is precisely the provenance the wrapper preserves — it cannot be recovered
	// from the blob's ranges alone (a two-window record like json-patch GO-2021-0076 looks
	// identical there, and replacing based on that shape would corrupt its GHSA)
	goLxdWrapped := func() transformers.GoVulnDBAffectedPackage {
		handle := goModuleAPH("github.com/canonical/lxd", lxdImports...)
		handle.BlobValue.Ranges = []db.Range{pseudoRange, tagRange}
		return transformers.GoVulnDBAffectedPackage{
			Handle:           handle,
			PseudoVersionFix: pseudoFix,
			CustomRanges:     []db.Range{tagRange},
		}
	}
	goEntryWith := func(aliases []string, rel any) transformers.RelatedEntries {
		entry := goVulnEntry("GO-2024-3312", aliases)
		entry.Related = append(entry.Related, rel)
		return entry
	}
	lxdAliases := []string{"CVE-2024-6156", "GHSA-4c49-9fpc-hc3v"}

	t.Run("GHSA range pinned to the fix commit's pseudo-version is replaced", func(t *testing.T) {
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-4c49-9fpc-hc3v", ghsaLxdAPH(pseudoRange))))

		wrapped := goLxdWrapped()
		entry := goEntryWith(lxdAliases, wrapped)
		keep := w.handleGoVulnDBEntry(&entry)

		// the module is on the GHSA, so the GO record is covered and dropped as usual
		assert.False(t, keep, "lxd is covered by the GHSA, so the GO record must be dropped")

		held := heldGHSA(t, w, "ghsa-4c49-9fpc-hc3v")
		aph, ok := held.Related[0].(db.AffectedPackageHandle)
		require.True(t, ok)
		assert.Equal(t, []db.Range{tagRangeWithGHSADate}, aph.BlobValue.Ranges,
			"the pseudo-version range must be replaced by the tag-space window, keeping the GHSA's fix date")
		assert.Equal(t, []db.Range{tagRange}, wrapped.CustomRanges,
			"the wrapper's own ranges must not be mutated by the fix-date carry-over")
		assert.Equal(t, lxdImports, goImportsOf(t, held, "github.com/canonical/lxd"),
			"symbol patching is unaffected by the range replacement")

		mods := held.VulnerabilityHandle.BlobValue.Modifications
		require.Len(t, mods, 1)
		assert.Equal(t, "https://vuln.go.dev/ID/GO-2024-3312.json", mods[0].URL)
		assert.Equal(t, []string{
			"added vulnerable go symbols for import github.com/canonical/lxd/lxd to affected package github.com/canonical/lxd",
			`replaced pseudo-version range "<` + pseudoFix + `" with "<5.21.2" for affected package github.com/canonical/lxd`,
		}, mods[0].Changes)
	})

	t.Run("a different pseudo-version fix leaves the GHSA range alone", func(t *testing.T) {
		// same module, but the GHSA is pinned to some other commit: precondition 1 fails, so
		// the range must not be touched — coverage and symbol patching still apply
		otherPseudo := "0.0.0-20200331193331-03aab09f5b5c"
		otherRange := db.Range{
			Version: db.Version{Type: "go", Constraint: "<" + otherPseudo},
			Fix:     &db.Fix{Version: otherPseudo, State: db.FixedStatus},
		}
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-4c49-9fpc-hc3v", ghsaLxdAPH(otherRange))))

		entry := goEntryWith(lxdAliases, goLxdWrapped())
		keep := w.handleGoVulnDBEntry(&entry)

		assert.False(t, keep)
		held := heldGHSA(t, w, "ghsa-4c49-9fpc-hc3v")
		aph, ok := held.Related[0].(db.AffectedPackageHandle)
		require.True(t, ok)
		assert.Equal(t, []db.Range{otherRange}, aph.BlobValue.Ranges, "mismatched fix commit must not be replaced")
	})

	t.Run("a GHSA package with more than one range is left alone", func(t *testing.T) {
		// precondition 2: with two ranges on the GHSA there is no way to know which one pairs
		// with the custom window, even though one of them names the right pseudo-version
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-4c49-9fpc-hc3v", ghsaLxdAPH(pseudoRange, tagRange))))

		entry := goEntryWith(lxdAliases, goLxdWrapped())
		keep := w.handleGoVulnDBEntry(&entry)

		assert.False(t, keep)
		held := heldGHSA(t, w, "ghsa-4c49-9fpc-hc3v")
		aph, ok := held.Related[0].(db.AffectedPackageHandle)
		require.True(t, ok)
		assert.Equal(t, []db.Range{pseudoRange, tagRange}, aph.BlobValue.Ranges,
			"ambiguous multi-range GHSA package must not be modified")
	})

	t.Run("the wrapper is unwrapped on every path, even with no GHSA to reconcile", func(t *testing.T) {
		// the wrapper is build-time-only context and must never reach the write batches: a GO
		// record with no GHSA aliases takes the early-return path and must still come out with
		// a plain affected package handle
		w := newMergeTestWriter()
		entry := goEntryWith([]string{"CVE-2024-6156"}, goLxdWrapped())
		keep := w.handleGoVulnDBEntry(&entry)

		assert.True(t, keep, "no GHSA aliases: the GO record is untouched and written")
		require.Len(t, entry.Related, 1)
		_, ok := entry.Related[0].(db.AffectedPackageHandle)
		assert.True(t, ok, "expected a plain handle, got %T", entry.Related[0])
	})

	t.Run("replaced ranges pass failOnMissingFixDate at write time", func(t *testing.T) {
		// the fix-date carry-over is what keeps a strict build working: without it the
		// replaced range has a fixed version but no availability date, and ensureFixDates
		// rejects the GHSA row when the held entries are written back at flush
		w := newMergeTestWriter()
		w.failOnMissingFixDate = true
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-4c49-9fpc-hc3v", ghsaLxdAPH(pseudoRange))))
		require.True(t, w.holdForGoVulnDBMerge(goEntryWith(lxdAliases, goLxdWrapped())))

		require.NoError(t, w.flushGoVulnDBMerge())
	})
}

// TestGoVulnDBMultipleRecordsPatchOneGHSA covers the converse of the multi-GHSA case: two GO
// records aliasing the SAME GHSA (the sibling shape to GO-2022-0536, where one GO record aliases
// two active GHSAs). Imports must accumulate across sources without duplicating paths, each
// source must leave its own modification entry, and the patched GHSA must be written exactly
// once at flush.
func TestGoVulnDBMultipleRecordsPatchOneGHSA(t *testing.T) {
	const mod = "github.com/example/mod"
	importsA := []db.GoImport{{Path: mod, Symbols: []string{"Parse"}}}
	importsB := []db.GoImport{
		{Path: mod, Symbols: []string{"Decode"}},        // same path as record A: skipped, no change recorded
		{Path: mod + "/sub", Symbols: []string{"Eval"}}, // new path: added, recorded
	}

	w := newMergeTestWriter()
	require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-2222-3333-4444", goModuleAPH(mod))))
	require.True(t, w.holdForGoVulnDBMerge(goVulnEntry("GO-2020-1111", []string{"GHSA-2222-3333-4444"}, goModuleAPH(mod, importsA...))))
	require.True(t, w.holdForGoVulnDBMerge(goVulnEntry("GO-2020-2222", []string{"GHSA-2222-3333-4444"}, goModuleAPH(mod, importsB...))))

	held := heldGHSA(t, w, "ghsa-2222-3333-4444")
	require.NoError(t, w.flushGoVulnDBMerge())

	// imports accumulated across both records; record B's duplicate path was skipped
	assert.Equal(t, []db.GoImport{
		{Path: mod, Symbols: []string{"Parse"}},
		{Path: mod + "/sub", Symbols: []string{"Eval"}},
	}, goImportsOf(t, held, mod))

	// one modification entry per patching GO record, in processing order
	mods := held.VulnerabilityHandle.BlobValue.Modifications
	require.Len(t, mods, 2)
	assert.Equal(t, "https://vuln.go.dev/ID/GO-2020-1111.json", mods[0].URL)
	assert.Equal(t, []string{
		"added vulnerable go symbols for import " + mod + " to affected package " + mod,
	}, mods[0].Changes)
	assert.Equal(t, "https://vuln.go.dev/ID/GO-2020-2222.json", mods[1].URL)
	assert.Equal(t, []string{
		"added vulnerable go symbols for import " + mod + "/sub to affected package " + mod,
	}, mods[1].Changes)

	// write-once: both GO records are fully covered (dropped), so flush batched exactly one
	// vulnerability write — the GHSA
	assert.Len(t, w.parentBuffer, 1, "expected exactly one vulnerability write (the patched GHSA)")
}

// TestGoVulnDBMergeRoundTrip drives the full writer path: held entries are
// reconciled at Close and land in the database with the patched qualifiers,
// modifications, and pruned GO record.
func TestGoVulnDBMergeRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	w, err := NewWriter(tmpDir, provider.States{}, false, 0)
	require.NoError(t, err)

	xnetImports := []db.GoImport{{Path: "golang.org/x/net/http2", Symbols: []string{"Server.ServeConn"}}}

	writeRelated := func(entry transformers.RelatedEntries) {
		require.NoError(t, w.Write(dataEntries(entry)...))
	}
	writeRelated(ghsaEntry("GHSA-69cg-p879-7622",
		goModuleAPH("golang.org/x/net"),
		goModuleAPH("golang.org/x/net/http2"),
	))
	writeRelated(goVulnEntry("GO-2022-0969", []string{"CVE-2022-27664", "GHSA-69cg-p879-7622"},
		goModuleAPH("stdlib", db.GoImport{Path: "net/http", Symbols: []string{"ListenAndServe"}}),
		goModuleAPH("golang.org/x/net", xnetImports...),
	))
	require.NoError(t, w.Close())

	reader, err := db.NewReader(db.Config{DBDirPath: tmpDir})
	require.NoError(t, err)
	defer reader.Close()

	// the GHSA record carries the modification audit trail
	ghsas, err := reader.GetVulnerabilities(&db.VulnerabilitySpecifier{Name: "GHSA-69cg-p879-7622"}, &db.GetVulnerabilityOptions{Preload: true})
	require.NoError(t, err)
	require.Len(t, ghsas, 1)
	mods := ghsas[0].BlobValue.Modifications
	require.Len(t, mods, 1)
	assert.Equal(t, "https://vuln.go.dev/ID/GO-2022-0969.json", mods[0].URL)
	assert.NotEmpty(t, mods[0].Changes)

	// the GO record survives with only the stdlib package
	gos, err := reader.GetVulnerabilities(&db.VulnerabilitySpecifier{Name: "GO-2022-0969"}, &db.GetVulnerabilityOptions{Preload: true})
	require.NoError(t, err)
	require.Len(t, gos, 1)

	// the GHSA x/net package carries the symbols; the GO record keeps stdlib only
	aphs, err := reader.GetAffectedPackages(&db.PackageSpecifier{Name: "golang.org/x/net", Ecosystem: string(pkg.GoModulePkg)}, &db.GetPackageOptions{
		PreloadPackage: true,
		PreloadBlob:    true,
	})
	require.NoError(t, err)
	require.Len(t, aphs, 1, "the govulndb x/net package must be dropped, leaving only the GHSA one")
	require.NotNil(t, aphs[0].BlobValue.Qualifiers)
	assert.Equal(t, xnetImports, aphs[0].BlobValue.Qualifiers.GoImports)

	stdlibAPHs, err := reader.GetAffectedPackages(&db.PackageSpecifier{Name: "stdlib", Ecosystem: string(pkg.GoModulePkg)}, &db.GetPackageOptions{
		PreloadPackage: true,
		PreloadBlob:    true,
	})
	require.NoError(t, err)
	require.Len(t, stdlibAPHs, 1)
}

// dataEntries wraps a RelatedEntries in the envelope the writer's Write method expects.
func dataEntries(entry transformers.RelatedEntries) []data.Entry {
	return []data.Entry{{DBSchemaVersion: db.ModelVersion, Data: entry}}
}
