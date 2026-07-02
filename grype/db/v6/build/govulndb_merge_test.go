package v6

import (
	"testing"

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
		// the GO record has nothing left to say.
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
		// record stays active. A rejected record never matches, so letting it
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
		// unreviewed records rarely carry symbols; the dedup (drop the GO
		// package) still applies, but the GHSA is not modified
		w := newMergeTestWriter()
		require.True(t, w.holdForGoVulnDBMerge(ghsaEntry("GHSA-c9gm-7rfj-8w5h", goModuleAPH("github.com/tidwall/gjson"))))

		entry := goVulnEntry("GO-2021-0265", []string{"GHSA-c9gm-7rfj-8w5h"},
			goModuleAPH("github.com/tidwall/gjson"),
		)
		keep := w.handleGoVulnDBEntry(&entry)

		assert.False(t, keep)
		held := heldGHSA(t, w, "ghsa-c9gm-7rfj-8w5h")
		assert.Nil(t, goImportsOf(t, held, "github.com/tidwall/gjson"))
		assert.Empty(t, held.VulnerabilityHandle.BlobValue.Modifications)
	})

	t.Run("sub-package-only GHSA match patches but does not cover", func(t *testing.T) {
		// if a GHSA lists only the sub-package, dropping the GO record's module
		// package would leave module-named packages matching nothing
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
