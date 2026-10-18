package v6

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/osv"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

// These drive the real chainguard transformer through NewWriter -> Write -> Close, so the merge
// is exercised on the shapes the feed produces and read back the way a scan reads it.

const (
	cveA = "CVE-2026-0001"
	cveB = "CVE-2026-0002"
)

// cgRecord is a chainguard record for one apk package, fixed at 1.0.0-r1.
func cgRecord(id, pkgName string, upstream ...string) unmarshal.OSVVulnerability {
	v := unmarshal.OSVVulnerability{Upstream: upstream}
	v.ID = id
	v.Affected = []osvmodel.Affected{{
		Package: osvmodel.Package{Ecosystem: "Chainguard", Name: pkgName, Purl: "pkg:apk/chainguard/" + pkgName + "?arch=x86_64"},
		Ranges: []osvmodel.Range{{
			Type:   osvmodel.RangeEcosystem,
			Events: []osvmodel.Event{{Introduced: "0"}, {Fixed: "1.0.0-r1"}},
		}},
	}}
	return v
}

func providerState(name string) provider.State {
	return provider.State{Provider: name, Version: 1, Processor: "vunnel@test", Timestamp: time.Now().UTC()}
}

func asEntry(e transformers.RelatedEntries) data.Entry {
	return data.Entry{DBSchemaVersion: db.ModelVersion, Data: e}
}

func cgEntries(t *testing.T, records ...unmarshal.OSVVulnerability) []transformers.RelatedEntries {
	t.Helper()
	var out []transformers.RelatedEntries
	for _, r := range records {
		entries, err := osv.Transform(r, providerState("chainguard"))
		require.NoError(t, err)
		for _, e := range entries {
			out = append(out, e.Data.(transformers.RelatedEntries))
		}
	}
	return out
}

// buildDB writes entries through the real writer and returns the directory holding the DB.
func buildDB(t *testing.T, entries ...transformers.RelatedEntries) string {
	t.Helper()
	dir := t.TempDir()
	states := provider.States{providerState("chainguard"), providerState("nvd"), providerState("kev")}
	w, err := NewWriter(dir, states, false, 100)
	require.NoError(t, err)
	for _, e := range entries {
		require.NoError(t, w.Write(asEntry(e)))
	}
	require.NoError(t, w.Close())
	return dir
}

func openProvider(t *testing.T, dir string) vulnerability.Provider {
	t.Helper()
	reader, err := db.NewReader(db.Config{DBDirPath: dir})
	require.NoError(t, err)
	vp := db.NewVulnerabilityProvider(reader)
	t.Cleanup(func() { _ = vp.Close() })
	return vp
}

func findChainguard(t *testing.T, vp vulnerability.Provider, pkgName string) []vulnerability.Vulnerability {
	t.Helper()
	vulns, err := vp.FindVulnerabilities(
		search.ByPackageName(pkgName),
		search.ByDistro(*distro.New(distro.Chainguard, "", "")),
	)
	require.NoError(t, err)
	return vulns
}

func relatedIDs(v vulnerability.Vulnerability) []string {
	var ids []string
	for _, r := range v.RelatedVulnerabilities {
		ids = append(ids, r.ID)
	}
	return ids
}

// foo's CGA lists only CVE-A; bar's lists CVE-A, CVE-B and a GHSA. Chainguard said nothing about
// CVE-B for foo, so foo's CVE-A result must not claim it: the apk matcher removes NVD results
// and emits DistroFixed ignores by that identity.
func TestWriter_MergedHandleDoesNotLeakIDsAcrossPackages(t *testing.T) {
	vp := openProvider(t, buildDB(t, cgEntries(t,
		cgRecord("CGA-1111-1111-1111", "foo", cveA),
		cgRecord("CGA-2222-2222-2222", "bar", cveA, cveB, "GHSA-2222-2222-2222"),
	)...))

	vulns := findChainguard(t, vp, "foo")
	require.Len(t, vulns, 1, "foo is affected by CVE-A only")
	require.Equal(t, cveA, vulns[0].ID)
	require.ElementsMatch(t, []string{cveA}, relatedIDs(vulns[0]),
		"foo's CVE-A result carries ids only bar's CGA listed")
}

// The converse: dropping handle aliases must not lose what a record does claim. bar's CGA ties
// CVE-A and CVE-B together, and that one-hop link stays on bar's own rows.
func TestWriter_MergedHandleKeepsRecordLinksOnItsOwnRows(t *testing.T) {
	dir := buildDB(t, cgEntries(t,
		cgRecord("CGA-1111-1111-1111", "foo", cveA),
		cgRecord("CGA-2222-2222-2222", "bar", cveA, cveB),
	)...)
	vp := openProvider(t, dir)

	byID := map[string]vulnerability.Vulnerability{}
	for _, v := range findChainguard(t, vp, "bar") {
		byID[v.ID] = v
	}
	require.Len(t, byID, 2, "bar's two-CVE record fans out to both names")
	require.Subset(t, relatedIDs(byID[cveA]), []string{cveB},
		"bar's CVE-A result still relates the sibling CVE its own CGA listed")
	// the CGA shows up as a PackageBlob CVE, but getRelatedVulnerabilities only surfaces cve-/ghsa- ids
	require.NotContains(t, relatedIDs(byID[cveA]), "CGA-2222-2222-2222")

	gdb, err := db.NewLowLevelDB(db.Config{DBDirPath: dir}.DBFilePath(), false, false, false)
	require.NoError(t, err)
	var aliases int64
	require.NoError(t, gdb.Model(&db.VulnerabilityAlias{}).Count(&aliases).Error)
	require.Zero(t, aliases, "a merged chainguard handle should write no vulnerability_aliases rows")
}

// Two CGAs for the same CVE land as one vulnerability row with both package rows.
func TestWriter_PersistsOneHandlePerMergedName(t *testing.T) {
	dir := buildDB(t, cgEntries(t,
		cgRecord("CGA-1111-1111-1111", "foo", cveA),
		cgRecord("CGA-2222-2222-2222", "bar", cveA),
	)...)

	reader, err := db.NewReader(db.Config{DBDirPath: dir})
	require.NoError(t, err)
	defer reader.Close()

	handles, err := reader.GetVulnerabilities(&db.VulnerabilitySpecifier{Name: cveA}, nil)
	require.NoError(t, err)
	require.Len(t, handles, 1, "one handle for the shared CVE")

	aphs, err := reader.GetAffectedPackages(nil, &db.GetPackageOptions{
		Vulnerabilities: []db.VulnerabilitySpecifier{{Name: cveA}},
	})
	require.NoError(t, err)
	require.Len(t, aphs, 2, "both CGAs' package rows hang off the one handle")
	for _, a := range aphs {
		require.Equal(t, handles[0].ID, a.VulnerabilityID)
	}
}

// KEV, EPSS and CWE decoration reads the handle's aliases. A sibling CVE in them would hang
// CVE-B's exploitation status on every CVE-A finding.
func TestWriter_MergedHandleDoesNotBorrowSiblingKEV(t *testing.T) {
	kevProvider := providerState("kev")
	entries := append(cgEntries(t, cgRecord("CGA-2222-2222-2222", "bar", cveA, cveB)),
		transformers.RelatedEntries{
			Provider: provider.Model(kevProvider),
			Related: []any{db.KnownExploitedVulnerabilityHandle{
				Cve:       cveB,
				BlobValue: &db.KnownExploitedVulnerabilityBlob{Cve: cveB},
			}},
		})
	vp := openProvider(t, buildDB(t, entries...))

	byID := map[string]vulnerability.Vulnerability{}
	for _, v := range findChainguard(t, vp, "bar") {
		byID[v.ID] = v
	}
	require.NotNil(t, byID[cveB].Metadata)
	require.Len(t, byID[cveB].Metadata.KnownExploited, 1, "control: CVE-B's own finding is KEV-listed")
	require.NotNil(t, byID[cveA].Metadata)
	require.Empty(t, byID[cveA].Metadata.KnownExploited, "CVE-A's finding borrowed CVE-B's KEV entry")
}
