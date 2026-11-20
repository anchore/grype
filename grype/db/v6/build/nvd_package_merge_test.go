package v6

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/entry"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/nvd"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// the inputs are unmodified vunnel results, extracted from real workspaces with
// grype/db/v6/diff/testdata/result-extractor, so the entries below are what the transformers produce for real records.
const cnaResults = "testdata/cna"

const (
	bcNVD     = "CVE-2026-8763"
	bcGHSA    = "GHSA-9pwp-9qqc-pr26"
	goNVD     = "CVE-2026-73605"
	goGHSA    = "GHSA-hf8h-97gm-4x2p"
	goVulnDB  = "GO-2026-6626"
	goModule  = "github.com/siyuan-note/siyuan/kernel"
	bcJdk18on = "org.bouncycastle:bcprov-jdk18on"
	bcLts8on  = "org.bouncycastle:bcprov-lts8on"
	bcFips    = "org.bouncycastle:bc-fips"
	bcJdk15   = "org.bouncycastle:bcprov-jdk15to18"
)

type bytesOpener struct {
	name     string
	contents []byte
}

func (o bytesOpener) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(o.contents)), nil
}

func (o bytesOpener) String() string { return o.name }

// resultPath finds the extracted result for a vulnerability ID under a provider, wherever the extractor put it.
func resultPath(t *testing.T, providerName, id string) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(filepath.Join(cnaResults, providerName, "results"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.EqualFold(d.Name(), id+".json") {
			found = path
		}
		return err
	})
	require.NoError(t, err)
	require.NotEmpty(t, found, "no %s result for %s", providerName, id)
	return found
}

func readEnvelope(t *testing.T, providerName, id string) (*unmarshal.ItemsEnvelope, []byte) {
	t.Helper()
	contents, err := os.ReadFile(resultPath(t, providerName, id))
	require.NoError(t, err)
	envelope, err := unmarshal.Envelope(bytes.NewReader(contents))
	require.NoError(t, err)
	return envelope, contents
}

// cnaProcessors are the processors a build with CNA reconciliation uses, with the CVE 5 records of the given CVEs indexed.
func cnaProcessors(t *testing.T, cve5 ...string) []data.Processor {
	t.Helper()
	openers := make(chan entry.Opener, len(cve5))
	for _, id := range cve5 {
		_, contents := readEnvelope(t, "cve5", id)
		openers <- bytesOpener{name: id, contents: contents}
	}
	close(openers)

	idx, err := nvd.NewIndex(openers)
	require.NoError(t, err)

	return Processors(NewConfig(
		WithCPEParts([]string{"a", "o", "h"}),
		WithInferNVDFixVersions(true),
		WithCNAIndex(idx),
	))
}

// transformResult runs the processor that claims an extracted result and returns the one entry it produces.
func transformResult(t *testing.T, processors []data.Processor, providerName, id string) transformers.RelatedEntries {
	t.Helper()
	envelope, _ := readEnvelope(t, providerName, id)
	state := provider.State{Provider: providerName, Version: 1, Timestamp: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)}

	for _, p := range processors {
		if !p.IsSupported(envelope.Schema) {
			continue
		}
		entries, err := p.Process(bytes.NewReader(envelope.Item), state)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		related, ok := entries[0].Data.(transformers.RelatedEntries)
		require.True(t, ok)
		return related
	}
	t.Fatalf("no processor for %s result %s (schema %s)", providerName, id, envelope.Schema)
	return transformers.RelatedEntries{}
}

func packageNames(entry transformers.RelatedEntries) []string {
	var names []string
	for _, rel := range entry.Related {
		switch r := rel.(type) {
		case db.AffectedPackageHandle:
			names = append(names, r.Package.Name)
		case transformers.GoVulnDBAffectedPackage:
			names = append(names, r.Handle.Package.Name)
		}
	}
	sort.Strings(names)
	return names
}

func cpeCount(entry transformers.RelatedEntries) int {
	var n int
	for _, rel := range entry.Related {
		if _, ok := rel.(db.AffectedCPEHandle); ok {
			n++
		}
	}
	return n
}

// withoutPackages returns the entry with the affected package handles named in drop removed, or all of them when
// drop is empty.
func withoutPackages(entry transformers.RelatedEntries, drop ...string) transformers.RelatedEntries {
	var kept []any
	for _, rel := range entry.Related {
		if aph, ok := rel.(db.AffectedPackageHandle); ok && (len(drop) == 0 || contains(drop, aph.Package.Name)) {
			continue
		}
		kept = append(kept, rel)
	}
	entry.Related = kept
	return entry
}

func onlyPackages(entry transformers.RelatedEntries, keep ...string) transformers.RelatedEntries {
	var kept []any
	for _, rel := range entry.Related {
		if aph, ok := rel.(db.AffectedPackageHandle); ok && !contains(keep, aph.Package.Name) {
			continue
		}
		kept = append(kept, rel)
	}
	entry.Related = kept
	return entry
}

func contains(values []string, v string) bool {
	for _, s := range values {
		if s == v {
			return true
		}
	}
	return false
}

// mergeFor holds and reconciles the given entries in order, the way the writer feeds the merger, and returns the
// reconciled nvd entries.
func mergeFor(entries ...transformers.RelatedEntries) []transformers.RelatedEntries {
	m := newNVDPackageMerger()
	for _, e := range entries {
		m.observe(e)
		m.hold(e)
	}
	return m.reconcile()
}

func TestNVDPackageMerge_realRecords(t *testing.T) {
	processors := cnaProcessors(t, bcNVD)
	nvdEntry := transformResult(t, processors, "nvd", bcNVD)
	ghsaEntry := transformResult(t, processors, "github", bcGHSA)

	// the inputs the cases below rely on
	require.Equal(t, []string{bcFips, bcJdk18on, bcLts8on}, packageNames(nvdEntry), "the CNA's packages")
	// the GHSA has one row per affected range, and three for bc-fips
	require.Equal(t, []string{bcFips, bcFips, bcFips, bcJdk15, bcJdk18on, bcLts8on}, packageNames(ghsaEntry), "the GHSA's packages")
	require.Positive(t, cpeCount(nvdEntry))

	out := mergeFor(nvdEntry, ghsaEntry)
	require.Len(t, out, 1)

	assert.Empty(t, packageNames(out[0]), "every CNA package is covered by the GHSA")
	assert.Equal(t, cpeCount(nvdEntry), cpeCount(out[0]), "CPE handles are kept")
	require.NotNil(t, out[0].VulnerabilityHandle, "the vulnerability is kept")
	assert.Equal(t, bcNVD, out[0].VulnerabilityHandle.Name)

	// the drops are recorded on the vulnerability, one modification for the GHSA that displaced them
	mods := out[0].VulnerabilityHandle.BlobValue.Modifications
	require.Len(t, mods, 1)
	assert.Equal(t, bcGHSA, mods[0].URL)
	assert.ElementsMatch(t, []string{
		"dropped java-archive:" + bcFips + ": covered by " + bcGHSA,
		"dropped java-archive:" + bcJdk18on + ": covered by " + bcGHSA,
		"dropped java-archive:" + bcLts8on + ": covered by " + bcGHSA,
	}, mods[0].Changes)
}

// each case makes one declared edit to the real GHSA entry
func TestNVDPackageMerge_edits(t *testing.T) {
	processors := cnaProcessors(t, bcNVD)

	tests := []struct {
		name         string
		edit         func(transformers.RelatedEntries) transformers.RelatedEntries
		wantPackages []string
		wantDropped  []string
	}{
		{
			name:         "a GHSA cut to one of the CNA's packages",
			edit:         func(e transformers.RelatedEntries) transformers.RelatedEntries { return onlyPackages(e, bcJdk18on) },
			wantPackages: []string{bcFips, bcLts8on},
			wantDropped:  []string{bcJdk18on},
		},
		{
			name:         "a GHSA with no packages",
			edit:         func(e transformers.RelatedEntries) transformers.RelatedEntries { return withoutPackages(e) },
			wantPackages: []string{bcFips, bcJdk18on, bcLts8on},
		},
		{
			name: "a withdrawn GHSA does not cover",
			edit: func(e transformers.RelatedEntries) transformers.RelatedEntries {
				e.VulnerabilityHandle.Status = db.VulnerabilityRejected
				return e
			},
			wantPackages: []string{bcFips, bcJdk18on, bcLts8on},
		},
		{
			name: "a GHSA in another ecosystem does not cover",
			edit: func(e transformers.RelatedEntries) transformers.RelatedEntries {
				for i, rel := range e.Related {
					if aph, ok := rel.(db.AffectedPackageHandle); ok {
						pkg := *aph.Package
						pkg.Ecosystem = string(syftPkg.NpmPkg)
						aph.Package = &pkg
						e.Related[i] = aph
					}
				}
				return e
			},
			wantPackages: []string{bcFips, bcJdk18on, bcLts8on},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nvdEntry := transformResult(t, processors, "nvd", bcNVD)
			ghsaEntry := transformResult(t, processors, "github", bcGHSA)

			out := mergeFor(nvdEntry, tt.edit(ghsaEntry))
			require.Len(t, out, 1)

			assert.Equal(t, tt.wantPackages, packageNames(out[0]))
			assert.Equal(t, cpeCount(nvdEntry), cpeCount(out[0]), "CPE handles are kept")

			mods := out[0].VulnerabilityHandle.BlobValue.Modifications
			if len(tt.wantDropped) == 0 {
				assert.Empty(t, mods)
				return
			}
			require.Len(t, mods, 1)
			assert.Equal(t, bcGHSA, mods[0].URL)
			require.Len(t, mods[0].Changes, len(tt.wantDropped))
			for i, name := range tt.wantDropped {
				assert.Contains(t, mods[0].Changes[i], name)
			}
		})
	}
}

func TestNVDPackageMerge_independentOfOrder(t *testing.T) {
	processors := cnaProcessors(t, bcNVD)
	nvdEntry := transformResult(t, processors, "nvd", bcNVD)
	ghsaEntry := transformResult(t, processors, "github", bcGHSA)

	nvdFirst := mergeFor(nvdEntry, ghsaEntry)

	// transform again: the merger changes the held entry
	nvdEntry = transformResult(t, processors, "nvd", bcNVD)
	nvdLast := mergeFor(ghsaEntry, nvdEntry)

	require.Len(t, nvdFirst, 1)
	require.Len(t, nvdLast, 1)
	assert.Equal(t, packageNames(nvdFirst[0]), packageNames(nvdLast[0]))
	assert.Equal(t, nvdFirst[0].VulnerabilityHandle.BlobValue.Modifications, nvdLast[0].VulnerabilityHandle.BlobValue.Modifications)
}

func TestNVDPackageMerge_hold(t *testing.T) {
	processors := cnaProcessors(t, bcNVD)
	nvdEntry := transformResult(t, processors, "nvd", bcNVD)
	ghsaEntry := transformResult(t, processors, "github", bcGHSA)

	tests := []struct {
		name     string
		entry    transformers.RelatedEntries
		wantHold bool
	}{
		{name: "nvd entry with package handles", entry: nvdEntry, wantHold: true},
		{name: "nvd entry with only CPE handles", entry: withoutPackages(nvdEntry), wantHold: false},
		{name: "entry from another provider", entry: ghsaEntry, wantHold: false},
		{name: "entry with no vulnerability handle", entry: transformers.RelatedEntries{}, wantHold: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantHold, newNVDPackageMerger().hold(tt.entry))
		})
	}
}

type affectedRow struct {
	vulnerability string
	provider      string
	ecosystem     string
	name          string
	constraint    string
}

// affectedRows reads every affected package row of a written database.
func affectedRows(t *testing.T, dir string) []affectedRow {
	t.Helper()
	reader, err := db.NewReader(db.Config{DBDirPath: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	handles, err := reader.GetAffectedPackages(nil, &db.GetPackageOptions{PreloadPackage: true, PreloadBlob: true, PreloadVulnerability: true})
	require.NoError(t, err)

	var rows []affectedRow
	for _, h := range handles {
		var constraints []string
		for _, r := range h.BlobValue.Ranges {
			constraints = append(constraints, r.Version.Constraint)
		}
		rows = append(rows, affectedRow{
			vulnerability: h.Vulnerability.Name,
			provider:      h.Vulnerability.ProviderID,
			ecosystem:     h.Package.Ecosystem,
			name:          h.Package.Name,
			constraint:    strings.Join(constraints, " || "),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		return a.vulnerability+a.provider+a.ecosystem+a.name < b.vulnerability+b.provider+b.ecosystem+b.name
	})
	return rows
}

func rowsOf(rows []affectedRow, providerName string) []string {
	var names []string
	for _, r := range rows {
		if r.provider == providerName {
			names = append(names, r.vulnerability+" "+r.name)
		}
	}
	return names
}

// writeAll writes the entries to a new database in order and returns its directory.
func writeAll(t *testing.T, entries []transformers.RelatedEntries, options ...WriterOption) string {
	t.Helper()
	dir := t.TempDir()
	w, err := NewWriter(dir, provider.States{}, false, 0, options...)
	require.NoError(t, err)
	for _, e := range entries {
		require.NoError(t, w.Write(dataEntries(e)...))
	}
	require.NoError(t, w.Close())
	return dir
}

func TestNVDPackageMerge_writer(t *testing.T) {
	newEntries := func() (nvdEntry, ghsaEntry transformers.RelatedEntries) {
		processors := cnaProcessors(t, bcNVD)
		return transformResult(t, processors, "nvd", bcNVD), transformResult(t, processors, "github", bcGHSA)
	}

	t.Run("without the merge both providers keep their rows", func(t *testing.T) {
		nvdEntry, ghsaEntry := newEntries()
		rows := affectedRows(t, writeAll(t, []transformers.RelatedEntries{nvdEntry, ghsaEntry}))
		assert.Len(t, rowsOf(rows, "nvd"), 3)
		assert.Len(t, rowsOf(rows, "github"), 6)
	})

	t.Run("nvd first and nvd last write the same rows", func(t *testing.T) {
		nvdEntry, ghsaEntry := newEntries()
		first := affectedRows(t, writeAll(t, []transformers.RelatedEntries{nvdEntry, ghsaEntry}, WithNVDPackageMerge()))

		nvdEntry, ghsaEntry = newEntries()
		last := affectedRows(t, writeAll(t, []transformers.RelatedEntries{ghsaEntry, nvdEntry}, WithNVDPackageMerge()))

		assert.Equal(t, first, last)
		assert.Empty(t, rowsOf(first, "nvd"), "the GHSA covers every CNA package")
		assert.Len(t, rowsOf(first, "github"), 6)
	})

	t.Run("the vulnerability and CPE rows of a held entry are written", func(t *testing.T) {
		nvdEntry, ghsaEntry := newEntries()
		dir := writeAll(t, []transformers.RelatedEntries{nvdEntry, ghsaEntry}, WithNVDPackageMerge())

		reader, err := db.NewReader(db.Config{DBDirPath: dir})
		require.NoError(t, err)
		defer reader.Close()

		vulns, err := reader.GetVulnerabilities(&db.VulnerabilitySpecifier{Name: bcNVD}, &db.GetVulnerabilityOptions{Preload: true})
		require.NoError(t, err)
		require.Len(t, vulns, 1)
		assert.Equal(t, "nvd", vulns[0].ProviderID)

		cpes, err := reader.GetAffectedCPEs(nil, &db.GetCPEOptions{PreloadVulnerability: true})
		require.NoError(t, err)
		assert.Len(t, cpes, cpeCount(nvdEntry))
	})
}

// the Go GHSA and its govulndb record are held by the govulndb merge before the writer sees their packages, so the
// CNA's go-module row is dropped only if the merge observes them first
func TestNVDPackageMerge_goGHSAHeldByGovulndbMerge(t *testing.T) {
	newEntries := func() []transformers.RelatedEntries {
		processors := cnaProcessors(t, goNVD)
		return []transformers.RelatedEntries{
			transformResult(t, processors, "nvd", goNVD),
			transformResult(t, processors, "github", goGHSA),
			transformResult(t, processors, "govulndb", goVulnDB),
		}
	}

	entries := newEntries()
	require.Equal(t, []string{goModule}, packageNames(entries[0]), "the CNA's go-module row")
	require.Equal(t, []string{goModule}, packageNames(entries[1]), "the GHSA names the same module")

	t.Run("without the merge the CNA row is written", func(t *testing.T) {
		rows := affectedRows(t, writeAll(t, newEntries()))
		assert.Equal(t, []string{goNVD + " " + goModule}, rowsOf(rows, "nvd"))
	})

	t.Run("with the merge the GHSA's row stands alone", func(t *testing.T) {
		rows := affectedRows(t, writeAll(t, newEntries(), WithNVDPackageMerge()))
		assert.Empty(t, rowsOf(rows, "nvd"))
		assert.Equal(t, []string{goGHSA + " " + goModule}, rowsOf(rows, "github"))
	})
}

// the NVD severity of a held entry must still reach the GHSA that aliases it
func TestNVDPackageMerge_severityBackfill(t *testing.T) {
	processors := cnaProcessors(t, bcNVD)
	nvdEntry := transformResult(t, processors, "nvd", bcNVD)
	ghsaEntry := transformResult(t, processors, "github", bcGHSA)

	require.NotEmpty(t, nvdEntry.VulnerabilityHandle.BlobValue.Severities, "the NVD record carries CVSS scores")
	nvdSeverity := nvdEntry.VulnerabilityHandle.BlobValue.Severities[0]

	// declared edit: the GHSA carries no severity of its own
	require.NotEmpty(t, ghsaEntry.VulnerabilityHandle.BlobValue.Severities)
	ghsaEntry.VulnerabilityHandle.BlobValue.Severities = nil

	dir := writeAll(t, []transformers.RelatedEntries{nvdEntry, ghsaEntry}, WithNVDPackageMerge())

	reader, err := db.NewReader(db.Config{DBDirPath: dir})
	require.NoError(t, err)
	defer reader.Close()

	vulns, err := reader.GetVulnerabilities(&db.VulnerabilitySpecifier{Name: bcGHSA}, &db.GetVulnerabilityOptions{Preload: true})
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.NotEmpty(t, vulns[0].BlobValue.Severities)
	assert.Equal(t, nvdSeverity, vulns[0].BlobValue.Severities[0])
}
