package v6

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

func timePtr(t time.Time) *time.Time { return &t }

// mergeableEntry builds the shape the chainguard transformer emits.
func mergeableEntry(name, provider, cga string, published, modified time.Time, aliases []string, refs []db.Reference, sevs []db.Severity) transformers.RelatedEntries {
	return transformers.RelatedEntries{
		MergeByName: true,
		VulnerabilityHandle: &db.VulnerabilityHandle{
			Name:          name,
			Status:        db.VulnerabilityActive,
			ProviderID:    provider,
			PublishedDate: timePtr(published),
			ModifiedDate:  timePtr(modified),
			BlobValue: &db.VulnerabilityBlob{
				ID:         name,
				Aliases:    aliases,
				References: refs,
				Severities: sevs,
			},
		},
		Related: []any{
			db.AffectedPackageHandle{
				Package:   &db.Package{Name: "demo", Ecosystem: "Chainguard"},
				BlobValue: &db.PackageBlob{CVEs: []string{name, cga}},
			},
		},
	}
}

// The core case: many records differing only in CGA and dates describe one CVE.
func TestNameMerger_FoldsRecordsSharingAName(t *testing.T) {
	m := newNameMerger()

	jan := time.Date(2026, time.January, 10, 0, 0, 0, 0, time.UTC)
	mar := time.Date(2026, time.March, 2, 0, 0, 0, 0, time.UTC)
	jun := time.Date(2026, time.June, 20, 0, 0, 0, 0, time.UTC)
	sep := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)

	// deliberately out of order: the merged window must not depend on arrival order
	require.True(t, m.hold(mergeableEntry("CVE-2026-1", "chainguard", "CGA-aaa", mar, jun, []string{"GHSA-x"}, nil, nil)))
	require.True(t, m.hold(mergeableEntry("CVE-2026-1", "chainguard", "CGA-bbb", jan, mar, []string{"GHSA-x"}, nil, nil)))
	require.True(t, m.hold(mergeableEntry("CVE-2026-1", "chainguard", "CGA-ccc", jun, sep, []string{"GO-2026-1"}, nil, nil)))

	out := m.reconcile()
	require.Len(t, out, 1, "three records describing one CVE become one handle")

	got := out[0]
	require.Equal(t, "CVE-2026-1", got.VulnerabilityHandle.Name)
	require.Equal(t, jan, *got.VulnerabilityHandle.PublishedDate, "published is the earliest across the group")
	require.Equal(t, sep, *got.VulnerabilityHandle.ModifiedDate, "modified is the latest across the group")
	require.Equal(t, []string{"GHSA-x", "GO-2026-1"}, got.VulnerabilityHandle.BlobValue.Aliases,
		"aliases are unioned, in first-seen order, without duplicates")

	require.Len(t, got.Related, 3, "every record's package rows survive the merge")
	var cgas []string
	for _, rel := range got.Related {
		aph := rel.(db.AffectedPackageHandle)
		cgas = append(cgas, aph.BlobValue.CVEs[len(aph.BlobValue.CVEs)-1])
	}
	require.Equal(t, []string{"CGA-aaa", "CGA-bbb", "CGA-ccc"}, cgas,
		"each package row keeps its own originating CGA rather than the union")
}

// The store's identity is name+provider+blob, so two providers publishing the same CVE are
// legitimately separate rows.
func TestNameMerger_KeepsProvidersApart(t *testing.T) {
	m := newNameMerger()
	now := time.Now().UTC()

	require.True(t, m.hold(mergeableEntry("CVE-2026-1", "chainguard", "CGA-aaa", now, now, nil, nil, nil)))
	require.True(t, m.hold(mergeableEntry("CVE-2026-1", "wolfi", "CGA-bbb", now, now, nil, nil, nil)))

	out := m.reconcile()
	require.Len(t, out, 2)
	require.Equal(t, "chainguard", out[0].VulnerabilityHandle.ProviderID)
	require.Equal(t, "wolfi", out[1].VulnerabilityHandle.ProviderID)
}

// Mirrors cacheKey's lowercasing: a merger stricter than the store would keep apart two
// entries that then collide at write time, and one would be silently dropped.
func TestNameMerger_KeyIsCaseInsensitive(t *testing.T) {
	m := newNameMerger()
	now := time.Now().UTC()

	require.True(t, m.hold(mergeableEntry("CVE-2026-1", "chainguard", "CGA-aaa", now, now, nil, nil, nil)))
	require.True(t, m.hold(mergeableEntry("cve-2026-1", "Chainguard", "CGA-bbb", now, now, nil, nil, nil)))

	out := m.reconcile()
	require.Len(t, out, 1)
	require.Equal(t, "CVE-2026-1", out[0].VulnerabilityHandle.Name, "the first spelling seen wins")
}

// These two need a computed key: db.Reference holds a slice, db.Severity an interface.
func TestNameMerger_UnionsReferencesAndSeverities(t *testing.T) {
	m := newNameMerger()
	now := time.Now().UTC()

	shared := db.Reference{URL: "https://example.com/a", Tags: []string{"ADVISORY"}}
	other := db.Reference{URL: "https://example.com/b", Tags: []string{"FIX"}}
	sevA := db.Severity{Scheme: db.SeveritySchemeCVSS, Value: db.CVSSSeverity{Vector: "CVSS:3.1/AV:N", Version: "3.1"}}
	sevB := db.Severity{Scheme: db.SeveritySchemeCVSS, Value: db.CVSSSeverity{Vector: "CVSS:3.1/AV:L", Version: "3.1"}}

	require.True(t, m.hold(mergeableEntry("CVE-2026-1", "chainguard", "CGA-aaa", now, now, nil,
		[]db.Reference{shared}, []db.Severity{sevA})))
	require.True(t, m.hold(mergeableEntry("CVE-2026-1", "chainguard", "CGA-bbb", now, now, nil,
		[]db.Reference{shared, other}, []db.Severity{sevA, sevB})))

	out := m.reconcile()
	require.Len(t, out, 1)
	blob := out[0].VulnerabilityHandle.BlobValue
	require.Equal(t, []db.Reference{shared, other}, blob.References, "the shared reference is not duplicated")
	require.Equal(t, []db.Severity{sevA, sevB}, blob.Severities, "disagreeing severities are unioned, not resolved arbitrarily")
}

// The merger stays inert for providers that have not opted in.
func TestNameMerger_IgnoresUnmarkedEntries(t *testing.T) {
	m := newNameMerger()
	now := time.Now().UTC()

	plain := mergeableEntry("CVE-2026-1", "nvd", "CGA-aaa", now, now, nil, nil, nil)
	plain.MergeByName = false
	require.False(t, m.hold(plain), "unmarked entries stream through")

	require.False(t, m.hold(transformers.RelatedEntries{MergeByName: true}),
		"an entry with no vulnerability handle has nothing to key on")

	require.Nil(t, m.reconcile())
}

// TestNameMerger_ReconcileResets guards against a second Close re-emitting the same handles.
func TestNameMerger_ReconcileResets(t *testing.T) {
	m := newNameMerger()
	now := time.Now().UTC()

	require.True(t, m.hold(mergeableEntry("CVE-2026-1", "chainguard", "CGA-aaa", now, now, nil, nil, nil)))
	require.Len(t, m.reconcile(), 1)
	require.Nil(t, m.reconcile())
}

// goMerge.hold claims any "GO-*" name with no provider guard, so it would swallow chainguard
// apk advisories named for a govulndb id and reconcile them against Go modules. Reversing the
// two hold calls in writeEntry makes this fail.
func TestWriterPrefersNameMergeOverGoMerge(t *testing.T) {
	w := &writer{
		goMerge:   newGoVulnDBMerger(),
		nameMerge: newNameMerger(),
	}

	now := time.Now().UTC()
	entry := mergeableEntry("GO-2026-4945", "chainguard", "CGA-aaa", now, now, nil, nil, nil)
	require.Equal(t, "Chainguard", entry.Related[0].(db.AffectedPackageHandle).Package.Ecosystem,
		"guard: this entry describes an apk package, not a Go module")

	require.NoError(t, w.writeEntry(entry))

	require.Empty(t, w.goMerge.govulndbEntries,
		"a GO-named chainguard record must not be held by the govulndb reconciler")
	require.Len(t, w.nameMerge.reconcile(), 1,
		"it must be held by the name merger instead")
}

// archRow builds a row with an arch qualifier; no ranges is the "affected at every version" shape.
func archRow(pkgName, arch, fixedVersion string) db.AffectedPackageHandle {
	var ranges []db.Range
	if fixedVersion != "" {
		ranges = []db.Range{{
			Version: db.Version{Type: "apk", Constraint: "< " + fixedVersion},
			Fix:     &db.Fix{Version: fixedVersion, State: db.FixedStatus},
		}}
	}
	a := arch
	return db.AffectedPackageHandle{
		OperatingSystem: &db.OperatingSystem{Name: "chainguard", ReleaseID: "chainguard", LabelVersion: "rolling"},
		Package:         &db.Package{Name: pkgName, Ecosystem: "Chainguard"},
		BlobValue: &db.PackageBlob{
			Qualifiers: &db.PackageQualifiers{Architecture: &a},
			Ranges:     ranges,
		},
	}
}

// Real shape from the feed: rook/CVE-2026-27140 is fixed on x86_64 but rangeless on aarch64.
// The merge is what puts those rows under one handle, so it must keep them distinguishable.
// Fails if anyone dedupes Related rows by (os, package), which would answer one architecture's
// question with the other's data.
func TestNameMerger_PreservesPerRowQualifiersAndRanges(t *testing.T) {
	m := newNameMerger()
	now := time.Now().UTC()

	x86 := mergeableEntry("CVE-2026-27140", "chainguard", "CGA-x86", now, now, nil, nil, nil)
	x86.Related = []any{archRow("rook", "x86_64", "1.19.4-r0")}

	arm := mergeableEntry("CVE-2026-27140", "chainguard", "CGA-arm", now, now, nil, nil, nil)
	arm.Related = []any{archRow("rook", "aarch64", "")} // no ranges: affected at every version

	require.True(t, m.hold(x86))
	require.True(t, m.hold(arm))

	out := m.reconcile()
	require.Len(t, out, 1, "both records describe one vulnerability")
	require.Len(t, out[0].Related, 2, "one row per architecture must survive the fold")

	byArch := map[string]db.AffectedPackageHandle{}
	for _, rel := range out[0].Related {
		aph := rel.(db.AffectedPackageHandle)
		require.NotNil(t, aph.BlobValue.Qualifiers, "every row keeps its qualifiers")
		require.NotNil(t, aph.BlobValue.Qualifiers.Architecture, "every row keeps its architecture")
		byArch[*aph.BlobValue.Qualifiers.Architecture] = aph
	}
	require.ElementsMatch(t, []string{"x86_64", "aarch64"}, keysOf(byArch),
		"the two architectures must remain separately addressable under the merged handle")

	// the x86_64 row keeps its fix...
	require.Equal(t, "< 1.19.4-r0", byArch["x86_64"].BlobValue.Ranges[0].Version.Constraint)
	require.Equal(t, db.FixedStatus, byArch["x86_64"].BlobValue.Ranges[0].Fix.State)

	// ...and must not have leaked onto the aarch64 row, which asserts the opposite
	require.Empty(t, byArch["aarch64"].BlobValue.Ranges,
		"the aarch64 row is affected at every version; inheriting the x86_64 fix would silently drop a real finding")
}

func keysOf(m map[string]db.AffectedPackageHandle) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
