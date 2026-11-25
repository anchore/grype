package nvd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// observedFixDate is one `x_observedFixDates` entry as the `cve5` provider writes it.
type observedFixDate = map[string]any

// loadCVE5WithFixDates decodes a published record after one declared edit: an `x_observedFixDates` list is added to
// the CNA container and to the `anchoreadp` container, where given. Published records carry no such list.
func loadCVE5WithFixDates(t *testing.T, cve string, cna, adp []observedFixDate) unmarshal.CVE5Record {
	t.Helper()

	var doc map[string]any
	require.NoError(t, json.Unmarshal(readCVE5Fixture(t, cve), &doc))
	containers := doc["containers"].(map[string]any)

	if cna != nil {
		containers["cna"].(map[string]any)["x_observedFixDates"] = cna
	}
	if adp != nil {
		edited := false
		for _, c := range containers["adp"].([]any) {
			container := c.(map[string]any)
			if container["providerMetadata"].(map[string]any)["shortName"] == "anchoreadp" {
				container["x_observedFixDates"] = adp
				edited = true
			}
		}
		require.True(t, edited, "the record has an anchoreadp container")
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)
	records, err := unmarshal.CVE5Entries(bytes.NewReader(b))
	require.NoError(t, err)
	require.Len(t, records, 1)
	return records[0]
}

func fixSummary(f *db.Fix) string {
	switch {
	case f == nil:
		return "no fix"
	case f.Detail == nil || f.Detail.Available == nil:
		return fmt.Sprintf("fix %s, no date", f.Version)
	}
	a := f.Detail.Available
	if a.Date == nil {
		return fmt.Sprintf("fix %s, %s, no date", f.Version, a.Kind)
	}
	return fmt.Sprintf("fix %s, %s %s", f.Version, a.Date.Format("2006-01-02"), a.Kind)
}

func rangeFixes(h *db.PackageBlob) []string {
	var out []string
	for _, r := range h.Ranges {
		out = append(out, fmt.Sprintf("%s: %s", r.Version.Constraint, fixSummary(r.Fix)))
	}
	return out
}

// entryFixes summarizes the fix of every range of every CPE and package row of one transformed record.
func entryFixes(t *testing.T, entries []data.Entry) (cpes, pkgs []string) {
	t.Helper()
	require.Len(t, entries, 1)
	re, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	for _, r := range re.Related {
		switch h := r.(type) {
		case db.AffectedCPEHandle:
			cpes = append(cpes, rangeFixes(h.BlobValue)...)
		case db.AffectedPackageHandle:
			pkgs = append(pkgs, rangeFixes(h.BlobValue)...)
		}
	}
	return cpes, pkgs
}

func TestCNAPackageHandles_fixDate(t *testing.T) {
	t.Run("a collectionURL and packageName entry dates the fix", func(t *testing.T) {
		rec := loadCVE5WithFixDates(t, "CVE-2025-32897", []observedFixDate{
			{
				"collectionURL": "https://repo.maven.apache.org/maven2",
				"packageName":   "org.apache.seata:seata-server",
				"fixVersion":    "2.3.0",
				"date":          "2025-06-20",
				"kind":          "first-observed",
			},
		}, nil)

		handles := cnaPackageHandles(cnaOnly(rec))
		require.Len(t, handles, 1)
		require.Equal(t, []string{">= 2.0.0, < 2.3.0: fix 2.3.0, 2025-06-20 first-observed"}, rangeFixes(handles[0].BlobValue))
	})

	t.Run("an entry for another fix version leaves the fix with no date", func(t *testing.T) {
		rec := loadCVE5WithFixDates(t, "CVE-2025-32897", []observedFixDate{
			{
				"collectionURL": "https://repo.maven.apache.org/maven2",
				"packageName":   "org.apache.seata:seata-server",
				"fixVersion":    "2.2.0",
				"date":          "2025-06-20",
				"kind":          "first-observed",
			},
		}, nil)

		handles := cnaPackageHandles(cnaOnly(rec))
		require.Len(t, handles, 1)
		require.Equal(t, []string{">= 2.0.0, < 2.3.0: fix 2.3.0, no date"}, rangeFixes(handles[0].BlobValue))
	})
}

func TestTransformCVE5Only_fixDates(t *testing.T) {
	cfg := defaultConfig()
	state := inputProviderState("nvd")

	t.Run("a CNA CPE row's inferred fix takes the matching entry's date", func(t *testing.T) {
		// the CNA's cpeApplicability has two bounds on one criteria, and only 5.10.6 has an entry
		rec := loadCVE5WithFixDates(t, "CVE-2026-72778", []observedFixDate{
			{
				"criteria":   "cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*",
				"fixVersion": "5.10.6",
				"date":       "2026-09-11",
				"kind":       "first-observed",
			},
		}, nil)

		cpes, _ := entryFixes(t, transformCVE5Only(cfg, project(rec), state))
		require.ElementsMatch(t, []string{
			">= 5.0.0, < 5.10.6: fix 5.10.6, 2026-09-11 first-observed",
			">= 4.0.0, < 4.18.2: fix 4.18.2, no date",
		}, cpes)
	})

	t.Run("a bound with no matching entry keeps a fix with no date", func(t *testing.T) {
		cpes, pkgs := entryFixes(t, transformCVE5Only(cfg, project(loadCVE5Fixture(t, "CVE-2026-72778")), state))
		require.ElementsMatch(t, []string{
			">= 5.0.0, < 5.10.6: fix 5.10.6, no date",
			">= 4.0.0, < 4.18.2: fix 4.18.2, no date",
		}, cpes)
		require.ElementsMatch(t, []string{
			">= 5.0.0-RC1, < 5.10.6: fix 5.10.6, no date",
			">= 4.0.0-RC1, < 4.18.2: fix 4.18.2, no date",
		}, pkgs)
	})

	t.Run("an anchoreadp entry dates the anchoreadp rows and a CNA entry does not", func(t *testing.T) {
		// the CNA's list holds an entry for each bound too, with other dates and a kind that no anchoreadp entry has
		rec := loadCVE5WithFixDates(t, "CVE-2026-47392",
			[]observedFixDate{
				{
					"criteria":   "cpe:2.3:a:praison:praisonai:*:*:*:*:*:python:*:*",
					"fixVersion": "4.6.40",
					"date":       "2026-01-01",
					"kind":       "cna-entry",
				},
				{
					"packageURL": "pkg:pypi/praisonai",
					"fixVersion": "4.6.40",
					"date":       "2026-01-01",
					"kind":       "cna-entry",
				},
			},
			[]observedFixDate{
				{
					"criteria":   "cpe:2.3:a:praison:praisonai:*:*:*:*:*:python:*:*",
					"fixVersion": "4.6.40",
					"date":       "2026-07-02",
					"kind":       "first-observed",
				},
				{
					"packageURL": "pkg:pypi/praisonai",
					"fixVersion": "4.6.40",
					"date":       "2026-07-03",
					"kind":       "first-observed",
				},
			},
		)

		cpes, pkgs := entryFixes(t, transformCVE5Only(cfg, project(rec), state))
		t.Run("CPE rows", func(t *testing.T) {
			require.ElementsMatch(t, []string{
				"< 4.6.40: fix 4.6.40, 2026-07-02 first-observed",
				"< 1.6.40: fix 1.6.40, no date",
			}, cpes)
		})
		t.Run("package rows", func(t *testing.T) {
			require.ElementsMatch(t, []string{
				"< 4.6.40: fix 4.6.40, 2026-07-03 first-observed",
				"< 1.6.40: fix 1.6.40, no date",
			}, pkgs)
		})
	})

	t.Run("an anchoreadp entry does not date a CNA CPE row", func(t *testing.T) {
		// the anchoreadp container has affected[] but no cpeApplicability, so the CNA's supplies the CPE rows and only
		// the CNA's own list may date them
		rec := loadCVE5WithFixDates(t, "CVE-2026-40034", nil, []observedFixDate{
			{
				"criteria":   "cpe:2.3:a:gitoxidelabs:gitoxide:*:*:*:*:*:*:*:*",
				"fixVersion": "0.5.21",
				"date":       "2026-07-02",
				"kind":       "first-observed",
			},
		})

		cpes, _ := entryFixes(t, transformCVE5Only(cfg, project(rec), state))
		require.Equal(t, []string{"< 0.5.21: fix 0.5.21, no date"}, cpes)
	})
}
