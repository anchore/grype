package v6

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/matcher/apk"
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

const secdbCVE = "CVE-2026-0099"

// secdbEntry is a chainguard secdb row as the os transformer writes it: under the chainguard OS, with
// no qualifiers.
func secdbEntry(cve, pkgName string) transformers.RelatedEntries {
	state := providerState("chainguard")
	return transformers.RelatedEntries{
		VulnerabilityHandle: &db.VulnerabilityHandle{
			Name:       cve,
			ProviderID: state.Provider,
			Provider:   provider.Model(state),
			BlobValue:  &db.VulnerabilityBlob{ID: cve},
		},
		Provider: provider.Model(state),
		Related: []any{db.AffectedPackageHandle{
			Package:         &db.Package{Name: pkgName, Ecosystem: "apk"},
			OperatingSystem: &db.OperatingSystem{Name: "chainguard", ReleaseID: "chainguard", LabelVersion: "rolling"},
			BlobValue: &db.PackageBlob{
				CVEs:   []string{cve},
				Ranges: []db.Range{{Version: db.Version{Type: "apk", Constraint: "< 1.0.0-r1"}}},
			},
		}},
	}
}

func searchRules(t *testing.T, dir string) []db.SearchRule {
	t.Helper()
	reader, err := db.NewReader(db.Config{DBDirPath: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })
	rules, err := reader.GetSearchRules()
	require.NoError(t, err)
	return rules
}

func redirectsIn(rules []db.SearchRule) []string {
	var out []string
	for _, r := range rules {
		if r.ReplacementDistroName != nil {
			if _, ok := db.OSVRedirectSearchRules()[*r.ReplacementDistroName]; ok {
				out = append(out, r.MatchDistroName+"->"+*r.ReplacementDistroName)
			}
		}
	}
	sort.Strings(out)
	return out
}

// The writer emits a distro's redirect only when it wrote OSV rows for it: a rule pointing at an OS
// with no rows would blank that distro for every client following it.
func TestWriter_OSVRedirectRuleOnlyWithOSVRows(t *testing.T) {
	wolfiRecord := cgRecord("CGA-3333-3333-3333", "baz", cveA)
	wolfiRecord.Affected[0].Package.Ecosystem = "Wolfi"
	wolfiRecord.Affected[0].Package.Purl = "pkg:apk/wolfi/baz?arch=x86_64"

	tests := []struct {
		name    string
		entries []transformers.RelatedEntries
		want    []string
	}{
		{
			name:    "today's secdb-only DB: no redirect",
			entries: []transformers.RelatedEntries{secdbEntry(secdbCVE, "foo")},
		},
		{
			name:    "chainguard OSV rows: chainguard redirect only",
			entries: append([]transformers.RelatedEntries{secdbEntry(secdbCVE, "foo")}, cgEntries(t, cgRecord("CGA-1111-1111-1111", "foo", cveA))...),
			want:    []string{"chainguard->chainguard-osv"},
		},
		{
			name:    "chainguard and wolfi OSV rows: both redirects",
			entries: cgEntries(t, cgRecord("CGA-1111-1111-1111", "foo", cveA), wolfiRecord),
			want:    []string{"chainguard->chainguard-osv", "wolfi->wolfi-osv"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := searchRules(t, buildDB(t, tt.entries...))
			assert.Equal(t, tt.want, redirectsIn(rules))
			// the built-in rules are written to every DB, as before
			for _, known := range db.KnownSearchRules() {
				assert.Contains(t, rules, known)
			}
			for _, r := range rules {
				if r.ReplacementDistroName != nil {
					assert.Equal(t, db.OSVRedirectClientDBSchemas, r.ApplicableClientDBSchemas, "an emitted redirect is gated")
				}
			}
		})
	}
}

// End to end through the real writer and the apk matcher: a DB holding chainguard's secdb rows and
// its OSV rows. This client follows the redirect, so it reports only the OSV rows, under the plain
// chainguard namespace.
func TestWriter_OSVRedirectApkMatcher(t *testing.T) {
	p := pkg.Package{
		ID:      pkg.ID("foo"),
		Name:    "foo",
		Version: "0.9.0-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  distro.New(distro.Chainguard, "20230214", ""),
	}

	tests := []struct {
		name    string
		entries []transformers.RelatedEntries
		want    map[string]string
	}{
		{
			name:    "secdb-only DB: secdb rows, as today",
			entries: []transformers.RelatedEntries{secdbEntry(secdbCVE, "foo")},
			want:    map[string]string{secdbCVE: "chainguard:distro:chainguard:rolling"},
		},
		{
			name:    "secdb and OSV rows: OSV rows only",
			entries: append([]transformers.RelatedEntries{secdbEntry(secdbCVE, "foo")}, cgEntries(t, cgRecord("CGA-1111-1111-1111", "foo", cveA))...),
			want:    map[string]string{cveA: "chainguard:distro:chainguard:rolling"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp := openProvider(t, buildDB(t, tt.entries...))
			matches, _, err := (&apk.Matcher{}).Match(vp, p)
			require.NoError(t, err)
			got := map[string]string{}
			for _, m := range matches {
				got[m.Vulnerability.ID] = m.Vulnerability.Namespace
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
