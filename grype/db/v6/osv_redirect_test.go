package v6

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The redirect must never be built in: a client on a DB without OSV rows (today's secdb-only DB, or
// one with no search_rules table) falls back to KnownSearchRules and must search chainguard and wolfi
// as it does today.
func TestOSVRedirect_NotBuiltIn(t *testing.T) {
	for _, r := range KnownSearchRules() {
		for _, src := range osvRedirectSources {
			assert.False(t, strings.EqualFold(r.MatchDistroName, src), "built-in rule matches %s: %+v", src, r)
		}
	}
	vp := rulesProvider(KnownSearchRules()...)
	for _, d := range []distro.Distro{*distro.New(distro.Chainguard, "20230214", ""), *distro.New(distro.Wolfi, "", "")} {
		notRewritten(t, vp, nameSearch(searchOf("openssl", "3.0.0-r0", d, syftPkg.ApkPkg)))
	}
}

func TestOSVRedirect_Targets(t *testing.T) {
	for in, want := range map[string]string{"chainguard": "chainguard-osv", "Chainguard": "chainguard-osv", "wolfi": "wolfi-osv", "Wolfi": "wolfi-osv"} {
		got, ok := OSVRedirectTarget(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got, in)
		src, ok := osvRedirectSource(got)
		assert.True(t, ok, got)
		assert.Equal(t, strings.ToLower(in), src)
	}
	for _, in := range []string{"alpine", "", "chainguard-osv", "rapidfort-alpine"} {
		_, ok := OSVRedirectTarget(in)
		assert.False(t, ok, in)
	}
	for _, in := range []string{"chainguard", "wolfi", "alpine-osv", ""} {
		_, ok := osvRedirectSource(in)
		assert.False(t, ok, in)
	}
}

// A target's name and release ID must both differ from the distro: released clients look an OS up by
// `name = ? OR release_id = ?` on the distro name, so either one equal to it exposes the OSV rows.
func TestOSVRedirect_TargetIsNotTheDistro(t *testing.T) {
	for target, rule := range OSVRedirectSearchRules() {
		assert.NotEqual(t, strings.ToLower(rule.MatchDistroName), strings.ToLower(target))
		assert.False(t, strings.HasPrefix(strings.ToLower(rule.MatchDistroName), strings.ToLower(target)))
	}
}

func TestOSVRedirect_RulesAreValid(t *testing.T) {
	rules := OSVRedirectSearchRules()
	require.Len(t, rules, 2)
	for target, r := range rules {
		require.NoError(t, r.Validate(), target)
		assert.Equal(t, SearchRuleReplace, r.Action)
		assert.Equal(t, "apk", r.MatchEcosystem)
		require.NotNil(t, r.ReplacementDistroName)
		assert.Equal(t, target, *r.ReplacementDistroName)
		require.NotNil(t, r.ReplacementDistroVersion)
		assert.Empty(t, *r.ReplacementDistroVersion, "the OSV OS rows are version-less")
		assert.Nil(t, r.ReplacementChannel)
		assert.Equal(t, OSVRedirectClientDBSchemas, r.ApplicableClientDBSchemas)
	}
}

func TestOSVRedirect_SearchRewrites(t *testing.T) { //nolint:funlen // one case per search shape
	vp := rulesProvider(append(KnownSearchRules(), redirectRules()...)...)
	cg := *distro.New(distro.Chainguard, "20230214", "")
	wolfi := *distro.New(distro.Wolfi, "", "")
	alpine := *distro.New(distro.Alpine, "3.18", "")
	apk := syftPkg.ApkPkg

	tests := []struct {
		name   string
		search []vulnerability.Criteria
		want   []searched
	}{
		{
			name:   "chainguard apk search is replaced by a version-less search of chainguard-osv",
			search: nameSearch(searchOf("openssl", "3.0.0-r0", cg, apk)),
			want:   []searched{ruled("chainguard-osv@+", "openssl", 0)},
		},
		{
			name:   "wolfi apk search is replaced by a search of wolfi-osv",
			search: nameSearch(searchOf("openssl", "3.0.0-r0", wolfi, apk)),
			want:   []searched{ruled("wolfi-osv@+", "openssl", 0)},
		},
		{
			// the rule leaves match_upstream_search NULL: an origin's rows live under the -osv OS too
			name:   "an origin (upstream) search is redirected like a direct one",
			search: append(nameSearch(searchOf("openssl", "3.0.0-r0", cg, apk)), search.BySourcePackage()),
			want:   []searched{ruled("chainguard-osv@+", "openssl", 0)},
		},
		{
			name:   "alpine is not redirected",
			search: nameSearch(searchOf("openssl", "3.0.0-r0", alpine, apk)),
			want:   []searched{own("alpine@3.18+", "openssl")},
		},
		{
			name:   "a non-apk package on chainguard is not redirected",
			search: nameSearch(searchOf("requests", "2.0.0", cg, syftPkg.PythonPkg)),
			want:   []searched{own("chainguard@20230214+", "requests")},
		},
		{
			name:   "a CPE search reads NVD's rows and is not redirected",
			search: cpeSearch(searchOf("openssl", "3.0.0-r0", cg, apk)),
			want:   []searched{own("", "cpe:vendor:openssl")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, searchesOf(rewrites(vp, pkg.Package{}, tt.search)))
		})
	}
}

// The OS a rule names is searched exactly: chainguard's "rolling" alias does not apply to it, which is
// why the rule drops the searched version itself.
func TestOSVRedirect_SearchIsExact(t *testing.T) {
	vp := rulesProvider(redirectRules()...)
	searches := rewrites(vp, pkg.Package{}, nameSearch(searchOf("openssl", "3.0.0-r0", *distro.New(distro.Chainguard, "20230214", ""), syftPkg.ApkPkg)))
	require.Len(t, searches, 1)
	var d *search.DistroCriteria
	for _, c := range searches[0] {
		if dc, ok := c.(*search.DistroCriteria); ok {
			d = dc
		}
	}
	require.NotNil(t, d)
	assert.True(t, d.Exact)
	require.Len(t, d.Distros, 1)
	assert.Equal(t, "chainguard-osv", d.Distros[0].Name())
	assert.Empty(t, d.Distros[0].Version)
}

// A client that reads search rules but lacks the subpackage fix (6.1.11, which introduced
// search_rules) must not follow the redirect; every client from the fix on must.
func TestOSVRedirect_ClientGate(t *testing.T) {
	assert.Equal(t, ">= 6.1.12", OSVRedirectClientDBSchemas, "the gate is the addition the fix shipped in and must not move")

	current := fmt.Sprintf("%d.%d.%d", ModelVersion, Revision, Addition)
	for _, tc := range []struct {
		client string
		want   bool
	}{
		{"6.1.10", false},
		{"6.1.11", false},
		{"6.1.12", true},
		{"6.1.20", true},
		{"6.2.0", true},
		{current, true},
	} {
		t.Run(tc.client, func(t *testing.T) {
			got := filterSearchRulesForClient(redirectRules(), version.New(tc.client, version.SemanticFormat))
			if tc.want {
				assert.Len(t, got, 2)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func TestOSVRedirect_Namespace(t *testing.T) {
	vuln := &VulnerabilityHandle{Provider: &Provider{ID: "chainguard"}}
	for osName, want := range map[string]string{
		"chainguard-osv": "chainguard:distro:chainguard:rolling",
		"wolfi-osv":      "chainguard:distro:wolfi:rolling",
		"chainguard":     "chainguard:distro:chainguard:rolling",
	} {
		got := MimicV5Namespace(vuln, &AffectedPackageHandle{
			Package:         &Package{Name: "openssl", Ecosystem: "apk"},
			OperatingSystem: &OperatingSystem{Name: osName, ReleaseID: osName, LabelVersion: "rolling"},
		})
		assert.Equal(t, want, got, osName)
	}
}

// The redirect end to end on one DB holding both row sets: today's secdb rows under chainguard and the
// OSV rows under chainguard-osv.
func TestOSVRedirect_DB(t *testing.T) { //nolint:funlen // one case per client and DB shape
	const (
		secdbCVE = "CVE-2026-1001"
		osvCVE   = "CVE-2026-1002"
	)
	cg := *distro.New(distro.Chainguard, "20230214", "")
	p := searchOf("openssl", "3.0.0-r0", cg, syftPkg.ApkPkg)

	build := func(t *testing.T, withOSV, withRule, dropTable bool) string {
		dir := t.TempDir()
		s := setupTestStore(t, dir)
		addApkRow(t, s, secdbCVE, "chainguard")
		if withOSV {
			addApkRow(t, s, osvCVE, "chainguard-osv")
		}
		if withRule {
			r := OSVRedirectSearchRules()["chainguard-osv"]
			require.NoError(t, s.AddSearchRules(&r))
		}
		if dropTable {
			require.NoError(t, s.db.Migrator().DropTable(&SearchRule{}))
		}
		require.NoError(t, s.Close())
		return dir
	}

	// found runs the searches the provider's rules make of p's own search, as a matcher does
	found := func(t *testing.T, vp vulnerability.Provider) map[string]string {
		cs := nameSearch(p)
		searches := [][]vulnerability.Criteria{cs}
		if rewritten, ok := vp.(SearchRuleProvider).SearchRewrites(p, cs); ok {
			searches = rewritten
		}
		out := map[string]string{}
		for _, s := range searches {
			vulns, err := vp.FindVulnerabilities(s...)
			require.NoError(t, err)
			for _, v := range vulns {
				out[v.ID] = v.Namespace
			}
		}
		return out
	}

	at := func(v string) *version.Version { return version.New(v, version.SemanticFormat) }
	current := at(fmt.Sprintf("%d.%d.%d", ModelVersion, Revision, Addition))
	secdbOnly := map[string]string{secdbCVE: "chainguard:distro:chainguard:rolling"}

	tests := []struct {
		name          string
		withOSV, rule bool
		client        *version.Version
		dropTable     bool
		want          map[string]string
	}{
		{
			name:    "fixed client, DB with OSV rows and the rule: OSV rows only, plain namespace",
			withOSV: true, rule: true, client: current,
			want: map[string]string{osvCVE: "chainguard:distro:chainguard:rolling"},
		},
		{
			name:    "6.1.11 client (reads search rules, lacks the fix): secdb rows",
			withOSV: true, rule: true, client: at("6.1.11"),
			want: secdbOnly,
		},
		{
			name:   "fixed client, today's secdb-only DB: secdb rows",
			client: current,
			want:   secdbOnly,
		},
		{
			name:    "fixed client, DB with no search_rules table: built-in rules only, secdb rows",
			withOSV: true, client: current, dropTable: true,
			want: secdbOnly,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := build(t, tt.withOSV, tt.rule, tt.dropTable)
			vp := newVulnerabilityProvider(setupReadOnlyTestStore(t, dir), tt.client)
			assert.Equal(t, tt.want, found(t, vp))
		})
	}

	// what a released client does: it never reads search_rules, and finds the distro's OS by name or
	// release ID (v0.96.1 and v0.121.0 alike), so the chainguard-osv OS is out of its reach
	t.Run("released clients' OS lookup does not reach chainguard-osv", func(t *testing.T) {
		s := setupReadOnlyTestStore(t, build(t, true, true, false))
		oss, err := s.GetOperatingSystems(OSSpecifier{Name: "chainguard", MajorVersion: "20230214"})
		require.NoError(t, err)
		require.Len(t, oss, 1)
		assert.Equal(t, "chainguard", oss[0].Name)

		var n int64
		require.NoError(t, s.db.Model(&OperatingSystem{}).Where("name = ? collate nocase OR release_id = ? collate nocase", "chainguard", "chainguard").Count(&n).Error)
		assert.EqualValues(t, 1, n, "the released lookup's own query")
	})
}

func redirectRules() []SearchRule {
	var out []SearchRule
	for _, r := range OSVRedirectSearchRules() {
		out = append(out, r)
	}
	return out
}

// addApkRow writes an open apk record for openssl < 3.0.1-r0 under the named rolling OS.
func addApkRow(t *testing.T, s *store, cve, osName string) {
	t.Helper()
	vuln := &VulnerabilityHandle{
		Name:      cve,
		Provider:  &Provider{ID: "chainguard"},
		BlobValue: &VulnerabilityBlob{ID: cve},
	}
	require.NoError(t, s.AddVulnerabilities(vuln))
	require.NoError(t, s.AddAffectedPackages(&AffectedPackageHandle{
		VulnerabilityID: vuln.ID,
		Package:         &Package{Name: "openssl", Ecosystem: "apk"},
		OperatingSystem: &OperatingSystem{Name: osName, ReleaseID: osName, LabelVersion: "rolling"},
		BlobValue: &PackageBlob{
			CVEs:   []string{cve},
			Ranges: []Range{{Version: Version{Type: "apk", Constraint: "< 3.0.1-r0"}}},
		},
	}))
}
