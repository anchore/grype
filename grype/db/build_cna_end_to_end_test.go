package db_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/testdb"
	"github.com/anchore/grype/grype/matcher/java"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// the end-to-end inputs are unmodified vunnel results for the nvd, cve5, github and govulndb providers, extracted
// from real workspaces with grype/db/v6/diff/testdata/result-extractor. The merge's unit tests read the same files.
//
// The `nvd` and `cve5` workspaces are complete, so NVD already has a record for every CVE 5 record. CVE-2026-108714
// and CVE-2026-98165 stand in for CVEs NVD has not received yet by leaving their NVD records out of the inputs, and
// the `github` workspace holds the advisories updated since 2026-09-18.
const endToEndInputs = "v6/build/testdata/cna"

const (
	cveZlib      = "CVE-2026-85091"
	cveBouncyLTS = "CVE-2026-59650"
	cveBouncy    = "CVE-2026-8763"
	ghsaBouncy   = "GHSA-9pwp-9qqc-pr26"
	cveGo        = "CVE-2026-73605"
	ghsaGo       = "GHSA-hf8h-97gm-4x2p"
	cveOnlyCVE5  = "CVE-2026-108714"
	cveLinux     = "CVE-2026-98165"

	jdk18on = "org.bouncycastle:bcprov-jdk18on"
)

// copyEndToEndInputs copies the inputs, because building writes provider state beside the results, and drops the
// providers named in skip.
func copyEndToEndInputs(t *testing.T, skip ...string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.CopyFS(dir, os.DirFS(endToEndInputs)))
	for _, name := range skip {
		require.NoError(t, os.RemoveAll(filepath.Join(dir, name)))
	}
	return dir
}

func buildEndToEnd(t *testing.T, inputDir string, reconcile bool) string {
	t.Helper()
	out := newOutputDir(t)
	testdb.BuildFromFlatFileDirWithConfig(t, cnaBuildTime, out, inputDir, func(cfg *db.BuildConfig) {
		cfg.ReconcileCNA = reconcile
	}, allResults)
	return out
}

func packageRows(t *testing.T, r v6.Reader, name, ecosystem string) []v6.AffectedPackageHandle {
	t.Helper()
	rows, err := r.GetAffectedPackages(
		&v6.PackageSpecifier{Name: name, Ecosystem: ecosystem},
		&v6.GetPackageOptions{PreloadBlob: true, PreloadVulnerability: true},
	)
	require.NoError(t, err)
	return rows
}

// providerAndName lists "<provider> <vulnerability>" for package rows, sorted.
func providerAndName(rows []v6.AffectedPackageHandle) []string {
	var out []string
	for _, row := range rows {
		out = append(out, row.Vulnerability.ProviderID+" "+row.Vulnerability.Name)
	}
	sort.Strings(out)
	return out
}

func constraints(row v6.AffectedPackageHandle) []string {
	var out []string
	for _, r := range row.BlobValue.Ranges {
		out = append(out, r.Version.Constraint)
	}
	return out
}

// packageRowsOf returns every affected package row for a vulnerability under a provider.
func packageRowsOf(t *testing.T, r v6.Reader, vulnerability, providerID string) []v6.AffectedPackageHandle {
	t.Helper()
	rows, err := r.GetAffectedPackages(nil, &v6.GetPackageOptions{
		PreloadPackage:       true,
		PreloadBlob:          true,
		PreloadVulnerability: true,
		Vulnerabilities:      []v6.VulnerabilitySpecifier{{Name: vulnerability}},
	})
	require.NoError(t, err)

	var out []v6.AffectedPackageHandle
	for _, row := range rows {
		if row.Vulnerability.ProviderID == providerID {
			out = append(out, row)
		}
	}
	return out
}

func packageNamesOf(rows []v6.AffectedPackageHandle) []string {
	var out []string
	for _, row := range rows {
		out = append(out, row.Package.Ecosystem+":"+row.Package.Name)
	}
	sort.Strings(out)
	return out
}

func TestBuild_reconcileCNAEndToEnd(t *testing.T) {
	out := buildEndToEnd(t, copyEndToEndInputs(t), true)
	r := openBuilt(t, out)

	t.Run("nothing is written under cve5", func(t *testing.T) {
		// govulndb has no provider row because its only record is covered by the GHSA, and the govulndb merge drops it
		assert.Equal(t, []string{"github", "nvd"}, providerNames(t, r))
		for _, name := range []string{cveZlib, cveBouncy, cveBouncyLTS, cveOnlyCVE5} {
			for _, v := range vulnerabilities(t, r, name) {
				assert.NotEqual(t, "cve5", v.ProviderID)
			}
		}
	})

	t.Run("the CNA's CPE range stands in for the configurations NVD has not written", func(t *testing.T) {
		cpes, err := r.GetAffectedCPEs(&cpe.Attributes{Part: "a", Vendor: "zlib", Product: "zlib"}, &v6.GetCPEOptions{PreloadBlob: true, PreloadVulnerability: true})
		require.NoError(t, err)
		require.Len(t, cpes, 1)
		assert.Equal(t, cveZlib, cpes[0].Vulnerability.Name)
		require.Len(t, cpes[0].BlobValue.Ranges, 1)
		assert.Equal(t, ">= 1.3.1.2, <= 1.3.2", cpes[0].BlobValue.Ranges[0].Version.Constraint)
	})

	t.Run("an analyzed CVE gets the CNA's package rows next to its NVD CPE rows", func(t *testing.T) {
		rows := packageRowsOf(t, r, cveBouncyLTS, "nvd")
		require.Equal(t, []string{"java-archive:org.bouncycastle:bcprov-jdk18on", "java-archive:org.bouncycastle:bcprov-lts8on"}, packageNamesOf(rows))
		for _, row := range rows {
			switch row.Package.Name {
			case jdk18on:
				assert.Equal(t, []string{"< 1.85"}, constraints(row))
			default:
				assert.Equal(t, []string{">= 2.73.0, < 2.73.12"}, constraints(row))
			}
		}

		cpes, err := r.GetAffectedCPEs(nil, &v6.GetCPEOptions{PreloadVulnerability: true, Vulnerabilities: []v6.VulnerabilitySpecifier{{Name: cveBouncyLTS}}})
		require.NoError(t, err)
		assert.NotEmpty(t, cpes, "the NVD CPE rows are kept")
	})

	t.Run("the GHSA's rows displace the CNA's for the same packages", func(t *testing.T) {
		assert.Empty(t, packageRowsOf(t, r, cveBouncy, "nvd"))
		assert.Len(t, packageRowsOf(t, r, ghsaBouncy, "github"), 6, "one row per affected range")

		vulns := vulnerabilities(t, r, cveBouncy)
		require.Len(t, vulns, 1)
		assert.Equal(t, "nvd", vulns[0].ProviderID)

		cpes, err := r.GetAffectedCPEs(nil, &v6.GetCPEOptions{PreloadVulnerability: true, Vulnerabilities: []v6.VulnerabilitySpecifier{{Name: cveBouncy}}})
		require.NoError(t, err)
		assert.NotEmpty(t, cpes, "the CVE's CPE rows are kept")

		// the drops are recorded on the CVE
		require.Len(t, vulns[0].BlobValue.Modifications, 1)
		mod := vulns[0].BlobValue.Modifications[0]
		assert.Equal(t, ghsaBouncy, mod.URL)
		require.Len(t, mod.Changes, 3)
		for _, name := range []string{"org.bouncycastle:bc-fips", jdk18on, "org.bouncycastle:bcprov-lts8on"} {
			assert.Contains(t, strings.Join(mod.Changes, "\n"), name)
		}
	})

	t.Run("a Go GHSA held for the govulndb merge displaces the CNA's go-module row", func(t *testing.T) {
		rows := packageRows(t, r, "github.com/siyuan-note/siyuan/kernel", "go-module")
		assert.Equal(t, []string{"github " + ghsaGo}, providerAndName(rows))

		assert.Len(t, vulnerabilities(t, r, cveGo), 1, "the CVE's vulnerability is kept")
	})

	t.Run("a CVE with only a CVE 5 record is written under nvd without a severity", func(t *testing.T) {
		vulns := vulnerabilities(t, r, cveOnlyCVE5)
		require.Len(t, vulns, 1)
		assert.Equal(t, "nvd", vulns[0].ProviderID)
		assert.Equal(t, v6.UnknownVulnerabilityStatus, vulns[0].Status)
		assert.Contains(t, vulns[0].BlobValue.Description, "MCP Kotlin SDK through 0.15.0")
		assert.Empty(t, vulns[0].BlobValue.Severities, "the CNA's CVSS scores are not used")

		rows := packageRows(t, r, "io.modelcontextprotocol:kotlin-sdk-server", "java-archive")
		require.Len(t, rows, 1)
		assert.Equal(t, cveOnlyCVE5, rows[0].Vulnerability.Name)
		assert.Equal(t, []string{"<= 0.15.0"}, constraints(rows[0]))
	})

	t.Run("a Linux CVE with only cpeApplicability is not written", func(t *testing.T) {
		assert.Empty(t, vulnerabilities(t, r, cveLinux))
	})

	t.Run("a jar in range is reported once for each vulnerability that applies", func(t *testing.T) {
		reader, err := v6.NewReader(v6.Config{DBDirPath: out})
		require.NoError(t, err)
		t.Cleanup(func() { _ = reader.Close() })

		p := dbtest.NewPackage("bcprov-jdk18on", "1.84", syftPkg.JavaPkg).
			WithLanguage(syftPkg.Java).
			WithMetadata(grypePkg.JavaMetadata{PomGroupID: "org.bouncycastle", PomArtifactID: "bcprov-jdk18on"}).
			Build()

		matches, _, err := java.NewJavaMatcher(java.MatcherConfig{}).Match(v6.NewVulnerabilityProvider(reader), p)
		require.NoError(t, err)

		var ids []string
		for _, m := range matches {
			ids = append(ids, m.Vulnerability.ID)
		}
		sort.Strings(ids)

		// CVE-2026-8763 is reported by its GHSA only, and CVE-2026-59650 has no GHSA
		assert.Equal(t, []string{cveBouncyLTS, ghsaBouncy}, ids)
	})
}

// tableRows renders every row of every table, except the build's own metadata, as sorted strings.
func tableRows(t *testing.T, dir string) map[string][]string {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(dir, v6.VulnerabilityDBFileName)+"?mode=ro")
	require.NoError(t, err)
	defer conn.Close()

	names, err := conn.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'db_metadata'`)
	require.NoError(t, err)
	var tables []string
	for names.Next() {
		var name string
		require.NoError(t, names.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, names.Err())
	require.NoError(t, names.Close())

	out := make(map[string][]string)
	for _, table := range tables {
		rows, err := conn.Query("SELECT * FROM " + table) //nolint:gosec // table names come from sqlite_master
		require.NoError(t, err)
		columns, err := rows.Columns()
		require.NoError(t, err)

		var rendered []string
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			require.NoError(t, rows.Scan(pointers...))
			rendered = append(rendered, fmt.Sprint(values...))
		}
		require.NoError(t, rows.Err())
		require.NoError(t, rows.Close())

		sort.Strings(rendered)
		out[table] = rendered
	}
	return out
}

func TestBuild_reconcileCNAOffIgnoresCVE5(t *testing.T) {
	// the two builds write to separate directories, because the build is skipped when the output is newer than the input
	withCVE5 := tableRows(t, buildEndToEnd(t, copyEndToEndInputs(t), false))
	withoutCVE5 := tableRows(t, buildEndToEnd(t, copyEndToEndInputs(t, "cve5"), false))

	require.NotEmpty(t, withoutCVE5["affected_package_handles"])
	require.Equal(t, len(withoutCVE5), len(withCVE5))
	for table, rows := range withoutCVE5 {
		assert.Equal(t, rows, withCVE5[table], "table %s", table)
	}
}
