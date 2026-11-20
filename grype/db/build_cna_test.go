package db_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/discard"
	logrusadapter "github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/grype/grype/db"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/testdb"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

const (
	nvdSchema  = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/nvd/schema-1.0.1.json"
	cve5Schema = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/cve5/schema-5.2.0.json"

	// the inputs are unmodified NVD and cvelistV5 records, shared with the NVD transformer's tests
	cnaTestdata = "v6/build/transformers/nvd/testdata/cna"
)

// a file include is passed so the build is not skipped for an empty output directory
const allResults = "**/*.json"

var cnaBuildTime = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

type cnaRecord struct {
	provider string
	cve      string
}

// writeCNAInputs writes flat-file provider results, one envelope per record, the way the flat-file store lays them out.
func writeCNAInputs(t *testing.T, records ...cnaRecord) string {
	t.Helper()
	inputDir := t.TempDir()

	// a provider with no records still gets a (empty) results directory
	for _, r := range records {
		require.NoError(t, os.MkdirAll(filepath.Join(inputDir, r.provider, "results"), 0o755))
	}

	for _, r := range records {
		var schema string
		switch r.provider {
		case "nvd":
			schema = nvdSchema
		default:
			schema = cve5Schema
		}

		item, err := os.ReadFile(filepath.Join(cnaTestdata, r.provider, r.cve+".json"))
		require.NoError(t, err)

		envelope, err := json.Marshal(map[string]any{
			"schema":     schema,
			"identifier": "2026/" + r.cve,
			"item":       json.RawMessage(item),
		})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(inputDir, r.provider, "results", r.cve+".json"), envelope, 0o600))
	}
	return inputDir
}

func emptyProvider(t *testing.T, inputDir, provider string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(inputDir, provider, "results"), 0o755))
}

// the CVEs: 85091 has an NVD record with no configurations, 59650 has only a CVE 5 record, 31391 has only a Linux CVE 5 record
func standardCNAInputs(t *testing.T) string {
	return writeCNAInputs(t,
		cnaRecord{"nvd", "CVE-2026-85091"},
		cnaRecord{"cve5", "CVE-2026-85091"},
		cnaRecord{"cve5", "CVE-2026-59650"},
		cnaRecord{"cve5", "CVE-2026-31391"},
	)
}

func newOutputDir(t *testing.T) string {
	dir := filepath.Join(t.TempDir(), "out")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	return dir
}

func openBuilt(t *testing.T, dir string) v6.Reader {
	t.Helper()
	r, err := v6.NewReader(v6.Config{DBDirPath: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func captureWarnings(t *testing.T) func() string {
	t.Helper()
	logFile := filepath.Join(t.TempDir(), "log.txt")
	l, err := logrusadapter.New(logrusadapter.Config{FileLocation: logFile, Level: logger.WarnLevel})
	require.NoError(t, err)
	log.Set(l)
	t.Cleanup(func() { log.Set(discard.New()) })
	return func() string {
		b, err := os.ReadFile(logFile)
		require.NoError(t, err)
		return string(b)
	}
}

func providerNames(t *testing.T, r v6.Reader) []string {
	t.Helper()
	providers, err := r.AllProviders()
	require.NoError(t, err)
	var names []string
	for _, p := range providers {
		names = append(names, p.ID)
	}
	return names
}

func vulnerabilities(t *testing.T, r v6.Reader, name string) []v6.VulnerabilityHandle {
	t.Helper()
	vulns, err := r.GetVulnerabilities(&v6.VulnerabilitySpecifier{Name: name}, &v6.GetVulnerabilityOptions{Preload: true})
	require.NoError(t, err)
	return vulns
}

func TestBuild_cve5IsSkippedWhenReconciliationIsOff(t *testing.T) {
	warnings := captureWarnings(t)
	in := standardCNAInputs(t)
	out := newOutputDir(t)

	testdb.BuildFromFlatFileDirWithConfig(t, cnaBuildTime, out, in, nil, allResults)

	require.NotContains(t, warnings(), "cve5", "cve5 records are skipped, not counted as dropped")

	r := openBuilt(t, out)
	require.Equal(t, []string{"nvd"}, providerNames(t, r))

	// nothing from the CVE 5 records reaches the database
	require.Empty(t, vulnerabilities(t, r, "CVE-2026-59650"))
	cpes, err := r.GetAffectedCPEs(&cpe.Attributes{Part: "a", Vendor: "zlib", Product: "zlib"}, nil)
	require.NoError(t, err)
	require.Empty(t, cpes)
}

func TestBuild_reconcileCNA(t *testing.T) {
	in := standardCNAInputs(t)
	out := newOutputDir(t)
	testdb.BuildFromFlatFileDirWithConfig(t, cnaBuildTime, out, in, func(cfg *db.BuildConfig) {
		cfg.ReconcileCNA = true
	}, allResults)

	r := openBuilt(t, out)
	require.Equal(t, []string{"nvd"}, providerNames(t, r), "nothing is written under cve5")

	t.Run("CPE rows from the CNA when NVD has no configurations", func(t *testing.T) {
		cpes, err := r.GetAffectedCPEs(&cpe.Attributes{Part: "a", Vendor: "zlib", Product: "zlib"}, &v6.GetCPEOptions{PreloadBlob: true})
		require.NoError(t, err)
		require.Len(t, cpes, 1)
		require.Len(t, cpes[0].BlobValue.Ranges, 1)
		require.Equal(t, ">= 1.3.1.2, <= 1.3.2", cpes[0].BlobValue.Ranges[0].Version.Constraint)
	})

	t.Run("a CVE with only a CVE 5 record is written under nvd", func(t *testing.T) {
		vulns := vulnerabilities(t, r, "CVE-2026-59650")
		require.Len(t, vulns, 1)
		require.Equal(t, "nvd", vulns[0].ProviderID)
		require.Equal(t, v6.UnknownVulnerabilityStatus, vulns[0].Status)
		require.Contains(t, vulns[0].BlobValue.Description, "Bouncy Castle for Java before 1.85")
		require.Empty(t, vulns[0].BlobValue.Severities)

		pkgs, err := r.GetAffectedPackages(
			&v6.PackageSpecifier{Name: "org.bouncycastle:bcprov-jdk18on", Ecosystem: "java-archive"},
			&v6.GetPackageOptions{PreloadBlob: true, PreloadVulnerability: true},
		)
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		require.Equal(t, "CVE-2026-59650", pkgs[0].Vulnerability.Name)
		require.Equal(t, "< 1.85", pkgs[0].BlobValue.Ranges[0].Version.Constraint)
	})

	t.Run("a Linux CVE with only cpeApplicability is not written", func(t *testing.T) {
		require.Empty(t, vulnerabilities(t, r, "CVE-2026-31391"))
	})
}

func TestBuild_reconcileCNAInputChecks(t *testing.T) {
	buildErr := func(t *testing.T, inputDir string, edit func(*db.BuildConfig)) (string, error) {
		t.Helper()
		out := newOutputDir(t)
		cfg := testdb.FlatFileBuildConfig(t, cnaBuildTime, out, inputDir)
		cfg.ReconcileCNA = true
		if edit != nil {
			edit(&cfg)
		}
		err := db.Build(cfg)
		return out, err
	}

	setCVE5Timestamp := func(ts time.Time) func(*db.BuildConfig) {
		return func(cfg *db.BuildConfig) {
			for i := range cfg.States {
				if cfg.States[i].Provider == "cve5" {
					cfg.States[i].Timestamp = ts
				}
			}
		}
	}

	t.Run("missing cve5", func(t *testing.T) {
		in := writeCNAInputs(t, cnaRecord{"nvd", "CVE-2026-85091"})
		out, err := buildErr(t, in, nil)
		require.ErrorContains(t, err, "cve5")
		require.NoFileExists(t, filepath.Join(out, v6.VulnerabilityDBFileName))
	})

	t.Run("missing nvd", func(t *testing.T) {
		in := writeCNAInputs(t, cnaRecord{"cve5", "CVE-2026-85091"})
		out, err := buildErr(t, in, nil)
		require.ErrorContains(t, err, "nvd")
		require.NoFileExists(t, filepath.Join(out, v6.VulnerabilityDBFileName))
	})

	t.Run("empty cve5", func(t *testing.T) {
		in := writeCNAInputs(t, cnaRecord{"nvd", "CVE-2026-85091"})
		emptyProvider(t, in, "cve5")
		out, err := buildErr(t, in, nil)
		require.ErrorContains(t, err, "cve5")
		require.NoFileExists(t, filepath.Join(out, v6.VulnerabilityDBFileName))
	})

	t.Run("cve5 more than 48 hours older than nvd", func(t *testing.T) {
		in := standardCNAInputs(t)
		out, err := buildErr(t, in, setCVE5Timestamp(time.Date(2026, 10, 4, 23, 0, 0, 0, time.UTC)))
		require.ErrorContains(t, err, "cve5")
		require.ErrorContains(t, err, "2026-10-04T23:00:00Z")
		require.ErrorContains(t, err, "2026-10-07T00:00:00Z")
		require.NoFileExists(t, filepath.Join(out, v6.VulnerabilityDBFileName))
	})

	t.Run("cve5 47 hours older than nvd builds", func(t *testing.T) {
		in := standardCNAInputs(t)
		out, err := buildErr(t, in, setCVE5Timestamp(cnaBuildTime.Add(-47*time.Hour)))
		require.NoError(t, err)
		require.FileExists(t, filepath.Join(out, v6.VulnerabilityDBFileName))
	})

	t.Run("schema 5", func(t *testing.T) {
		in := standardCNAInputs(t)
		_, err := buildErr(t, in, func(cfg *db.BuildConfig) { cfg.SchemaVersion = 5 })
		require.ErrorContains(t, err, "schema")
	})
}
