package db_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

	writeCVE5Result := func(t *testing.T, inputDir, schema string, item []byte) {
		t.Helper()
		envelope, err := json.Marshal(map[string]any{"schema": schema, "identifier": "2026/cve-2026-85091", "item": json.RawMessage(item)})
		require.NoError(t, err)
		dir := filepath.Join(inputDir, "cve5", "results")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "CVE-2026-85091.json"), envelope, 0o600))
	}

	t.Run("cve5 with an unsupported schema", func(t *testing.T) {
		in := writeCNAInputs(t, cnaRecord{"nvd", "CVE-2026-85091"})
		item, err := os.ReadFile(filepath.Join(cnaTestdata, "cve5", "CVE-2026-85091.json"))
		require.NoError(t, err)
		writeCVE5Result(t, in, "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/cve5/schema-6.0.0.json", item)

		out, err := buildErr(t, in, nil)
		require.ErrorContains(t, err, "cve5")
		require.NoFileExists(t, filepath.Join(out, v6.VulnerabilityDBFileName))
	})

	t.Run("cve5 records that do not decode", func(t *testing.T) {
		in := writeCNAInputs(t, cnaRecord{"nvd", "CVE-2026-85091"})
		writeCVE5Result(t, in, cve5Schema, []byte(`"a string, not a record"`))

		out, err := buildErr(t, in, nil)
		require.ErrorContains(t, err, "cve5")
		require.NoFileExists(t, filepath.Join(out, v6.VulnerabilityDBFileName))
	})

	t.Run("schema 5", func(t *testing.T) {
		in := standardCNAInputs(t)
		_, err := buildErr(t, in, func(cfg *db.BuildConfig) { cfg.SchemaVersion = 5 })
		require.ErrorContains(t, err, "schema")
	})
}

// processorFixture reads a processor test fixture. An openvex fixture is a document, and the provider's result is
// one of its statements, so the first statement is returned for it.
func processorFixture(t *testing.T, fixture string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("processors", "testdata", fixture))
	require.NoError(t, err)
	if fixture != "openvex.json" {
		return b
	}
	var doc struct {
		Statements []json.RawMessage `json:"statements"`
	}
	require.NoError(t, json.Unmarshal(b, &doc))
	require.NotEmpty(t, doc.Statements)
	return doc.Statements[0]
}

// writeEditedInput writes a processor test fixture, with declared string replacements, as a provider's one result.
func writeEditedInput(t *testing.T, inputDir, providerName, schema, fixture string, replacements ...string) {
	t.Helper()
	item := processorFixture(t, fixture)
	r := strings.NewReplacer(replacements...)
	edited := r.Replace(string(item))
	for i := 1; i < len(replacements); i += 2 {
		require.Contains(t, edited, replacements[i])
	}

	envelope, err := json.Marshal(map[string]any{
		"schema":     schema,
		"identifier": providerName + "-" + fixture,
		"item":       json.RawMessage(edited),
	})
	require.NoError(t, err)
	dir := filepath.Join(inputDir, providerName, "results")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, fixture), envelope, 0o600))
}

// only an unscoped package row from an advisory provider stands in for an nvd row; a distro's row or a VEX
// statement about one version is not a second finding for the same package
func TestBuild_reconcileCNAKeepsNVDRowsOtherProvidersDoNotCover(t *testing.T) {
	const cve = "CVE-2026-41608"

	tests := []struct {
		name  string
		input func(t *testing.T, inputDir string)
	}{
		{
			name: "an OS-scoped row for the same package",
			input: func(t *testing.T, inputDir string) {
				writeEditedInput(t, inputDir, "hummingbird",
					"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/csaf-vex/schema-2.0.0.json",
					"csaf-vex.json",
					"CVE-2026-12345", cve,
					"pkg:rpm/redhat/testpkg@1.2.3-1.hum1?arch=src", "pkg:pypi/thrift@0.24.0",
				)
			},
		},
		{
			name: "an openvex affected statement for one version",
			input: func(t *testing.T, inputDir string) {
				writeEditedInput(t, inputDir, "openvex",
					"https://github.com/openvex/spec/openvex_json_schema_0.2.0.json",
					"openvex.json",
					"CVE-2023-45803", cve,
					"pkg:pypi/urllib3@1.26.16+cgr.1", "pkg:pypi/thrift@0.23.0",
					`"status": "fixed"`, `"status": "affected"`,
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := writeCNAInputs(t, cnaRecord{"nvd", cve}, cnaRecord{"cve5", cve})
			tt.input(t, in)
			out := newOutputDir(t)
			testdb.BuildFromFlatFileDirWithConfig(t, cnaBuildTime, out, in, func(cfg *db.BuildConfig) {
				cfg.ReconcileCNA = true
			}, allResults)

			pkgs, err := openBuilt(t, out).GetAffectedPackages(
				&v6.PackageSpecifier{Name: "thrift", Ecosystem: "python"},
				&v6.GetPackageOptions{PreloadVulnerability: true},
			)
			require.NoError(t, err)

			byProvider := map[string][]string{}
			for _, p := range pkgs {
				byProvider[p.Vulnerability.ProviderID] = append(byProvider[p.Vulnerability.ProviderID], p.Vulnerability.Name)
			}
			require.Len(t, byProvider, 2, "the other provider's row is written too: %v", byProvider)
			require.Equal(t, []string{cve}, byProvider["nvd"])
		})
	}
}

// addObservedFixDates makes a declared edit to a published CVE 5 result in inputDir: an `x_observedFixDates` list
// is added to its CNA container. Published records carry no such list.
func addObservedFixDates(t *testing.T, inputDir, cve string, entries ...map[string]any) {
	t.Helper()
	path := filepath.Join(inputDir, "cve5", "results", cve+".json")
	b, err := os.ReadFile(path)
	require.NoError(t, err)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(b, &envelope))
	item := envelope["item"].(map[string]any)
	item["containers"].(map[string]any)["cna"].(map[string]any)["x_observedFixDates"] = entries

	b, err = json.Marshal(envelope)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, b, 0o600))
}

func TestBuild_reconcileCNAFixDates(t *testing.T) {
	const (
		bcprov     = "pkg:maven/org.bouncycastle/bcprov-jdk18on"
		bcprovLTS  = "pkg:maven/org.bouncycastle/bcprov-lts8on"
		craft      = "cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*"
		craftPURL  = "pkg:composer/craftcms/cms"
		firstSeen  = "first-observed"
		bcpDate    = "2026-08-01"
		craftDate  = "2026-09-11"
		missingMsg = `missing fix date for version "2.73.12"`
	)

	// the CNA bounds of the CVE 5 only records: bcprov 1.85, bcprov-lts8on 2.73.12, and craft_cms 5.10.6 and 4.18.2
	// as both CPE bounds and composer package bounds
	inputs := func(t *testing.T, withLTS bool) string {
		in := writeCNAInputs(t,
			cnaRecord{"nvd", "CVE-2026-85091"},
			cnaRecord{"cve5", "CVE-2026-85091"},
			cnaRecord{"cve5", "CVE-2026-59650"},
			cnaRecord{"cve5", "CVE-2026-72778"},
		)
		entries := []map[string]any{{"packageURL": bcprov, "fixVersion": "1.85", "date": bcpDate, "kind": firstSeen}}
		if withLTS {
			entries = append(entries, map[string]any{"packageURL": bcprovLTS, "fixVersion": "2.73.12", "date": bcpDate, "kind": firstSeen})
		}
		addObservedFixDates(t, in, "CVE-2026-59650", entries...)
		addObservedFixDates(t, in, "CVE-2026-72778",
			map[string]any{"criteria": craft, "fixVersion": "5.10.6", "date": craftDate, "kind": firstSeen},
			map[string]any{"criteria": craft, "fixVersion": "4.18.2", "date": craftDate, "kind": firstSeen},
			map[string]any{"packageURL": craftPURL, "fixVersion": "5.10.6", "date": craftDate, "kind": firstSeen},
			map[string]any{"packageURL": craftPURL, "fixVersion": "4.18.2", "date": craftDate, "kind": firstSeen},
		)
		return in
	}

	strictBuild := func(t *testing.T, in string) (string, error) {
		out := newOutputDir(t)
		cfg := testdb.FlatFileBuildConfig(t, cnaBuildTime, out, in)
		cfg.ReconcileCNA = true
		cfg.FailOnMissingFixDate = true
		return out, db.Build(cfg)
	}

	t.Run("every CNA bound has an entry", func(t *testing.T) {
		out, err := strictBuild(t, inputs(t, true))
		require.NoError(t, err)

		r := openBuilt(t, out)
		pkgs, err := r.GetAffectedPackages(
			&v6.PackageSpecifier{Name: "org.bouncycastle:bcprov-jdk18on", Ecosystem: "java-archive"},
			&v6.GetPackageOptions{PreloadBlob: true},
		)
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		fix := pkgs[0].BlobValue.Ranges[0].Fix
		require.Equal(t, "1.85", fix.Version)
		require.Equal(t, firstSeen, fix.Detail.Available.Kind)
		require.Equal(t, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), fix.Detail.Available.Date.UTC())

		cpes, err := r.GetAffectedCPEs(&cpe.Attributes{Part: "a", Vendor: "craftcms", Product: "craft_cms"}, &v6.GetCPEOptions{PreloadBlob: true})
		require.NoError(t, err)
		require.Len(t, cpes, 1)
		for _, rng := range cpes[0].BlobValue.Ranges {
			require.NotNil(t, rng.Fix, rng.Version.Constraint)
			require.NotNil(t, rng.Fix.Detail, rng.Version.Constraint)
			require.Equal(t, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC), rng.Fix.Detail.Available.Date.UTC())
		}
	})

	t.Run("a CNA bound with no entry fails the build, naming the fix version", func(t *testing.T) {
		_, err := strictBuild(t, inputs(t, false))
		require.ErrorContains(t, err, missingMsg)
	})
}
