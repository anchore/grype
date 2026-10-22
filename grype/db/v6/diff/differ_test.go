package diff

import (
	"archive/tar"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/db/v6/testdb"
)

var debug = os.Getenv("GRYPE_DEV_DB_DEBUG") == "true"

func Test_basicPackageDiff(t *testing.T) {
	type changes []any
	type added []string
	type modified []string
	type removed []string
	tests := []struct {
		name     string
		oldDB    []string
		newDB    []string
		expected map[string]changes
	}{
		{
			name: "os-echo-add",
			oldDB: []string{
				"cve-2025-59800",
			},
			newDB: []string{
				"cve-2025-59800",
				"cve-2025-59801",
			},
			expected: map[string]changes{
				"ghostscript": {
					added{"CVE-2025-59801"},
				},
			},
		},
		{
			name: "os-echo-modify",
			oldDB: []string{
				"cve-2025-59800",
				"cve-2025-59801",
			},
			newDB: []string{
				"cve-2025-59800",
				"cve-2025-59801-modified",
			},
			expected: map[string]changes{
				"ghostscript": {
					modified{"CVE-2025-59801"},
				},
			},
		},
		{
			name: "os-echo-remove",
			oldDB: []string{
				"cve-2025-59800",
				"cve-2025-59801",
			},
			newDB: []string{
				"cve-2025-59800",
			},
			expected: map[string]changes{
				"ghostscript": {
					removed{"CVE-2025-59801"},
				},
			},
		},
		{
			name: "cpe-added",
			oldDB: []string{
				"cve-2025-24456",
			},
			newDB: []string{
				"cve-2025-24456",
				"cve-2025-21916",
			},
			expected: map[string]changes{
				"linux_kernel": {
					added{"CVE-2025-21916"},
				},
			},
		},
		{
			name: "cpe-removed",
			oldDB: []string{
				"cve-2025-24456",
				"cve-2025-21916",
			},
			newDB: []string{
				"cve-2025-24456",
			},
			expected: map[string]changes{
				"linux_kernel": {
					removed{"CVE-2025-21916"},
				},
			},
		},
		{
			name: "cpe-modified",
			oldDB: []string{
				"cve-2025-24456",
				"cve-2025-21916",
			},
			newDB: []string{
				"cve-2025-24456",
				"cve-2025-21916-modified",
			},
			expected: map[string]changes{
				"linux_kernel": {
					modified{"CVE-2025-21916"},
				},
			},
		},
		{
			name: "channel-added",
			oldDB: []string{
				"rhel-8/cve-2025-13012",
			},
			newDB: []string{
				"rhel-8/cve-2025-13012",
				"rhel-8.4+eus/cve-2025-13012",
			},
			expected: map[string]changes{
				"firefox": {
					added{"CVE-2025-13012"},
				},
				"thunderbird": {
					added{"CVE-2025-13012"},
				},
			},
		},
		{
			name: "channel-added-removed",
			oldDB: []string{
				"rhel-8/cve-2025-13012",
			},
			newDB: []string{
				"rhel-8.4+eus/cve-2025-13012",
			},
			expected: map[string]changes{
				"firefox": {
					added{"CVE-2025-13012"},
					removed{"CVE-2025-13012"},
				},
				"thunderbird": {
					added{"CVE-2025-13012"},
					removed{"CVE-2025-13012"},
				},
			},
		},
		{
			name: "unaffected-added",
			oldDB: []string{
				"pypi/CGA-r79g-x2wf-m9qj.json",
			},
			newDB: []string{
				"pypi/CGA-r79g-x2wf-m9qj.json",
				"pypi/CGA-v587-68x3-qwqr.json",
			},
			expected: map[string]changes{
				"pillow": {
					added{"CGA-v587-68x3-qwqr"},
				},
			},
		},
		{
			name: "unaffected-removed",
			oldDB: []string{
				"pypi/CGA-r79g-x2wf-m9qj.json",
				"pypi/CGA-v587-68x3-qwqr.json",
			},
			newDB: []string{
				"pypi/CGA-r79g-x2wf-m9qj.json",
			},
			expected: map[string]changes{
				"pillow": {
					removed{"CGA-v587-68x3-qwqr"},
				},
			},
		},
		{
			name: "unaffected-modified",
			oldDB: []string{
				"pypi/CGA-r79g-x2wf-m9qj.json",
				"pypi/CGA-v587-68x3-qwqr.json",
			},
			newDB: []string{
				"pypi/CGA-r79g-x2wf-m9qj.json",
				"pypi/CGA-v587-68x3-qwqr-modified.json",
			},
			expected: map[string]changes{
				"pillow": {
					modified{"CGA-v587-68x3-qwqr"},
				},
			},
		},
		{
			name: "status-change-removal",
			oldDB: []string{
				"2020/cve-2020-15415",
			},
			newDB: []string{
				"2020/cve-2020-15415-status-rejected",
			},
			expected: map[string]changes{
				"vigor3900": {
					removed{"cve-2020-15415"},
				},
			},
		},
		{
			name: "status-change-addition",
			oldDB: []string{
				"2020/cve-2020-15415-status-rejected",
			},
			newDB: []string{
				"2020/cve-2020-15415",
			},
			expected: map[string]changes{
				"vigor3900": {
					added{"cve-2020-15415"},
				},
			},
		},
	}

	testdataDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	inputDir := filepath.Join(testdataDir, "inputs")

	var tmpdir string
	if debug {
		tmpdir = filepath.Join(testdataDir, "cache")
		t.Logf("using persistent testdata cache dir: %s", tmpdir)
	} else {
		tmpdir = t.TempDir()
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpdir := filepath.Join(tmpdir, regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(t.Name(), "_"))

			oldDB := filepath.Join(tmpdir, "oldDB")
			err = os.MkdirAll(oldDB, 0o755)
			require.NoError(t, err)

			testdb.BuildFromFlatFileDir(t,
				time.Date(2022, 8, 11, 18, 1, 5, 0, time.UTC),
				oldDB,
				inputDir,
				tt.oldDB...)

			newDB := filepath.Join(tmpdir, "newDB")
			testdb.BuildFromFlatFileDir(t,
				time.Date(2022, 8, 12, 1, 55, 19, 0, time.UTC),
				newDB,
				inputDir,
				tt.newDB...)

			differ, err := NewDBDiffer(Config{
				Config: installation.Config{},
				Debug:  debug,
				OldDB:  oldDB,
				NewDB:  newDB,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = differ.Close() })
			require.NotNil(t, differ)

			packageResult, err := differ.Diff()
			require.NoError(t, err)

			for pkg, expected := range tt.expected {
				pkgs := findPackageDiff(packageResult, pkg)
				if len(expected) == 0 {
					require.Empty(t, pkgs, "expected no package diff for %q", pkg)
					continue
				}
				require.NotEmpty(t, pkgs, "expected package diff for %q", pkg)

				vulnChanges := pkgs[0].Vulnerabilities

				hasAdded := false
				hasModified := false
				hasRemoved := false
				for _, expected := range expected {
					switch expected := expected.(type) {
					case added:
						hasAdded = true
						requireVulns(t, "added", vulnChanges.Added, expected...)
					case modified:
						hasModified = true
						requireVulns(t, "modified", vulnChanges.Modified, expected...)
					case removed:
						hasRemoved = true
						requireVulns(t, "removed", vulnChanges.Removed, expected...)
					}
				}
				if !hasAdded {
					require.Emptyf(t, vulnChanges.Added, "expected no added vulns; expected changes: %+v", vulnChanges)
				}
				if !hasModified {
					require.Emptyf(t, vulnChanges.Modified, "expected no modified vulns; expected changes: %+v", vulnChanges)
				}
				if !hasRemoved {
					require.Emptyf(t, vulnChanges.Removed, "expected no removed vulns; expected changes: %+v", vulnChanges)
				}
			}

			// make sure we don't have unexpected changes
			for _, pkg := range packageResult.Packages {
				if _, checked := tt.expected[pkg.Name]; !checked {
					assert.Failf(t, "packge found in diff not expected", "%q: %+v", pkg.Name, pkg.Vulnerabilities)
				}
			}
		})
	}
}

func Test_packageDiff(t *testing.T) {
	type changes []any
	type pkg struct {
		ecosystem string
		name      string
	}
	type added []VulnerabilityID
	type modified []VulnerabilityID
	type removed []VulnerabilityID
	v := func(provider, id string) VulnerabilityID {
		return VulnerabilityID{Provider: provider, ID: id}
	}
	p := func(ecosystem, name string) pkg {
		return pkg{ecosystem: ecosystem, name: name}
	}
	tests := []struct {
		name     string
		oldDB    []string
		newDB    []string
		expected map[pkg]changes
	}{
		// no-change cases
		{
			name:     "no-changes-os",
			oldDB:    []string{"cve-2025-59800"},
			newDB:    []string{"cve-2025-59800"},
			expected: map[pkg]changes{},
		},
		{
			name:     "no-changes-cpe",
			oldDB:    []string{"cve-2025-24456"},
			newDB:    []string{"cve-2025-24456"},
			expected: map[pkg]changes{},
		},
		{
			name:     "no-changes-os-and-cpe",
			oldDB:    []string{"cve-2025-59800", "cve-2025-24456"},
			newDB:    []string{"cve-2025-59800", "cve-2025-24456"},
			expected: map[pkg]changes{},
		},
		// adding multiple NVD CPE vulns
		{
			name:  "nvd-add-multiple-cpe-vulns",
			oldDB: []string{"cve-2025-24456"},
			newDB: []string{"cve-2025-24456", "cve-2025-21916", "cve-2010-1724"},
			expected: map[pkg]changes{
				p("cpe", "linux_kernel"): {
					added{v("nvd", "CVE-2025-21916")},
				},
				p("cpe", "zikula_application_framework"): {
					added{v("nvd", "CVE-2010-1724")},
				},
			},
		},
		// removing multiple NVD CPE vulns
		{
			name:  "nvd-remove-multiple-cpe-vulns",
			oldDB: []string{"cve-2025-24456", "cve-2025-21916", "cve-2010-1724"},
			newDB: []string{"cve-2025-24456"},
			expected: map[pkg]changes{
				p("cpe", "linux_kernel"): {
					removed{v("nvd", "CVE-2025-21916")},
				},
				p("cpe", "zikula_application_framework"): {
					removed{v("nvd", "CVE-2010-1724")},
				},
			},
		},
		// modifying multiple NVD CPE vulns at once
		{
			name:  "nvd-modify-multiple-cpe-vulns",
			oldDB: []string{"cve-2025-24456", "cve-2025-21916", "cve-2010-1724"},
			newDB: []string{"cve-2025-24456", "cve-2025-21916-modified", "cve-2010-1724-modified"},
			expected: map[pkg]changes{
				p("cpe", "linux_kernel"): {
					modified{v("nvd", "CVE-2025-21916")},
				},
				p("cpe", "zikula_application_framework"): {
					modified{v("nvd", "CVE-2010-1724")},
				},
			},
		},
		// mixed add, remove, modify on NVD CPE vulns
		{
			name:  "nvd-mixed-add-remove-modify-cpe",
			oldDB: []string{"cve-2025-24456", "cve-2025-21916", "cve-2010-1724"},
			newDB: []string{"cve-2025-24456", "cve-2025-21916-modified"},
			expected: map[pkg]changes{
				p("cpe", "linux_kernel"): {
					modified{v("nvd", "CVE-2025-21916")},
				},
				p("cpe", "zikula_application_framework"): {
					removed{v("nvd", "CVE-2010-1724")},
				},
			},
		},
		// add multiple OS vulns to same package (ghostscript via echo=deb + oracle=rpm)
		{
			name:  "os-add-multiple-vulns-same-package",
			oldDB: []string{"cve-2025-24456"},
			newDB: []string{"cve-2025-24456", "cve-2025-59800", "cve-2025-59801"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					added{v("echo", "CVE-2025-59800"), v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					added{v("oracle", "CVE-2025-59801")},
				},
			},
		},
		// remove multiple OS vulns from same package
		{
			name:  "os-remove-multiple-vulns-same-package",
			oldDB: []string{"cve-2025-24456", "cve-2025-59800", "cve-2025-59801"},
			newDB: []string{"cve-2025-24456"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					removed{v("echo", "CVE-2025-59800"), v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					removed{v("oracle", "CVE-2025-59801")},
				},
			},
		},
		// add one vuln, remove another for the same package
		{
			name:  "os-add-and-remove-same-package",
			oldDB: []string{"cve-2025-59801"},
			newDB: []string{"cve-2025-59800"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					added{v("echo", "CVE-2025-59800")},
					removed{v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					removed{v("oracle", "CVE-2025-59801")},
				},
			},
		},
		// modify vuln across echo + oracle providers, add oracle advisory
		{
			name:  "os-add-and-modify-same-package",
			oldDB: []string{"cve-2025-59800", "cve-2025-59801"},
			newDB: []string{"cve-2025-59800", "cve-2025-59801-modified", "ol-10/elsa-2025-8915"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					modified{v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					modified{v("oracle", "CVE-2025-59801")},
				},
				p("rpm", "grafana-pcp"): {
					added{v("oracle", "ELSA-2025-8915")},
				},
			},
		},
		// add multiple oracle advisories affecting different packages
		{
			name:  "os-add-multiple-oracle-advisories",
			oldDB: []string{"cve-2025-59800"},
			newDB: []string{"cve-2025-59800", "ol-10/elsa-2025-8915", "ol-10/elsa-2025-19720", "ol-10/elsa-2025-8047"},
			expected: map[pkg]changes{
				p("rpm", "grafana-pcp"): {
					added{v("oracle", "ELSA-2025-8915")},
				},
				p("rpm", "libsoup3"): {
					added{v("oracle", "ELSA-2025-19720")},
				},
				p("rpm", "libsoup3-devel"): {
					added{v("oracle", "ELSA-2025-19720")},
				},
				p("rpm", "libsoup3-doc"): {
					added{v("oracle", "ELSA-2025-19720")},
				},
				p("rpm", "python3-unbound"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-anchor"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-devel"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-dracut"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-libs"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
			},
		},
		// remove multiple oracle advisories
		{
			name:  "os-remove-multiple-oracle-advisories",
			oldDB: []string{"cve-2025-59800", "ol-10/elsa-2025-8915", "ol-10/elsa-2025-8047"},
			newDB: []string{"cve-2025-59800"},
			expected: map[pkg]changes{
				p("rpm", "grafana-pcp"): {
					removed{v("oracle", "ELSA-2025-8915")},
				},
				p("rpm", "python3-unbound"): {
					removed{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound"): {
					removed{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-anchor"): {
					removed{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-devel"): {
					removed{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-dracut"): {
					removed{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-libs"): {
					removed{v("oracle", "ELSA-2025-8047")},
				},
			},
		},
		// add same vuln from multiple providers (echo + oracle)
		{
			name:  "os-add-vuln-across-providers",
			oldDB: []string{"cve-2025-59800"},
			newDB: []string{"cve-2025-59800", "cve-2025-59801", "ol-9/cve-2025-59801"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					added{v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					added{v("oracle", "CVE-2025-59801")},
				},
			},
		},
		// modify same vuln across multiple providers (echo + oracle)
		{
			name:  "os-modify-vuln-across-providers",
			oldDB: []string{"cve-2025-59800", "cve-2025-59801", "ol-9/cve-2025-59801"},
			newDB: []string{"cve-2025-59800", "cve-2025-59801-modified", "ol-9/cve-2025-59801-modified"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					modified{v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					modified{v("oracle", "CVE-2025-59801")},
				},
			},
		},
		// remove vuln from oracle provider, keep unrelated echo vuln
		{
			name:  "os-remove-oracle-keep-echo",
			oldDB: []string{"cve-2025-59800", "ol-10/elsa-2025-8915"},
			newDB: []string{"cve-2025-59800"},
			expected: map[pkg]changes{
				p("rpm", "grafana-pcp"): {
					removed{v("oracle", "ELSA-2025-8915")},
				},
			},
		},
		// add vuln across multiple RHEL channels
		{
			name:  "os-add-multiple-rhel-channels",
			oldDB: []string{"rhel-8/cve-2025-13012"},
			newDB: []string{"rhel-8/cve-2025-13012", "rhel-8.4+eus/cve-2025-13012", "rhel-9/cve-2025-13012"},
			expected: map[pkg]changes{
				p("rpm", "firefox"): {
					added{v("rhel", "CVE-2025-13012")},
				},
				p("rpm", "thunderbird"): {
					added{v("rhel", "CVE-2025-13012")},
				},
			},
		},
		// remove RHEL channels
		{
			name:  "os-remove-rhel-channels",
			oldDB: []string{"rhel-8/cve-2025-13012", "rhel-8.4+eus/cve-2025-13012", "rhel-9/cve-2025-13012"},
			newDB: []string{"rhel-8/cve-2025-13012"},
			expected: map[pkg]changes{
				p("rpm", "firefox"): {
					removed{v("rhel", "CVE-2025-13012")},
				},
				p("rpm", "thunderbird"): {
					removed{v("rhel", "CVE-2025-13012")},
				},
			},
		},
		// swap RHEL channels (remove old, add new)
		{
			name:  "os-swap-rhel-channels",
			oldDB: []string{"rhel-8/cve-2025-13012"},
			newDB: []string{"rhel-9/cve-2025-13012"},
			expected: map[pkg]changes{
				p("rpm", "firefox"): {
					added{v("rhel", "CVE-2025-13012")},
					removed{v("rhel", "CVE-2025-13012")},
				},
				p("rpm", "thunderbird"): {
					added{v("rhel", "CVE-2025-13012")},
					removed{v("rhel", "CVE-2025-13012")},
				},
			},
		},
		// mixed OS and CPE: add both simultaneously
		{
			name:  "mixed-os-and-cpe-add",
			oldDB: []string{"cve-2025-59800", "cve-2025-24456"},
			newDB: []string{"cve-2025-59800", "cve-2025-24456", "cve-2025-59801", "cve-2025-21916"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					added{v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					added{v("oracle", "CVE-2025-59801")},
				},
				p("cpe", "linux_kernel"): {
					added{v("nvd", "CVE-2025-21916")},
				},
			},
		},
		// mixed OS and CPE: remove both simultaneously
		{
			name:  "mixed-os-and-cpe-remove",
			oldDB: []string{"cve-2025-59800", "cve-2025-59801", "cve-2025-24456", "cve-2025-21916"},
			newDB: []string{"cve-2025-59800", "cve-2025-24456"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					removed{v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					removed{v("oracle", "CVE-2025-59801")},
				},
				p("cpe", "linux_kernel"): {
					removed{v("nvd", "CVE-2025-21916")},
				},
			},
		},
		// mixed OS and CPE: modify both simultaneously
		{
			name:  "mixed-os-and-cpe-modify",
			oldDB: []string{"cve-2025-59800", "cve-2025-59801", "cve-2025-24456", "cve-2025-21916"},
			newDB: []string{"cve-2025-59800", "cve-2025-59801-modified", "cve-2025-24456", "cve-2025-21916-modified"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					modified{v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					modified{v("oracle", "CVE-2025-59801")},
				},
				p("cpe", "linux_kernel"): {
					modified{v("nvd", "CVE-2025-21916")},
				},
			},
		},
		// complex: add OS, modify CPE, remove oracle advisory
		{
			name:  "mixed-add-modify-remove-across-types",
			oldDB: []string{"cve-2025-59800", "cve-2025-24456", "cve-2025-21916", "ol-10/elsa-2025-8915"},
			newDB: []string{"cve-2025-59800", "cve-2025-59801", "cve-2025-24456", "cve-2025-21916-modified"},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					added{v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					added{v("oracle", "CVE-2025-59801")},
				},
				p("cpe", "linux_kernel"): {
					modified{v("nvd", "CVE-2025-21916")},
				},
				p("rpm", "grafana-pcp"): {
					removed{v("oracle", "ELSA-2025-8915")},
				},
			},
		},
		// complex: multiple operations on different packages in a single diff
		{
			name: "mixed-multiple-operations-many-packages",
			oldDB: []string{
				"cve-2025-59800",
				"cve-2025-59801",
				"cve-2025-24456",
				"cve-2025-21916",
				"cve-2010-1724",
				"ol-10/elsa-2025-8915",
				"rhel-8/cve-2025-13012",
			},
			newDB: []string{
				"cve-2025-59800",
				"cve-2025-59801-modified",
				"cve-2025-24456",
				"cve-2025-21916-modified",
				"ol-10/elsa-2025-19720",
				"rhel-8/cve-2025-13012",
				"rhel-9/cve-2025-13012",
			},
			expected: map[pkg]changes{
				p("deb", "ghostscript"): {
					modified{v("echo", "CVE-2025-59801")},
				},
				p("rpm", "ghostscript"): {
					modified{v("oracle", "CVE-2025-59801")},
				},
				p("cpe", "linux_kernel"): {
					modified{v("nvd", "CVE-2025-21916")},
				},
				p("cpe", "zikula_application_framework"): {
					removed{v("nvd", "CVE-2010-1724")},
				},
				p("rpm", "grafana-pcp"): {
					removed{v("oracle", "ELSA-2025-8915")},
				},
				p("rpm", "libsoup3"): {
					added{v("oracle", "ELSA-2025-19720")},
				},
				p("rpm", "libsoup3-devel"): {
					added{v("oracle", "ELSA-2025-19720")},
				},
				p("rpm", "libsoup3-doc"): {
					added{v("oracle", "ELSA-2025-19720")},
				},
				p("rpm", "firefox"): {
					added{v("rhel", "CVE-2025-13012")},
				},
				p("rpm", "thunderbird"): {
					added{v("rhel", "CVE-2025-13012")},
				},
			},
		},
		// add oracle advisory while also adding CPE vuln
		{
			name:  "mixed-oracle-and-cpe-add",
			oldDB: []string{"cve-2025-24456"},
			newDB: []string{"cve-2025-24456", "cve-2025-21916", "ol-10/elsa-2025-8047"},
			expected: map[pkg]changes{
				p("cpe", "linux_kernel"): {
					added{v("nvd", "CVE-2025-21916")},
				},
				p("rpm", "python3-unbound"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-anchor"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-devel"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-dracut"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-libs"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
			},
		},
		// remove one oracle advisory, add another
		{
			name:  "os-swap-oracle-advisories",
			oldDB: []string{"cve-2025-59800", "ol-10/elsa-2025-8915"},
			newDB: []string{"cve-2025-59800", "ol-10/elsa-2025-8047"},
			expected: map[pkg]changes{
				p("rpm", "grafana-pcp"): {
					removed{v("oracle", "ELSA-2025-8915")},
				},
				p("rpm", "python3-unbound"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-anchor"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-devel"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-dracut"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
				p("rpm", "unbound-libs"): {
					added{v("oracle", "ELSA-2025-8047")},
				},
			},
		},
		// add and modify CPE vulns with no OS changes
		{
			name:  "cpe-add-and-modify-only",
			oldDB: []string{"cve-2025-24456", "cve-2010-1724"},
			newDB: []string{"cve-2025-24456", "cve-2010-1724-modified", "cve-2025-21916"},
			expected: map[pkg]changes{
				p("cpe", "zikula_application_framework"): {
					modified{v("nvd", "CVE-2010-1724")},
				},
				p("cpe", "linux_kernel"): {
					added{v("nvd", "CVE-2025-21916")},
				},
			},
		},
		// remove and modify CPE vulns with no OS changes
		{
			name:  "cpe-remove-and-modify-only",
			oldDB: []string{"cve-2025-24456", "cve-2025-21916", "cve-2010-1724"},
			newDB: []string{"cve-2025-24456", "cve-2025-21916-modified"},
			expected: map[pkg]changes{
				p("cpe", "linux_kernel"): {
					modified{v("nvd", "CVE-2025-21916")},
				},
				p("cpe", "zikula_application_framework"): {
					removed{v("nvd", "CVE-2010-1724")},
				},
			},
		},
	}

	testdataDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	inputDir := filepath.Join(testdataDir, "inputs")

	var tmpdir string
	if debug {
		tmpdir = filepath.Join(testdataDir, "cache")
		t.Logf("using persistent testdata cache dir: %s", tmpdir)
	} else {
		tmpdir = t.TempDir()
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpdir := filepath.Join(tmpdir, regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(t.Name(), "_"))

			oldDB := filepath.Join(tmpdir, "oldDB")
			err = os.MkdirAll(oldDB, 0o755)
			require.NoError(t, err)

			testdb.BuildFromFlatFileDir(t,
				time.Date(2022, 8, 11, 18, 1, 5, 0, time.UTC),
				oldDB,
				inputDir,
				tt.oldDB...)

			newDB := filepath.Join(tmpdir, "newDB")
			testdb.BuildFromFlatFileDir(t,
				time.Date(2022, 8, 12, 1, 55, 19, 0, time.UTC),
				newDB,
				inputDir,
				tt.newDB...)

			differ, err := NewDBDiffer(Config{
				Config: installation.Config{},
				Debug:  debug,
				OldDB:  oldDB,
				NewDB:  newDB,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = differ.Close() })
			require.NotNil(t, differ)

			packageResult, err := differ.Diff()
			require.NoError(t, err)

			for expectedPkg, expected := range tt.expected {
				pd := findExactPackageDiff(packageResult, expectedPkg.ecosystem, expectedPkg.name)
				if len(expected) == 0 {
					require.Nilf(t, pd, "expected no package diff for %+v", expectedPkg)
					continue
				}
				require.NotNilf(t, pd, "expected package diff for %+v", expectedPkg)

				vulnChanges := pd.Vulnerabilities

				hasAdded := false
				hasModified := false
				hasRemoved := false
				for _, expected := range expected {
					switch expected := expected.(type) {
					case added:
						hasAdded = true
						requireExactVulnIDs(t, "added", vulnChanges.Added, expected...)
					case modified:
						hasModified = true
						requireExactVulnIDs(t, "modified", vulnChanges.Modified, expected...)
					case removed:
						hasRemoved = true
						requireExactVulnIDs(t, "removed", vulnChanges.Removed, expected...)
					}
				}
				if !hasAdded {
					require.Emptyf(t, vulnChanges.Added, "expected no added vulns for %+v; got: %+v", expectedPkg, vulnChanges.Added)
				}
				if !hasModified {
					require.Emptyf(t, vulnChanges.Modified, "expected no modified vulns for %+v; got: %+v", expectedPkg, vulnChanges.Modified)
				}
				if !hasRemoved {
					require.Emptyf(t, vulnChanges.Removed, "expected no removed vulns for %+v; got: %+v", expectedPkg, vulnChanges.Removed)
				}
			}

			// make sure we don't have unexpected changes
			for _, resultPkg := range packageResult.Packages {
				key := pkg{ecosystem: resultPkg.Ecosystem, name: resultPkg.Name}
				if _, checked := tt.expected[key]; !checked {
					assert.Failf(t, "package found in diff not expected", "%+v: %+v", key, resultPkg.Vulnerabilities)
				}
			}
		})
	}
}

// Test_hydrationPermutations verifies that the differ works correctly across different database
// schema states, simulating older databases that may be missing columns added in later schema
// versions. For example, the "channel" column was added to the operating_systems table in
// schema 6.0.3 — an older database archive would not have it. The hydration step in
// newResolvedDB should add any missing columns/indexes before the diff runs.
func Test_hydrationPermutations(t *testing.T) {
	type dbMutation func(t *testing.T, dbDir string)

	// dropOSChannel simulates a pre-6.0.3 database by removing the channel column
	// from the operating_systems table. In SQLite, ALTER TABLE DROP COLUMN requires
	// dropping dependent indexes first.
	dropOSChannel := func(t *testing.T, dbDir string) {
		t.Helper()
		dbPath := filepath.Join(dbDir, "vulnerability.db")
		db, err := v6.NewLowLevelDB(dbPath, false, true, false)
		require.NoError(t, err)
		defer closeLowLevelDB(db)

		// drop indexes that reference the channel column
		require.NoError(t, db.Exec("DROP INDEX IF EXISTS idx_operating_systems_channel").Error)
		require.NoError(t, db.Exec("DROP INDEX IF EXISTS os_idx").Error)
		// now drop the column
		require.NoError(t, db.Exec("ALTER TABLE operating_systems DROP COLUMN channel").Error)
	}

	type changes []any
	type pkg struct {
		ecosystem string
		name      string
	}
	type added []VulnerabilityID
	type removed []VulnerabilityID

	v := func(provider, id string) VulnerabilityID {
		return VulnerabilityID{Provider: provider, ID: id}
	}
	p := func(ecosystem, name string) pkg {
		return pkg{ecosystem: ecosystem, name: name}
	}

	tests := []struct {
		name      string
		oldDB     []string
		newDB     []string
		mutateOld dbMutation // applied to the old DB after build, before diff
		mutateNew dbMutation // applied to the new DB after build, before diff
		expected  map[pkg]changes
	}{
		{
			name:  "both-current-with-channel",
			oldDB: []string{"rhel-8/cve-2025-13012"},
			newDB: []string{"rhel-8/cve-2025-13012", "rhel-8.4+eus/cve-2025-13012"},
			expected: map[pkg]changes{
				p("rpm", "firefox"):     {added{v("rhel", "CVE-2025-13012")}},
				p("rpm", "thunderbird"): {added{v("rhel", "CVE-2025-13012")}},
			},
		},
		{
			name:      "old-db-missing-channel-column",
			oldDB:     []string{"rhel-8/cve-2025-13012"},
			newDB:     []string{"rhel-8/cve-2025-13012", "rhel-8.4+eus/cve-2025-13012"},
			mutateOld: dropOSChannel,
			expected: map[pkg]changes{
				p("rpm", "firefox"):     {added{v("rhel", "CVE-2025-13012")}},
				p("rpm", "thunderbird"): {added{v("rhel", "CVE-2025-13012")}},
			},
		},
		{
			name:      "new-db-missing-channel-column",
			oldDB:     []string{"rhel-8/cve-2025-13012", "rhel-8.4+eus/cve-2025-13012"},
			newDB:     []string{"rhel-8/cve-2025-13012"},
			mutateNew: dropOSChannel,
			expected: map[pkg]changes{
				p("rpm", "firefox"):     {removed{v("rhel", "CVE-2025-13012")}},
				p("rpm", "thunderbird"): {removed{v("rhel", "CVE-2025-13012")}},
			},
		},
		{
			name:      "both-dbs-missing-channel-column",
			oldDB:     []string{"rhel-8/cve-2025-13012"},
			newDB:     []string{"rhel-8/cve-2025-13012", "rhel-9/cve-2025-13012"},
			mutateOld: dropOSChannel,
			mutateNew: dropOSChannel,
			expected: map[pkg]changes{
				p("rpm", "firefox"):     {added{v("rhel", "CVE-2025-13012")}},
				p("rpm", "thunderbird"): {added{v("rhel", "CVE-2025-13012")}},
			},
		},
		{
			name:      "no-changes-after-hydration",
			oldDB:     []string{"rhel-8/cve-2025-13012"},
			newDB:     []string{"rhel-8/cve-2025-13012"},
			mutateOld: dropOSChannel,
			expected:  map[pkg]changes{},
		},
		{
			name:      "mixed-os-and-cpe-with-old-db-missing-channel",
			oldDB:     []string{"rhel-8/cve-2025-13012", "cve-2025-24456"},
			newDB:     []string{"rhel-8/cve-2025-13012", "rhel-8.4+eus/cve-2025-13012", "cve-2025-24456", "cve-2025-21916"},
			mutateOld: dropOSChannel,
			expected: map[pkg]changes{
				p("rpm", "firefox"):      {added{v("rhel", "CVE-2025-13012")}},
				p("rpm", "thunderbird"):  {added{v("rhel", "CVE-2025-13012")}},
				p("cpe", "linux_kernel"): {added{v("nvd", "CVE-2025-21916")}},
			},
		},
	}

	testdataDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	inputDir := filepath.Join(testdataDir, "inputs")

	var tmpdir string
	if debug {
		tmpdir = filepath.Join(testdataDir, "cache")
		t.Logf("using persistent testdata cache dir: %s", tmpdir)
	} else {
		tmpdir = t.TempDir()
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpdir := filepath.Join(tmpdir, regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(t.Name(), "_"))

			oldDBDir := filepath.Join(tmpdir, "oldDB")
			err = os.MkdirAll(oldDBDir, 0o755)
			require.NoError(t, err)

			testdb.BuildFromFlatFileDir(t,
				time.Date(2022, 8, 11, 18, 1, 5, 0, time.UTC),
				oldDBDir,
				inputDir,
				tt.oldDB...)

			if tt.mutateOld != nil {
				tt.mutateOld(t, oldDBDir)
			}

			newDBDir := filepath.Join(tmpdir, "newDB")
			testdb.BuildFromFlatFileDir(t,
				time.Date(2022, 8, 12, 1, 55, 19, 0, time.UTC),
				newDBDir,
				inputDir,
				tt.newDB...)

			if tt.mutateNew != nil {
				tt.mutateNew(t, newDBDir)
			}

			differ, err := NewDBDiffer(Config{
				Config: installation.Config{},
				Debug:  debug,
				OldDB:  oldDBDir,
				NewDB:  newDBDir,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = differ.Close() })
			require.NotNil(t, differ)

			packageResult, err := differ.Diff()
			require.NoError(t, err)

			for expectedPkg, expected := range tt.expected {
				pd := findExactPackageDiff(packageResult, expectedPkg.ecosystem, expectedPkg.name)
				if len(expected) == 0 {
					require.Nilf(t, pd, "expected no package diff for %+v", expectedPkg)
					continue
				}
				require.NotNilf(t, pd, "expected package diff for %+v", expectedPkg)

				vulnChanges := pd.Vulnerabilities

				hasAdded := false
				hasRemoved := false
				for _, expected := range expected {
					switch expected := expected.(type) {
					case added:
						hasAdded = true
						requireExactVulnIDs(t, "added", vulnChanges.Added, expected...)
					case removed:
						hasRemoved = true
						requireExactVulnIDs(t, "removed", vulnChanges.Removed, expected...)
					}
				}
				if !hasAdded {
					require.Emptyf(t, vulnChanges.Added, "expected no added vulns for %+v; got: %+v", expectedPkg, vulnChanges.Added)
				}
				if !hasRemoved {
					require.Emptyf(t, vulnChanges.Removed, "expected no removed vulns for %+v; got: %+v", expectedPkg, vulnChanges.Removed)
				}
			}

			// make sure we don't have unexpected changes
			for _, resultPkg := range packageResult.Packages {
				key := pkg{ecosystem: resultPkg.Ecosystem, name: resultPkg.Name}
				if _, checked := tt.expected[key]; !checked {
					assert.Failf(t, "package found in diff not expected", "%+v: %+v", key, resultPkg.Vulnerabilities)
				}
			}
		})
	}
}

// Test_handlesWithoutBlobs verifies that package / CPE handles without a blob are excluded from the diff, rather than
// being reported as modified (missing blobs can't be compared, so they would never be considered equivalent)
func Test_handlesWithoutBlobs(t *testing.T) {
	inputDir, err := filepath.Abs(filepath.Join("testdata", "inputs"))
	require.NoError(t, err)

	removeBlobs := func(dbDir string) {
		db, err := v6.NewLowLevelDB(filepath.Join(dbDir, v6.VulnerabilityDBFileName), false, true, false)
		require.NoError(t, err)
		defer closeLowLevelDB(db)
		require.NoError(t, db.Exec("PRAGMA foreign_keys = OFF").Error)
		for _, table := range []string{"affected_package_handles", "unaffected_package_handles", "affected_cpe_handles", "unaffected_cpe_handles"} {
			require.NoError(t, db.Exec("UPDATE "+table+" SET blob_id = 0").Error)
		}
	}

	tmpdir := t.TempDir()
	var dirs []string
	for _, name := range []string{"oldDB", "newDB"} {
		dir := filepath.Join(tmpdir, name)
		testdb.BuildFromFlatFileDir(t, time.Time{}, dir, inputDir, "cve-2025-59800", "cve-2020-15415")
		removeBlobs(dir)
		dirs = append(dirs, dir)
	}

	differ, err := NewDBDiffer(Config{Config: installation.Config{}, OldDB: dirs[0], NewDB: dirs[1]})
	require.NoError(t, err)
	t.Cleanup(func() { _ = differ.Close() })

	result, err := differ.Diff()
	require.NoError(t, err)
	require.Empty(t, result.Packages)
}

// Test_packageDiffExact asserts the exact package results for edge cases that can't be expressed with the flat file
// fixtures alone, so the databases are altered with SQL after they are built
func Test_packageDiffExact(t *testing.T) {
	tests := []struct {
		name      string
		oldDB     []string
		newDB     []string
		mutateOld []string
		mutateNew []string
		expected  []PackageDiff
	}{
		{
			// NULL and '' are reported identically, so they must be treated as the same package / CPE
			name:      "null and empty values are equivalent",
			oldDB:     []string{"cve-2025-59800", "cve-2025-21916"},
			newDB:     []string{"cve-2025-59800", "cve-2025-21916"},
			mutateOld: []string{"UPDATE packages SET ecosystem = NULL", "UPDATE cpes SET edition = NULL"},
			mutateNew: []string{"UPDATE packages SET ecosystem = ''"},
		},
		{
			// fix availability doesn't affect matching, so blobs that only differ there are not modified
			name:  "fix availability only change",
			oldDB: []string{"echo-rolling/CVE-2025-13012", "cve-2025-21916"},
			newDB: []string{"echo-rolling/CVE-2025-13012", "cve-2025-21916"},
			mutateNew: []string{
				`UPDATE blobs SET value = replace(value, '"first-observed"', '"advisory"')
				 WHERE id IN (SELECT blob_id FROM affected_package_handles) AND value LIKE '%"first-observed"%'`,
				`UPDATE blobs SET value = replace(value, '"first-observed"', '"advisory"')
				 WHERE id IN (SELECT blob_id FROM affected_cpe_handles) AND value LIKE '%"first-observed"%'`,
			},
		},
		{
			// a vulnerable record is removed when the other side has a matching not-vulnerable record, even if it also
			// has a matching vulnerable record
			name:      "mixed statuses for the same package",
			oldDB:     []string{"cve-2025-59800"},
			newDB:     []string{"cve-2025-59800"},
			mutateNew: []string{copyHandles("affected_package_handles", "unaffected_package_handles")},
			expected: []PackageDiff{
				{Ecosystem: "deb", Name: "ghostscript", Vulnerabilities: VulnerabilityChanges{Removed: []VulnerabilityID{{Provider: "echo", ID: "CVE-2025-59800"}}}},
			},
		},
		{
			// cpes that only differ by '' vs '*' render to the same CPE string, so must be reported once
			name:  "cpes with the same cpe string",
			oldDB: []string{"cve-2025-24456"},
			newDB: []string{"cve-2025-24456", "cve-2025-21916"},
			mutateNew: []string{
				`INSERT INTO cpes (part, vendor, product, edition, language, software_edition, target_hardware, target_software, other)
				 SELECT part, vendor, product, '*', language, software_edition, target_hardware, target_software, other
				 FROM cpes WHERE product = 'linux_kernel'`,
				`INSERT INTO affected_cpe_handles (vulnerability_id, cpe_id, blob_id)
				 SELECT h.vulnerability_id, (SELECT id FROM cpes WHERE product = 'linux_kernel' AND edition = '*'), h.blob_id
				 FROM affected_cpe_handles h JOIN cpes c ON c.id = h.cpe_id
				 WHERE c.product = 'linux_kernel' AND c.edition = ''`,
			},
			expected: []PackageDiff{
				{
					Ecosystem:       "cpe",
					Name:            "linux_kernel",
					CPE:             "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
					Vulnerabilities: VulnerabilityChanges{Added: []VulnerabilityID{{Provider: "nvd", ID: "CVE-2025-21916"}}},
				},
			},
		},
	}

	inputDir, err := filepath.Abs(filepath.Join("testdata", "inputs"))
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldDB := filepath.Join(t.TempDir(), "oldDB")
			testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 11, 18, 1, 5, 0, time.UTC), oldDB, inputDir, tt.oldDB...)
			execSQL(t, oldDB, tt.mutateOld...)

			newDB := filepath.Join(t.TempDir(), "newDB")
			testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 12, 1, 55, 19, 0, time.UTC), newDB, inputDir, tt.newDB...)
			execSQL(t, newDB, tt.mutateNew...)

			differ, err := NewDBDiffer(Config{Config: installation.Config{}, OldDB: oldDB, NewDB: newDB})
			require.NoError(t, err)
			t.Cleanup(func() { _ = differ.Close() })

			result, err := differ.Diff()
			require.NoError(t, err)
			require.Equal(t, tt.expected, nilIfEmpty(result.Packages))
		})
	}
}

// execSQL runs each statement against the database in dbDir, requiring that each one changes at least one row (so a
// mutation can't silently become a no-op if the fixtures change)
func execSQL(t *testing.T, dbDir string, statements ...string) {
	t.Helper()
	if len(statements) == 0 {
		return
	}
	db, err := v6.NewLowLevelDB(filepath.Join(dbDir, v6.VulnerabilityDBFileName), false, true, false)
	require.NoError(t, err)
	defer closeLowLevelDB(db)
	require.NoError(t, db.Exec("PRAGMA foreign_keys = OFF").Error)
	for _, stmt := range statements {
		res := db.Exec(stmt)
		require.NoError(t, res.Error, stmt)
		require.NotZero(t, res.RowsAffected, "statement changed no rows: %s", stmt)
	}
}

// copyHandles returns a statement that copies every handle in the from table into the to table
func copyHandles(from, to string) string {
	return `INSERT INTO ` + to + ` (vulnerability_id, operating_system_id, package_id, blob_id)
		SELECT vulnerability_id, operating_system_id, package_id, blob_id FROM ` + from
}

func nilIfEmpty[T any](s []T) []T {
	if len(s) == 0 {
		return nil
	}
	return s
}

// Test_ResolvedDB_cleanupNeverPanics verifies Cleanup is safe for local databases and for the zero value returned
// alongside an error, since NewDBDiffer calls it whenever setup fails
func Test_ResolvedDB_cleanupNeverPanics(t *testing.T) {
	require.NotPanics(t, ResolvedDB{}.Cleanup)

	inputDir, err := filepath.Abs(filepath.Join("testdata", "inputs"))
	require.NoError(t, err)

	dbDir := filepath.Join(t.TempDir(), "db")
	testdb.BuildFromFlatFileDir(t, time.Time{}, dbDir, inputDir, "cve-2025-59800")

	for _, value := range []string{dbDir, filepath.Join(dbDir, v6.VulnerabilityDBFileName)} {
		resolved, err := ResolveDB(value, "")
		require.NoError(t, err)
		require.NotPanics(t, resolved.Cleanup, value)
	}
}

// Test_ResolveDB_keepsUserDataOnFailure verifies a failed resolve only removes directories it created itself
func Test_ResolveDB_keepsUserDataOnFailure(t *testing.T) {
	const keep = "keep.txt"

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string) (value, defaultDir string)
		kept  string
		gone  string
	}{
		{
			name: "directory without a db",
			setup: func(_ *testing.T, dir string) (string, string) {
				return dir, ""
			},
			kept: keep,
		},
		{
			name: "default directory without a db",
			setup: func(_ *testing.T, dir string) (string, string) {
				return "", dir
			},
			kept: keep,
		},
		{
			name: "db file in a user directory",
			setup: func(t *testing.T, dir string) (string, string) {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "other.db"), []byte("not a db"), 0o600))
				return filepath.Join(dir, "other.db"), ""
			},
			kept: keep,
		},
		{
			name: "corrupt archive next to an existing directory",
			setup: func(t *testing.T, dir string) (string, string) {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "db.tar.gz"), []byte("not an archive"), 0o600))
				require.NoError(t, os.Mkdir(filepath.Join(dir, "db"), 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "db", keep), []byte("x"), 0o600))
				return filepath.Join(dir, "db.tar.gz"), ""
			},
			kept: filepath.Join("db", keep),
		},
		{
			name: "corrupt archive extraction is cleaned up",
			setup: func(t *testing.T, dir string) (string, string) {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "db.tar.gz"), []byte("not an archive"), 0o600))
				return filepath.Join(dir, "db.tar.gz"), ""
			},
			kept: keep,
			gone: "db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, keep), []byte("x"), 0o600))

			_, err := ResolveDB(tt.setup(t, dir))
			require.Error(t, err)

			assert.FileExists(t, filepath.Join(dir, tt.kept))
			if tt.gone != "" {
				assert.NoDirExists(t, filepath.Join(dir, tt.gone))
			}
			requireNoExtractLeftovers(t, dir)
		})
	}
}

// Test_ResolveDB_archiveExtraction verifies an archive is only ever extracted into place once it is complete and
// loads, so a failed or interrupted run never leaves a directory that breaks the next one
func Test_ResolveDB_archiveExtraction(t *testing.T) {
	inputDir, err := filepath.Abs(filepath.Join("testdata", "inputs"))
	require.NoError(t, err)

	srcDir := filepath.Join(t.TempDir(), "src")
	testdb.BuildFromFlatFileDir(t, time.Time{}, srcDir, inputDir, "cve-2025-59800")
	goodDB, err := os.ReadFile(filepath.Join(srcDir, v6.VulnerabilityDBFileName))
	require.NoError(t, err)
	badDB := []byte("not a db")

	t.Run("extracts once and reuses", func(t *testing.T) {
		dir := t.TempDir()
		archive := writeDBArchive(t, dir, goodDB)

		for range 2 {
			resolved, err := ResolveDB(archive, "")
			require.NoError(t, err)
			assert.Equal(t, filepath.Join(dir, "db"), resolved.Dir)
			assert.NotEmpty(t, resolved.Info.BuildTimestamp)
			assert.FileExists(t, filepath.Join(resolved.Dir, v6.VulnerabilityDBFileName))
			requireNoExtractLeftovers(t, dir)
		}
	})

	t.Run("an archive that fails to load leaves nothing behind", func(t *testing.T) {
		dir := t.TempDir()
		archive := writeDBArchive(t, dir, badDB)

		_, err := ResolveDB(archive, "")
		require.Error(t, err)
		assert.NoDirExists(t, filepath.Join(dir, "db"))
		requireNoExtractLeftovers(t, dir)

		// replacing the archive is enough to recover, there is nothing stale to remove by hand
		writeDBArchive(t, dir, goodDB)
		_, err = ResolveDB(archive, "")
		require.NoError(t, err)
	})

	t.Run("an unusable previous extraction is named in the error", func(t *testing.T) {
		dir := t.TempDir()
		archive := writeDBArchive(t, dir, goodDB)
		require.NoError(t, os.Mkdir(filepath.Join(dir, "db"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "db", v6.VulnerabilityDBFileName), badDB, 0o600))

		_, err := ResolveDB(archive, "")
		require.ErrorContains(t, err, filepath.Join(dir, "db"))
	})
}

// writeDBArchive writes a db.tar.gz into dir holding the given vulnerability.db content, and returns its path
func writeDBArchive(t *testing.T, dir string, dbContent []byte) string {
	t.Helper()
	path := filepath.Join(dir, "db.tar.gz")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: v6.VulnerabilityDBFileName, Mode: 0o600, Size: int64(len(dbContent))}))
	_, err = tw.Write(dbContent)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return path
}

func requireNoExtractLeftovers(t *testing.T, dir string) {
	t.Helper()
	leftovers, err := filepath.Glob(filepath.Join(dir, "*-extract-*"))
	require.NoError(t, err)
	require.Empty(t, leftovers, "temporary extraction directories left behind")
}

// Test_NewDBDiffer_defaultsToInstalledDB verifies a single db argument is diffed against the installed db, which
// lives in a schema versioned directory under the db root
func Test_NewDBDiffer_defaultsToInstalledDB(t *testing.T) {
	inputDir, err := filepath.Abs(filepath.Join("testdata", "inputs"))
	require.NoError(t, err)

	cfg := installation.Config{DBRootDir: t.TempDir()}
	testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 12, 0, 0, 0, 0, time.UTC), cfg.DBDirectoryPath(), inputDir, "cve-2025-59800")
	oldDir := filepath.Join(t.TempDir(), "old")
	testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 11, 0, 0, 0, 0, time.UTC), oldDir, inputDir, "cve-2025-59800")

	differ, err := NewDBDiffer(Config{Config: cfg, OldDB: oldDir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = differ.Close() })
	assert.Equal(t, cfg.DBDirectoryPath(), differ.newDB.Dir)
}

// Test_DBDiffer_removesDownloads verifies downloaded databases are removed when the other side fails to resolve,
// and on Close otherwise
func Test_DBDiffer_removesDownloads(t *testing.T) {
	inputDir, err := filepath.Abs(filepath.Join("testdata", "inputs"))
	require.NoError(t, err)

	// separate dbs, since the local one is hydrated in place while the served one is being downloaded
	servedDir := filepath.Join(t.TempDir(), "served")
	testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 11, 0, 0, 0, 0, time.UTC), servedDir, inputDir, "cve-2025-59800")
	localDir := filepath.Join(t.TempDir(), "local")
	testdb.BuildFromFlatFileDir(t, time.Date(2022, 8, 12, 0, 0, 0, 0, time.UTC), localDir, inputDir, "cve-2025-59800")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(servedDir, v6.VulnerabilityDBFileName))
	}))
	t.Cleanup(srv.Close)

	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	downloads := func() []string {
		matches, err := filepath.Glob(filepath.Join(tmp, "grype-db-diff-*"))
		require.NoError(t, err)
		return matches
	}

	_, err = NewDBDiffer(Config{OldDB: srv.URL, NewDB: filepath.Join(t.TempDir(), "missing")})
	require.Error(t, err)
	assert.Empty(t, downloads(), "download kept after the other side failed")

	differ, err := NewDBDiffer(Config{OldDB: srv.URL, NewDB: localDir})
	require.NoError(t, err)
	require.Len(t, downloads(), 1)
	require.NoError(t, differ.Close())
	assert.Empty(t, downloads(), "download kept after Close")
}

func requireVulns(t *testing.T, testType string, vulns []VulnerabilityID, vulnNames ...string) {
	t.Helper()
	if len(vulns) != len(vulnNames) {
		t.Errorf("expected %d %s vulnerabilities %v, got %d: %v", len(vulnNames), testType, vulnNames, len(vulns), vulns)
	}
nextVuln:
	for _, required := range vulnNames {
		for _, vuln := range vulns {
			if strings.EqualFold(vuln.ID, required) {
				continue nextVuln
			}
		}
		t.Errorf("expected %s vulnerability %q not found", testType, required)
	}
}

// requireExactVulnIDs requires that vulns holds exactly the expected entries, with no duplicates
func requireExactVulnIDs(t *testing.T, testType string, vulns []VulnerabilityID, expected ...VulnerabilityID) {
	t.Helper()
	if len(vulns) != len(expected) {
		t.Errorf("expected %d %s vulnerabilities %v, got %d: %v", len(expected), testType, expected, len(vulns), vulns)
	}
	requireVulnIDs(t, testType, vulns, expected...)
}

func requireVulnIDs(t *testing.T, testType string, vulns []VulnerabilityID, expected ...VulnerabilityID) {
	t.Helper()
nextVuln:
	for _, exp := range expected {
		for _, vuln := range vulns {
			if strings.EqualFold(vuln.ID, exp.ID) && strings.EqualFold(vuln.Provider, exp.Provider) {
				continue nextVuln
			}
		}
		t.Errorf("expected %s vulnerability {Provider: %q, ID: %q} not found in %v", testType, exp.Provider, exp.ID, vulns)
	}
}

func findPackageDiff(diff *Result, packageName string) []PackageDiff {
	var out []PackageDiff
	for _, p := range diff.Packages {
		if strings.EqualFold(p.Name, packageName) {
			out = append(out, p)
		}
	}
	return out
}

func findExactPackageDiff(diff *Result, ecosystem, name string) *PackageDiff {
	for _, p := range diff.Packages {
		if strings.EqualFold(p.Ecosystem, ecosystem) && strings.EqualFold(p.Name, name) {
			return &p
		}
	}
	return nil
}
