package diff

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
						requireVulnIDs(t, "added", vulnChanges.Added, expected...)
					case modified:
						hasModified = true
						requireVulnIDs(t, "modified", vulnChanges.Modified, expected...)
					case removed:
						hasRemoved = true
						requireVulnIDs(t, "removed", vulnChanges.Removed, expected...)
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

func requireVulns(t *testing.T, testType string, vulns []VulnerabilityID, vulnNames ...string) {
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
