package commands

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	"github.com/anchore/grype/cmd/grype/cli/options"
	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestDBSearchMatchOptionsApplyArgs(t *testing.T) {
	testCases := []struct {
		name               string
		args               []string
		expectedPackages   []string
		expectedVulnIDs    []string
		expectedErrMessage string
	}{
		{
			name:             "empty arguments",
			args:             []string{},
			expectedPackages: []string{},
			expectedVulnIDs:  []string{},
		},
		{
			name: "valid cpe",
			args: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
			expectedPackages: []string{
				"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			},
			expectedVulnIDs: []string{},
		},
		{
			name: "valid purl",
			args: []string{"pkg:npm/package-name@1.0.0"},
			expectedPackages: []string{
				"pkg:npm/package-name@1.0.0",
			},
			expectedVulnIDs: []string{},
		},
		{
			name:             "valid vulnerability IDs",
			args:             []string{"CVE-2023-0001", "GHSA-1234", "ALAS-2023-1234"},
			expectedPackages: []string{},
			expectedVulnIDs: []string{
				"CVE-2023-0001",
				"GHSA-1234",
				"ALAS-2023-1234",
			},
		},
		{
			name: "mixed package and vulns",
			args: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "CVE-2023-0001"},
			expectedPackages: []string{
				"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			},
			expectedVulnIDs: []string{
				"CVE-2023-0001",
			},
		},
		{
			name: "plain package name",
			args: []string{"package-name"},
			expectedPackages: []string{
				"package-name",
			},
			expectedVulnIDs: []string{},
		},
		{
			name: "invalid PostLoad error for Package",
			args: []string{"pkg:npm/package-name@1.0.0", "cpe:invalid"},
			expectedPackages: []string{
				"pkg:npm/package-name@1.0.0",
			},
			expectedErrMessage: "invalid CPE",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &dbSearchMatchOptions{
				Vulnerability: options.DBSearchVulnerabilities{},
				Package:       options.DBSearchPackages{},
			}

			err := opts.applyArgs(tc.args)

			if tc.expectedErrMessage != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErrMessage)
				return
			}

			require.NoError(t, err)
			if d := cmp.Diff(tc.expectedPackages, opts.Package.Packages, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("unexpected package specifiers: %s", d)
			}
			if d := cmp.Diff(tc.expectedVulnIDs, opts.Vulnerability.VulnerabilityIDs, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("unexpected vulnerability specifiers: %s", d)
			}
		})
	}
}

func TestMimicV5Namespace(t *testing.T) {
	tests := []struct {
		name      string
		osName    string
		osChannel string
		expected  string
	}{
		{
			name:      "distro namespace without channel",
			osName:    "redhat",
			osChannel: "",
			expected:  "redhat:distro:redhat:8",
		},
		{
			name:      "distro namespace with channel",
			osName:    "redhat",
			osChannel: "eus",
			expected:  "redhat:distro:redhat:8:eus",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Model: v6.VulnerabilityHandle{
						Provider: &v6.Provider{ID: "rhel"},
					},
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					Model: &v6.AffectedPackageHandle{
						OperatingSystem: &v6.OperatingSystem{
							Name:         tt.osName,
							MajorVersion: "8",
							MinorVersion: "6",
							Channel:      tt.osChannel,
						},
						Package: &v6.Package{
							Name:      "test-package",
							Ecosystem: "rpm",
						},
					},
				},
			}

			result := mimicV5Namespace(row)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestRenderDBSearchPackagesTableRows(t *testing.T) {
	vuln := func(id string) dbsearch.VulnerabilityInfo {
		return dbsearch.VulnerabilityInfo{
			Model:             v6.VulnerabilityHandle{Name: id, Provider: &v6.Provider{ID: "debian"}},
			VulnerabilityBlob: v6.VulnerabilityBlob{ID: id},
		}
	}
	pkg := func(name, osVersion string, constraints ...string) dbsearch.AffectedPackageInfo {
		var ranges []v6.Range
		for _, c := range constraints {
			ranges = append(ranges, v6.Range{Version: v6.Version{Constraint: c}})
		}
		return dbsearch.AffectedPackageInfo{
			Model: &v6.AffectedPackageHandle{
				OperatingSystem: &v6.OperatingSystem{Name: "debian", MajorVersion: osVersion},
				Package:         &v6.Package{Name: name, Ecosystem: "deb"},
			},
			Package: &dbsearch.Package{Name: name, Ecosystem: "deb"},
			Detail:  v6.PackageBlob{Ranges: ranges},
		}
	}
	pkgs := func(p ...dbsearch.AffectedPackageInfo) []dbsearch.AffectedPackageInfo {
		return p
	}

	tests := []struct {
		name     string
		input    dbsearch.Matches
		expected [][]string
	}{
		{
			name: "affected only",
			input: dbsearch.Matches{
				{Vulnerability: vuln("CVE-2024-0001"), AffectedPackages: pkgs(pkg("jinja2", "12", "< 3.1.2-1+deb12u2"))},
			},
			expected: [][]string{
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:12", "< 3.1.2-1+deb12u2"},
			},
		},
		{
			name: "unaffected constraints are listed after affected constraints on the same row",
			input: dbsearch.Matches{
				{
					Vulnerability:    vuln("CVE-2024-0001"),
					AffectedPackages: pkgs(pkg("jinja2", "12", "< 3.1.2-1+deb12u2")),
					Unaffected:       pkgs(pkg("jinja2", "12", "= 3.1.2-1+deb12u1+patched"), pkg("jinja2", "12", "= 3.1.1-1+patched")),
				},
			},
			expected: [][]string{
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:12", "< 3.1.2-1+deb12u2; unaffected: = 3.1.1-1+patched || = 3.1.2-1+deb12u1+patched"},
			},
		},
		{
			name: "unaffected records without constraints",
			input: dbsearch.Matches{
				{
					Vulnerability:    vuln("CVE-2024-0001"),
					AffectedPackages: pkgs(),
					Unaffected:       pkgs(pkg("jinja2", "11"), pkg("jinja2", "11")),
				},
			},
			expected: [][]string{
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:11", "unaffected: *"},
			},
		},
		{
			name: "affected records without constraints are displayed as any version",
			input: dbsearch.Matches{
				{
					Vulnerability:    vuln("CVE-2024-0001"),
					AffectedPackages: pkgs(pkg("redis", "9"), pkg("redis", "9", "")),
					Unaffected:       pkgs(pkg("redis", "9")),
				},
				{Vulnerability: vuln("CVE-2024-0002"), AffectedPackages: pkgs(pkg("redis", "9"))},
				{Vulnerability: vuln("CVE-2024-0003"), AffectedPackages: pkgs(pkg("redis", "9"), pkg("redis", "9", "< 7.2.4-1"))},
			},
			expected: [][]string{
				{"CVE-2024-0001", "redis", "deb", "debian:distro:debian:9", "*; unaffected: *"},
				{"CVE-2024-0002", "redis", "deb", "debian:distro:debian:9", "*"},
				{"CVE-2024-0003", "redis", "deb", "debian:distro:debian:9", "*"},
				{"CVE-2024-0003", "redis", "deb", "debian:distro:debian:9", "< 7.2.4-1"},
			},
		},
		{
			name: "unaffected records with and without constraints",
			input: dbsearch.Matches{
				{
					Vulnerability:    vuln("CVE-2024-0001"),
					AffectedPackages: pkgs(),
					Unaffected:       pkgs(pkg("jinja2", "12"), pkg("jinja2", "12", "= 3.1.2-1")),
				},
			},
			expected: [][]string{
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:12", "unaffected: * || = 3.1.2-1"},
			},
		},
		{
			name: "affected records with different constraints are separate rows, identical ones are listed once",
			input: dbsearch.Matches{
				{
					Vulnerability:    vuln("CVE-2024-0001"),
					AffectedPackages: pkgs(pkg("jinja2", "12", "< 3.1.5-1"), pkg("jinja2", "12", "< 3.1.2-1+deb12u2", "< 3.1.5-1"), pkg("jinja2", "12", "< 3.1.5-1")),
				},
			},
			expected: [][]string{
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:12", "< 3.1.2-1+deb12u2 || < 3.1.5-1"},
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:12", "< 3.1.5-1"},
			},
		},
		{
			// e.g. records for different RHEL minor releases share a namespace
			name: "unaffected constraints are on their own row when there are several affected rows",
			input: dbsearch.Matches{
				{
					Vulnerability:    vuln("CVE-2024-0001"),
					AffectedPackages: pkgs(pkg("jinja2", "12", "< 3.1.5-1"), pkg("jinja2", "12", "< 3.1.6-1")),
					Unaffected:       pkgs(pkg("jinja2", "12", "= 3.1.4-1+patched")),
				},
			},
			expected: [][]string{
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:12", "< 3.1.5-1"},
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:12", "< 3.1.6-1"},
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:12", "unaffected: = 3.1.4-1+patched"},
			},
		},
		{
			name: "records for different namespaces, packages, and vulnerabilities are separate rows",
			input: dbsearch.Matches{
				{Vulnerability: vuln("CVE-2024-0002"), AffectedPackages: pkgs(pkg("jinja2", "12", "< 3.1.5-1"))},
				{
					Vulnerability:    vuln("CVE-2024-0001"),
					AffectedPackages: pkgs(pkg("jinja2", "12", "< 3.1.2-1+deb12u2")),
					Unaffected:       pkgs(pkg("jinja2", "11"), pkg("python-jinja2", "12", "= 3.1.2-1")),
				},
			},
			expected: [][]string{
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:11", "unaffected: *"},
				{"CVE-2024-0001", "jinja2", "deb", "debian:distro:debian:12", "< 3.1.2-1+deb12u2"},
				{"CVE-2024-0001", "python-jinja2", "deb", "debian:distro:debian:12", "unaffected: = 3.1.2-1"},
				{"CVE-2024-0002", "jinja2", "deb", "debian:distro:debian:12", "< 3.1.5-1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, renderDBSearchPackagesTableRows(tt.input))
		})
	}
}

func TestDBSearchMatchOptions_IncludeAliases(t *testing.T) {
	t.Run("vulnerability IDs given as args satisfy --include-aliases", func(t *testing.T) {
		opts := &dbSearchMatchOptions{Vulnerability: options.DBSearchVulnerabilities{IncludeAliases: true}}
		require.NoError(t, opts.applyArgs([]string{"CVE-2024-1234"}))
		require.Equal(t, []string{"CVE-2024-1234"}, opts.Vulnerability.VulnerabilityIDs)
	})

	t.Run("--include-aliases without vulnerability IDs is rejected before opening the DB", func(t *testing.T) {
		opts := dbSearchMatchOptions{Vulnerability: options.DBSearchVulnerabilities{IncludeAliases: true}}
		require.ErrorContains(t, runDBSearchMatches(opts), "--include-aliases requires at least one vulnerability ID")
	})
}
