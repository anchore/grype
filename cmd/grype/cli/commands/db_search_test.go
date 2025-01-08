package commands

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	"github.com/anchore/grype/cmd/grype/cli/options"
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

func TestV5Namespace(t *testing.T) {
	tests := []struct {
		name     string
		input    dbsearch.AffectedPackage
		expected string
	}{
		{
			name: "nvd provider",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "nvd",
				},
			},
			expected: "nvd:cpe",
		},
		{
			name: "github javascript direct",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "github",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					Package: &dbsearch.Package{
						Ecosystem: "javascript",
					},
				},
			},
			expected: "github:language:javascript",
		},
		{
			name: "github npm ecosystem",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "github",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					Package: &dbsearch.Package{
						Ecosystem: "npm",
					},
				},
			},
			expected: "github:language:javascript",
		},
		{
			name: "github node ecosystem",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "github",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					Package: &dbsearch.Package{
						Ecosystem: "node",
					},
				},
			},
			expected: "github:language:javascript",
		},
		{
			name: "github golang variations",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "github",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					Package: &dbsearch.Package{
						Ecosystem: "go-module",
					},
				},
			},
			expected: "github:language:go",
		},
		{
			name: "github composer to php",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "github",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					Package: &dbsearch.Package{
						Ecosystem: "composer",
					},
				},
			},
			expected: "github:language:php",
		},
		{
			name: "ubuntu distribution",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "ubuntu",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					OS: &dbsearch.OperatingSystem{
						Name:    "ubuntu",
						Version: "22.04",
					},
				},
			},
			expected: "ubuntu:distro:ubuntu:22.04",
		},
		{
			name: "amazon linux distribution",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "amazon",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					OS: &dbsearch.OperatingSystem{
						Name:    "amazon",
						Version: "2023",
					},
				},
			},
			expected: "amazon:distro:amazonlinux:2023",
		},
		{
			name: "mariner to azurelinux conversion",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "mariner",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					OS: &dbsearch.OperatingSystem{
						Name:    "mariner",
						Version: "3.0",
					},
				},
			},
			expected: "mariner:distro:azurelinux:3.0",
		},
		{
			name: "mariner regular version",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "mariner",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					OS: &dbsearch.OperatingSystem{
						Name:    "mariner",
						Version: "2.0",
					},
				},
			},
			expected: "mariner:distro:mariner:2.0",
		},
		{
			name: "oracle linux distribution",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "oracle",
				},
				AffectedPackageInfo: dbsearch.AffectedPackageInfo{
					OS: &dbsearch.OperatingSystem{
						Name:    "oracle",
						Version: "8",
					},
				},
			},
			expected: "oracle:distro:oraclelinux:8",
		},
		{
			name: "provider only fallback",
			input: dbsearch.AffectedPackage{
				Vulnerability: dbsearch.VulnerabilityInfo{
					Provider: "custom",
				},
			},
			expected: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v5Namespace(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
