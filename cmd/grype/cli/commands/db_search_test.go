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
