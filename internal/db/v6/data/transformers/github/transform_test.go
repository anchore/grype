package github

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data/provider"
	"github.com/anchore/grype/internal/db/data/unmarshal"
	v6 "github.com/anchore/grype/internal/db/v6"
	"github.com/anchore/grype/internal/db/v6/data/transformers"
	"github.com/anchore/grype/internal/db/v6/data/transformers/internal"
	"github.com/anchore/syft/syft/pkg"
)

func TestTransform(t *testing.T) {
	type counts struct {
		providerCount        int
		vulnerabilityCount   int
		affectedPackageCount int
	}

	tests := []struct {
		name       string
		fixture    string
		state      provider.State
		wantCounts counts
	}{
		{
			name:    "multiple fixed versions for Plone",
			fixture: "test-fixtures/multiple-fixed-in-names.json",
			state: provider.State{
				Provider:  "github",
				Version:   1,
				Timestamp: time.Date(2024, 03, 01, 12, 0, 0, 0, time.UTC),
			},
			wantCounts: counts{
				providerCount:        1,
				vulnerabilityCount:   1,
				affectedPackageCount: 3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisories := loadFixture(t, tt.fixture)
			require.Len(t, advisories, 1, "expected exactly one advisory")
			advisory := advisories[0]

			entries, err := Transform(advisory, tt.state)
			require.NoError(t, err)
			require.Len(t, entries, 1, "expected exactly one data.Entry")

			entry := entries[0]
			require.NotNil(t, entry.Data)

			data, ok := entry.Data.(transformers.RelatedEntries)
			require.True(t, ok, "expected entry.Data to be of type RelatedEntries")

			require.NotNil(t, data.VulnerabilityHandle, "expected a VulnerabilityHandle")
			require.Equal(t, tt.wantCounts.vulnerabilityCount, 1)

			require.Len(t, data.Related, tt.wantCounts.affectedPackageCount, "unexpected number of related entries")
		})
	}
}

func TestGetVulnerability(t *testing.T) {
	now := time.Date(2024, 03, 01, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		expected []v6.VulnerabilityHandle
	}{
		{
			name: "test-fixtures/GHSA-2wgc-48g2-cj5w.json",
			expected: []v6.VulnerabilityHandle{
				{
					Name:       "GHSA-2wgc-48g2-cj5w",
					ProviderID: "github",
					Provider: &v6.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2024-02-08T22:48:31Z"),
					PublishedDate: internal.ParseTime("2024-01-30T20:56:46Z"),
					WithdrawnDate: nil,
					Status:        v6.VulnerabilityActive,
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "GHSA-2wgc-48g2-cj5w",
						Description: "vantage6 has insecure SSH configuration for node and server containers",
						References: []v6.Reference{
							{
								URL: "https://github.com/advisories/GHSA-2wgc-48g2-cj5w",
							},
						},
						Aliases: []string{"CVE-2024-21653"},
						Severities: []v6.Severity{
							{
								Scheme: v6.SeveritySchemeCHML,
								Value:  "medium",
							},
							{
								Scheme: v6.SeveritySchemeCVSS,
								Value: v6.CVSSSeverity{
									Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
									Version: "3.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/GHSA-3x74-v64j-qc3f.json",
			expected: []v6.VulnerabilityHandle{
				{
					Name:       "GHSA-3x74-v64j-qc3f",
					ProviderID: "github",
					Provider: &v6.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2024-03-21T17:48:19Z"),
					PublishedDate: internal.ParseTime("2023-06-13T18:30:39Z"),
					WithdrawnDate: internal.ParseTime("2023-06-28T23:54:39Z"),
					Status:        v6.VulnerabilityRejected,
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "GHSA-3x74-v64j-qc3f",
						Description: "Withdrawn Advisory: CraftCMS Server-Side Template Injection vulnerability",
						References: []v6.Reference{
							{
								URL: "https://github.com/advisories/GHSA-3x74-v64j-qc3f",
							},
						},
						Aliases: []string{"CVE-2023-30179"},
						Severities: []v6.Severity{
							{
								Scheme: v6.SeveritySchemeCHML,
								Value:  "high",
							},
							{
								Scheme: v6.SeveritySchemeCVSS,
								Value: v6.CVSSSeverity{
									Vector:  "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
									Version: "3.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-npm-0.json",
			expected: []v6.VulnerabilityHandle{
				{
					Name:       "GHSA-vc9j-fhvv-8vrf",
					ProviderID: "github",
					Provider: &v6.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2023-01-09T05:03:39Z"),
					PublishedDate: internal.ParseTime("2020-07-27T19:55:52Z"),
					WithdrawnDate: nil,
					Status:        v6.VulnerabilityActive,
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "GHSA-vc9j-fhvv-8vrf",
						Description: "Remote Code Execution in scratch-vm",
						References: []v6.Reference{
							{
								URL: "https://github.com/advisories/GHSA-vc9j-fhvv-8vrf",
							},
						},
						Aliases: []string{"CVE-2020-14000"},
						Severities: []v6.Severity{
							{
								Scheme: v6.SeveritySchemeCHML,
								Value:  "critical",
							},
							{
								Scheme: v6.SeveritySchemeCVSS,
								Value: v6.CVSSSeverity{
									Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									Version: "3.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-python-0.json",
			expected: []v6.VulnerabilityHandle{
				{
					Name:       "GHSA-6cwv-x26c-w2q4",
					ProviderID: "github",
					Provider: &v6.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					Status: "active",
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "GHSA-6cwv-x26c-w2q4",
						Description: "Low severity vulnerability that affects notebook",
						References: []v6.Reference{
							{
								URL: "https://github.com/advisories/GHSA-6cwv-x26c-w2q4",
							},
						},

						Aliases: []string{"CVE-2018-8768"},

						Severities: []v6.Severity{
							{
								Scheme: v6.SeveritySchemeCHML,
								Value:  "low",
							},
						},
					},
				},
				{
					Name:       "GHSA-p5wr-vp8g-q5p4",
					ProviderID: "github",
					Provider: &v6.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					Status: "active",
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "GHSA-p5wr-vp8g-q5p4",
						Description: "Moderate severity vulnerability that affects Plone",
						References: []v6.Reference{
							{
								URL: "https://github.com/advisories/GHSA-p5wr-vp8g-q5p4",
							},
						},
						Aliases: []string{"CVE-2017-5524"},
						Severities: []v6.Severity{
							{
								Scheme: v6.SeveritySchemeCHML,
								Value:  "medium",
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-withdrawn.json",
			expected: []v6.VulnerabilityHandle{
				{
					Name:       "GHSA-6cwv-x26c-w2q4",
					ProviderID: "github",
					Provider: &v6.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  nil,
					PublishedDate: nil,
					WithdrawnDate: internal.ParseTime("2022-01-31T14:32:09Z"),
					Status:        v6.VulnerabilityRejected,
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "GHSA-6cwv-x26c-w2q4",
						Description: "Low severity vulnerability that affects notebook",
						References: []v6.Reference{
							{
								URL: "https://github.com/advisories/GHSA-6cwv-x26c-w2q4",
							},
						},
						Aliases: []string{"CVE-2018-8768"},
						Severities: []v6.Severity{
							{
								Scheme: v6.SeveritySchemeCHML,
								Value:  "low",
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/multiple-fixed-in-names.json",
			expected: []v6.VulnerabilityHandle{
				{
					Name:       "GHSA-p5wr-vp8g-q5p4",
					ProviderID: "github",
					Provider: &v6.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					Status: v6.VulnerabilityActive,
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "GHSA-p5wr-vp8g-q5p4",
						Description: "Moderate severity vulnerability that affects Plone",
						References: []v6.Reference{
							{
								URL: "https://github.com/advisories/GHSA-p5wr-vp8g-q5p4",
							},
						},
						Aliases: []string{"CVE-2017-5524"},
						Severities: []v6.Severity{
							{
								Scheme: v6.SeveritySchemeCHML,
								Value:  "medium",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisories := loadFixture(t, tt.name)
			var results []v6.VulnerabilityHandle

			for _, advisory := range advisories {
				result := getVulnerability(advisory, provider.State{Provider: "github", Version: 1, Timestamp: now})
				results = append(results, result)
			}
			if d := cmp.Diff(tt.expected, results); d != "" {
				t.Fatalf("unexpected result: %s", d)
			}
		})
	}
}

func TestGetAffectedPackage(t *testing.T) {
	tests := []struct {
		name     string
		expected []v6.AffectedPackageHandle
	}{
		{
			name: "test-fixtures/GHSA-2wgc-48g2-cj5w.json",
			expected: []v6.AffectedPackageHandle{
				{
					Package: &v6.Package{
						Name:      "vantage6",
						Ecosystem: "python",
					},
					BlobValue: &v6.AffectedPackageBlob{
						CVEs: []string{"CVE-2024-21653"},
						Ranges: []v6.AffectedRange{
							{
								Version: v6.AffectedVersion{
									Type:       "python",
									Constraint: "<4.2.0",
								},
								Fix: &v6.Fix{
									Version: "4.2.0",
									State:   v6.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/GHSA-3x74-v64j-qc3f.json",
			expected: []v6.AffectedPackageHandle{
				{
					Package: &v6.Package{
						Name:      "craftcms/cms",
						Ecosystem: "packagist",
					},
					BlobValue: &v6.AffectedPackageBlob{
						CVEs: []string{"CVE-2023-30179"},
						Ranges: []v6.AffectedRange{
							{
								Version: v6.AffectedVersion{
									Type:       "packagist",
									Constraint: "<4.4.2",
								},
								Fix: &v6.Fix{
									Version: "4.4.2",
									State:   v6.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-npm-0.json",
			expected: []v6.AffectedPackageHandle{
				{
					Package: &v6.Package{
						Name:      "scratch-vm",
						Ecosystem: "npm",
					},
					BlobValue: &v6.AffectedPackageBlob{
						CVEs: []string{"CVE-2020-14000"},
						Ranges: []v6.AffectedRange{
							{
								Version: v6.AffectedVersion{
									Type:       "npm",
									Constraint: "<=0.2.0-prerelease.20200709173451",
								},
								Fix: &v6.Fix{
									Version: "0.2.0-prerelease.20200714185213",
									State:   v6.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-python-0.json",
			expected: []v6.AffectedPackageHandle{
				{
					Package: &v6.Package{
						Ecosystem: "python",
						Name:      "notebook",
					},
					BlobValue: &v6.AffectedPackageBlob{
						CVEs:       []string{"CVE-2018-8768"},
						Qualifiers: nil,
						Ranges: []v6.AffectedRange{
							{
								Version: v6.AffectedVersion{Type: "python", Constraint: "<5.4.1"},
								Fix:     &v6.Fix{Version: "5.4.1", State: v6.FixedStatus},
							},
						},
					},
				},
				{
					Package: &v6.Package{
						Ecosystem: "python",
						Name:      "Plone",
					},
					BlobValue: &v6.AffectedPackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []v6.AffectedRange{
							{
								Version: v6.AffectedVersion{Type: "python", Constraint: ">=4.0,<4.3.12"},
								Fix:     &v6.Fix{Version: "4.3.12", State: v6.FixedStatus},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/multiple-fixed-in-names.json",
			expected: []v6.AffectedPackageHandle{
				{
					Package: &v6.Package{
						Name:      "Plone",
						Ecosystem: "python",
					},
					BlobValue: &v6.AffectedPackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []v6.AffectedRange{
							{
								Version: v6.AffectedVersion{
									Type:       "python",
									Constraint: ">=4.0,<4.3.12",
								},
								Fix: &v6.Fix{
									Version: "4.3.12",
									State:   v6.FixedStatus,
								},
							},
						},
					},
				},
				{
					Package: &v6.Package{
						Name:      "Plone",
						Ecosystem: "python",
					},
					BlobValue: &v6.AffectedPackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []v6.AffectedRange{
							{
								Version: v6.AffectedVersion{
									Type:       "python",
									Constraint: ">=5.1a1,<5.1b1",
								},
								Fix: &v6.Fix{
									Version: "5.1b1",
									State:   v6.FixedStatus,
								},
							},
						},
					},
				},
				{
					Package: &v6.Package{
						Name:      "Plone-debug",
						Ecosystem: "python",
					},
					BlobValue: &v6.AffectedPackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []v6.AffectedRange{
							{
								Version: v6.AffectedVersion{
									Type:       "python",
									Constraint: ">=5.0rc1,<5.0.7",
								},
								Fix: &v6.Fix{
									Version: "5.0.7",
									State:   v6.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisories := loadFixture(t, tt.name)
			var results []v6.AffectedPackageHandle
			for _, advisor := range advisories {
				result := getAffectedPackage(advisor)
				results = append(results, result...)
			}
			if d := cmp.Diff(tt.expected, results); d != "" {
				t.Fatalf("unexpected result: %s", d)
			}
		})
	}
}

func TestGetPackageType(t *testing.T) {
	tests := []struct {
		ecosystem    string
		expectedType pkg.Type
	}{
		{"composer", pkg.PhpComposerPkg},
		{"Composer", pkg.PhpComposerPkg}, // testing case insensitivity
		{"COMPOSER", pkg.PhpComposerPkg}, // testing case insensitivity
		{"rust", pkg.RustPkg},
		{"cargo", pkg.RustPkg},
		{"dart", pkg.DartPubPkg},
		{"nuget", pkg.DotnetPkg},
		{".net", pkg.DotnetPkg},
		{"go", pkg.GoModulePkg},
		{"golang", pkg.GoModulePkg},
		{"maven", pkg.JavaPkg},
		{"java", pkg.JavaPkg},
		{"npm", pkg.NpmPkg},
		{"pypi", pkg.PythonPkg},
		{"python", pkg.PythonPkg},
		{"pip", pkg.PythonPkg},
		{"swift", pkg.SwiftPkg},
		{"rubygems", pkg.GemPkg},
		{"ruby", pkg.GemPkg},
		{"gem", pkg.GemPkg},
		{"apk", pkg.ApkPkg},
		{"rpm", pkg.RpmPkg},
		{"deb", pkg.DebPkg},
		{"github-action", pkg.GithubActionPkg},

		// test for unknown type fallback
		{"unknown-ecosystem", pkg.Type("unknown-ecosystem")},
		{"", pkg.Type("")},
	}

	for _, tc := range tests {
		t.Run(tc.ecosystem, func(t *testing.T) {
			gotType := getPackageType(tc.ecosystem)
			if gotType != tc.expectedType {
				t.Errorf("getPackageType(%q) = %v, want %v", tc.ecosystem, gotType, tc.expectedType)
			}
		})
	}
}

func TestGetRanges(t *testing.T) {
	advisories := loadFixture(t, "test-fixtures/GHSA-92cp-5422-2mw7.json")
	require.Len(t, advisories, 1)
	advisory := advisories[0]
	var ranges []v6.AffectedRange
	expectedRanges := []v6.AffectedRange{
		{
			Version: v6.AffectedVersion{
				Type:       "go",
				Constraint: ">=9.7.0-beta.1,<9.7.3",
			},
			Fix: &v6.Fix{
				Version: "9.7.3",
				State:   v6.FixedStatus,
			},
		},
		{
			Version: v6.AffectedVersion{
				// important: this emits an unknown constraint type,
				// triggering fuzzy matching when the input is not
				// valid semver
				Type:       "Unknown",
				Constraint: ">=9.6.0b1,<9.6.3",
			},
			Fix: &v6.Fix{
				Version: "9.6.3",
				State:   v6.FixedStatus,
			},
		},
		{
			Version: v6.AffectedVersion{
				Type:       "go",
				Constraint: ">=9.5.1,<9.5.5",
			},
			Fix: &v6.Fix{
				Version: "9.5.5",
				State:   v6.FixedStatus,
			},
		},
	}
	var errors []error
	for _, fixedIn := range advisory.Advisory.FixedIn {
		rng, err := getRanges(fixedIn)
		if err != nil {
			errors = append(errors, err)
		}
		ranges = append(ranges, rng...)
	}

	require.Equal(t, 1, len(errors))
	if diff := cmp.Diff(expectedRanges, ranges); diff != "" {
		t.Errorf("getRanges() mismatch (-want +got):\n%s", diff)
	}
}

func loadFixture(t *testing.T, path string) []unmarshal.GitHubAdvisory {
	f, err := os.Open(path)
	t.Cleanup(func() {
		require.NoError(t, f.Close())
	})
	require.NoError(t, err)

	entries, err := unmarshal.GitHubAdvisoryEntries(f)
	require.NoError(t, err)

	return entries
}
