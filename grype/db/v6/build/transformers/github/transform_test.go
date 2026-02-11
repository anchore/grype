package github

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
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
		expected []db.VulnerabilityHandle
	}{
		{
			name: "test-fixtures/GHSA-2wgc-48g2-cj5w.json",
			expected: []db.VulnerabilityHandle{
				{
					Name:       "GHSA-2wgc-48g2-cj5w",
					ProviderID: "github",
					Provider: &db.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2024-02-08T22:48:31Z"),
					PublishedDate: internal.ParseTime("2024-01-30T20:56:46Z"),
					WithdrawnDate: nil,
					Status:        db.VulnerabilityActive,
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GHSA-2wgc-48g2-cj5w",
						Description: "vantage6 has insecure SSH configuration for node and server containers",
						References: []db.Reference{
							{
								URL: "https://github.com/advisories/GHSA-2wgc-48g2-cj5w",
							},
						},
						Aliases: []string{"CVE-2024-21653"},
						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "medium",
							},
							{
								Scheme: db.SeveritySchemeCVSS,
								Value: db.CVSSSeverity{
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
			expected: []db.VulnerabilityHandle{
				{
					Name:       "GHSA-3x74-v64j-qc3f",
					ProviderID: "github",
					Provider: &db.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2024-03-21T17:48:19Z"),
					PublishedDate: internal.ParseTime("2023-06-13T18:30:39Z"),
					WithdrawnDate: internal.ParseTime("2023-06-28T23:54:39Z"),
					Status:        db.VulnerabilityRejected,
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GHSA-3x74-v64j-qc3f",
						Description: "Withdrawn Advisory: CraftCMS Server-Side Template Injection vulnerability",
						References: []db.Reference{
							{
								URL: "https://github.com/advisories/GHSA-3x74-v64j-qc3f",
							},
						},
						Aliases: []string{"CVE-2023-30179"},
						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "high",
							},
							{
								Scheme: db.SeveritySchemeCVSS,
								Value: db.CVSSSeverity{
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
			expected: []db.VulnerabilityHandle{
				{
					Name:       "GHSA-vc9j-fhvv-8vrf",
					ProviderID: "github",
					Provider: &db.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2023-01-09T05:03:39Z"),
					PublishedDate: internal.ParseTime("2020-07-27T19:55:52Z"),
					WithdrawnDate: nil,
					Status:        db.VulnerabilityActive,
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GHSA-vc9j-fhvv-8vrf",
						Description: "Remote Code Execution in scratch-vm",
						References: []db.Reference{
							{
								URL: "https://github.com/advisories/GHSA-vc9j-fhvv-8vrf",
							},
						},
						Aliases: []string{"CVE-2020-14000"},
						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "critical",
							},
							{
								Scheme: db.SeveritySchemeCVSS,
								Value: db.CVSSSeverity{
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
			expected: []db.VulnerabilityHandle{
				{
					Name:       "GHSA-6cwv-x26c-w2q4",
					ProviderID: "github",
					Provider: &db.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					Status: "active",
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GHSA-6cwv-x26c-w2q4",
						Description: "Low severity vulnerability that affects notebook",
						References: []db.Reference{
							{
								URL: "https://github.com/advisories/GHSA-6cwv-x26c-w2q4",
							},
						},

						Aliases: []string{"CVE-2018-8768"},

						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "low",
							},
						},
					},
				},
				{
					Name:       "GHSA-p5wr-vp8g-q5p4",
					ProviderID: "github",
					Provider: &db.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					Status: "active",
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GHSA-p5wr-vp8g-q5p4",
						Description: "Moderate severity vulnerability that affects Plone",
						References: []db.Reference{
							{
								URL: "https://github.com/advisories/GHSA-p5wr-vp8g-q5p4",
							},
						},
						Aliases: []string{"CVE-2017-5524"},
						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "medium",
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-withdrawn.json",
			expected: []db.VulnerabilityHandle{
				{
					Name:       "GHSA-6cwv-x26c-w2q4",
					ProviderID: "github",
					Provider: &db.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  nil,
					PublishedDate: nil,
					WithdrawnDate: internal.ParseTime("2022-01-31T14:32:09Z"),
					Status:        db.VulnerabilityRejected,
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GHSA-6cwv-x26c-w2q4",
						Description: "Low severity vulnerability that affects notebook",
						References: []db.Reference{
							{
								URL: "https://github.com/advisories/GHSA-6cwv-x26c-w2q4",
							},
						},
						Aliases: []string{"CVE-2018-8768"},
						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "low",
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/multiple-fixed-in-names.json",
			expected: []db.VulnerabilityHandle{
				{
					Name:       "GHSA-p5wr-vp8g-q5p4",
					ProviderID: "github",
					Provider: &db.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					Status: db.VulnerabilityActive,
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GHSA-p5wr-vp8g-q5p4",
						Description: "Moderate severity vulnerability that affects Plone",
						References: []db.Reference{
							{
								URL: "https://github.com/advisories/GHSA-p5wr-vp8g-q5p4",
							},
						},
						Aliases: []string{"CVE-2017-5524"},
						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "medium",
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/GHSA-qc55-vm3j-74gp.json",
			expected: []db.VulnerabilityHandle{
				{
					Name:       "GHSA-qc55-vm3j-74gp",
					ProviderID: "github",
					Provider: &db.Provider{
						ID:           "github",
						Version:      "1",
						DateCaptured: &now,
					},
					ModifiedDate:  internal.ParseTime("2024-09-24T21:02:13Z"),
					PublishedDate: internal.ParseTime("2018-07-12T20:30:36Z"),
					WithdrawnDate: nil,
					Status:        db.VulnerabilityActive,
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GHSA-qc55-vm3j-74gp",
						Description: "JSNAPy allows unprivileged local users to alter files under the directory",
						References: []db.Reference{
							{
								URL: "https://github.com/advisories/GHSA-qc55-vm3j-74gp",
							},
							{
								URL: "https://nvd.nist.gov/vuln/detail/CVE-2018-0023",
							},
							{
								URL: "https://kb.juniper.net/JSA10856",
							},
							{
								URL: "https://github.com/pypa/advisory-database/tree/main/vulns/jsnapy/PYSEC-2018-84.yaml",
							},
							{
								URL: "https://web.archive.org/web/20200227125151/http://www.securityfocus.com/bid/103745",
							},
						},
						Aliases: []string{"CVE-2018-0023"},
						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "high",
							},
							{
								Scheme: db.SeveritySchemeCVSS,
								Value: db.CVSSSeverity{
									Vector:  "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
									Version: "3.0",
								},
							},
							{
								Scheme: db.SeveritySchemeCVSS,
								Value: db.CVSSSeverity{
									Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
									Version: "4.0",
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
			var results []db.VulnerabilityHandle

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
		expected []db.AffectedPackageHandle
	}{
		{
			name: "test-fixtures/GHSA-2wgc-48g2-cj5w.json",
			expected: []db.AffectedPackageHandle{
				{
					Package: &db.Package{
						Name:      "vantage6",
						Ecosystem: "python",
					},
					BlobValue: &db.PackageBlob{
						CVEs: []string{"CVE-2024-21653"},
						Ranges: []db.Range{
							{
								Version: db.Version{
									Type:       "python",
									Constraint: "<4.2.0",
								},
								Fix: &db.Fix{
									Version: "4.2.0",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: internal.ParseTime("2024-01-30T15:00:00Z"),
											Kind: "advisory",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/GHSA-3x74-v64j-qc3f.json",
			expected: []db.AffectedPackageHandle{
				{
					Package: &db.Package{
						Name:      "craftcms/cms",
						Ecosystem: "packagist",
					},
					BlobValue: &db.PackageBlob{
						CVEs: []string{"CVE-2023-30179"},
						Ranges: []db.Range{
							{
								Version: db.Version{
									Type:       "packagist",
									Constraint: "<4.4.2",
								},
								Fix: &db.Fix{
									Version: "4.4.2",
									State:   db.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-npm-0.json",
			expected: []db.AffectedPackageHandle{
				{
					Package: &db.Package{
						Name:      "scratch-vm",
						Ecosystem: "npm",
					},
					BlobValue: &db.PackageBlob{
						CVEs: []string{"CVE-2020-14000"},
						Ranges: []db.Range{
							{
								Version: db.Version{
									Type:       "npm",
									Constraint: "<=0.2.0-prerelease.20200709173451",
								},
								Fix: &db.Fix{
									Version: "0.2.0-prerelease.20200714185213",
									State:   db.FixedStatus,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/github-github-python-0.json",
			expected: []db.AffectedPackageHandle{
				{
					Package: &db.Package{
						Ecosystem: "python",
						Name:      "notebook",
					},
					BlobValue: &db.PackageBlob{
						CVEs:       []string{"CVE-2018-8768"},
						Qualifiers: nil,
						Ranges: []db.Range{
							{
								Version: db.Version{Type: "python", Constraint: "<5.4.1"},
								Fix:     &db.Fix{Version: "5.4.1", State: db.FixedStatus},
							},
						},
					},
				},
				{
					Package: &db.Package{
						Ecosystem: "python",
						Name:      "Plone",
					},
					BlobValue: &db.PackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []db.Range{
							{
								Version: db.Version{Type: "python", Constraint: ">=4.0,<4.3.12"},
								Fix:     &db.Fix{Version: "4.3.12", State: db.FixedStatus},
							},
						},
					},
				},
			},
		},
		{
			name: "test-fixtures/multiple-fixed-in-names.json",
			expected: []db.AffectedPackageHandle{
				{
					Package: &db.Package{
						Name:      "Plone",
						Ecosystem: "python",
					},
					BlobValue: &db.PackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []db.Range{
							{
								Version: db.Version{
									Type:       "python",
									Constraint: ">=4.0,<4.3.12",
								},
								Fix: &db.Fix{
									Version: "4.3.12",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: internal.ParseTime("2017-05-20T10:30:45Z"),
											Kind: "release",
										},
									},
								},
							},
						},
					},
				},
				{
					Package: &db.Package{
						Name:      "Plone",
						Ecosystem: "python",
					},
					BlobValue: &db.PackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []db.Range{
							{
								Version: db.Version{
									Type:       "python",
									Constraint: ">=5.1a1,<5.1b1",
								},
								Fix: &db.Fix{
									Version: "5.1b1",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: internal.ParseTime("2017-06-15T14:22:33Z"),
											Kind: "commit",
										},
									},
								},
							},
						},
					},
				},
				{
					Package: &db.Package{
						Name:      "Plone-debug",
						Ecosystem: "python",
					},
					BlobValue: &db.PackageBlob{
						CVEs: []string{"CVE-2017-5524"},
						Ranges: []db.Range{
							{
								Version: db.Version{
									Type:       "python",
									Constraint: ">=5.0rc1,<5.0.7",
								},
								Fix: &db.Fix{
									Version: "5.0.7",
									State:   db.FixedStatus,
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
			var results []db.AffectedPackageHandle
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
	var ranges []db.Range
	expectedRanges := []db.Range{
		{
			Version: db.Version{
				Type:       "go",
				Constraint: ">=9.7.0-beta.1,<9.7.3",
			},
			Fix: &db.Fix{
				Version: "9.7.3",
				State:   db.FixedStatus,
			},
		},
		{
			Version: db.Version{
				// important: this emits an unknown constraint type,
				// triggering fuzzy matching when the input is not
				// valid semver
				Type:       "Unknown",
				Constraint: ">=9.6.0b1,<9.6.3",
			},
			Fix: &db.Fix{
				Version: "9.6.3",
				State:   db.FixedStatus,
			},
		},
		{
			Version: db.Version{
				Type:       "go",
				Constraint: ">=9.5.1,<9.5.5",
			},
			Fix: &db.Fix{
				Version: "9.5.5",
				State:   db.FixedStatus,
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

func TestGetFixAvailability(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected map[string]*db.FixAvailability // keyed by package identifier for fixture-based testing
	}{
		{
			name:    "GHSA-2wgc-48g2-cj5w with advisory availability",
			fixture: "test-fixtures/GHSA-2wgc-48g2-cj5w.json",
			expected: map[string]*db.FixAvailability{
				"4.2.0": {
					Date: internal.ParseTime("2024-01-30T15:00:00Z"),
					Kind: "advisory",
				},
			},
		},
		{
			name:    "multiple-fixed-in-names with mixed availability",
			fixture: "test-fixtures/multiple-fixed-in-names.json",
			expected: map[string]*db.FixAvailability{
				"4.3.12": {
					Date: internal.ParseTime("2017-05-20T10:30:45Z"),
					Kind: "release",
				},
				"5.1b1": {
					Date: internal.ParseTime("2017-06-15T14:22:33Z"),
					Kind: "commit",
				},
				"5.0.7": nil, // no availability data in fixture
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisories := loadFixture(t, tt.fixture)
			require.Len(t, advisories, 1, "expected exactly one advisory")

			for _, fixedIn := range advisories[0].Advisory.FixedIn {
				result := getFixAvailability(fixedIn)
				expected := tt.expected[fixedIn.Identifier]

				if expected == nil {
					require.Nil(t, result, "expected nil availability for %s", fixedIn.Identifier)
				} else {
					require.NotNil(t, result, "expected non-nil availability for %s", fixedIn.Identifier)
					require.Equal(t, expected.Kind, result.Kind)
					require.Equal(t, expected.Date, result.Date)
				}
			}
		})
	}

	// keep edge case test for scenarios not covered by fixtures
	t.Run("invalid date returns nil", func(t *testing.T) {
		fixedIn := unmarshal.GithubFixedIn{
			Available: struct {
				Date string `json:"date,omitempty"`
				Kind string `json:"kind,omitempty"`
			}{
				Date: "invalid-date",
				Kind: "commit",
			},
		}
		result := getFixAvailability(fixedIn)
		require.Nil(t, result)
	})
}

func TestGetFix(t *testing.T) {
	// fixture-based tests
	tests := []struct {
		name     string
		fixture  string
		expected map[string]*db.Fix // keyed by package identifier
	}{
		{
			name:    "GHSA-2wgc-48g2-cj5w with availability",
			fixture: "test-fixtures/GHSA-2wgc-48g2-cj5w.json",
			expected: map[string]*db.Fix{
				"4.2.0": {
					Version: "4.2.0",
					State:   db.FixedStatus,
					Detail: &db.FixDetail{
						Available: &db.FixAvailability{
							Date: internal.ParseTime("2024-01-30T15:00:00Z"),
							Kind: "advisory",
						},
					},
				},
			},
		},
		{
			name:    "multiple-fixed-in-names with mixed availability",
			fixture: "test-fixtures/multiple-fixed-in-names.json",
			expected: map[string]*db.Fix{
				"4.3.12": {
					Version: "4.3.12",
					State:   db.FixedStatus,
					Detail: &db.FixDetail{
						Available: &db.FixAvailability{
							Date: internal.ParseTime("2017-05-20T10:30:45Z"),
							Kind: "release",
						},
					},
				},
				"5.1b1": {
					Version: "5.1b1",
					State:   db.FixedStatus,
					Detail: &db.FixDetail{
						Available: &db.FixAvailability{
							Date: internal.ParseTime("2017-06-15T14:22:33Z"),
							Kind: "commit",
						},
					},
				},
				"5.0.7": {
					Version: "5.0.7",
					State:   db.FixedStatus,
					Detail:  nil, // no availability data
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisories := loadFixture(t, tt.fixture)
			require.Len(t, advisories, 1, "expected exactly one advisory")

			for _, fixedIn := range advisories[0].Advisory.FixedIn {
				result := getFix(fixedIn)
				expected := tt.expected[fixedIn.Identifier]

				require.NotNil(t, expected, "no expected result for identifier %s", fixedIn.Identifier)
				if d := cmp.Diff(expected, result); d != "" {
					t.Fatalf("unexpected result for %s: %s", fixedIn.Identifier, d)
				}
			}
		})
	}

	// keep edge case tests
	t.Run("no fix version and no availability", func(t *testing.T) {
		fixedIn := unmarshal.GithubFixedIn{
			Identifier: "",
			Available: struct {
				Date string `json:"date,omitempty"`
				Kind string `json:"kind,omitempty"`
			}{},
		}
		expected := &db.Fix{
			Version: "",
			State:   db.NotFixedStatus,
			Detail:  nil,
		}
		result := getFix(fixedIn)
		if d := cmp.Diff(expected, result); d != "" {
			t.Fatalf("unexpected result: %s", d)
		}
	})
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
