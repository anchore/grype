package dbsearch

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/syft/syft/cpe"
)

func TestAffectedPackageTableRowMarshalJSON(t *testing.T) {
	row := AffectedPackage{
		Vulnerability: VulnerabilityInfo{
			VulnerabilityBlob: v6.VulnerabilityBlob{
				ID:          "CVE-1234-5678",
				Description: "Test vulnerability",
			},
			Provider:      "provider1",
			Status:        "active",
			PublishedDate: ptr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
			ModifiedDate:  ptr(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
			KnownExploited: []KnownExploited{
				{
					CVE:                        "CVE-1234-5678",
					VendorProject:              "LinuxFoundation",
					Product:                    "Linux",
					DateAdded:                  "2025-02-02",
					RequiredAction:             "Yes",
					DueDate:                    "2025-02-02",
					KnownRansomwareCampaignUse: "Known",
					Notes:                      "note!",
					URLs:                       []string{"https://example.com"},
					CWEs:                       []string{"CWE-1234"},
				},
			},
			EPSS: []EPSS{
				{
					CVE:        "CVE-1234-5678",
					EPSS:       0.893,
					Percentile: 0.99,
					Date:       "2025-02-24",
				},
			},
		},
		AffectedPackageInfo: AffectedPackageInfo{
			Package:   &Package{Name: "pkg1", Ecosystem: "ecosystem1"},
			CPE:       &CPE{Part: "a", Vendor: "vendor1:2:3", Product: "product1/subproduct"},
			Namespace: "namespace1",
			Detail: v6.PackageBlob{
				CVEs: []string{"CVE-1234-5678"},
				Qualifiers: &v6.PackageQualifiers{
					RpmModularity: ptr("modularity"),
					PlatformCPEs:  []string{"platform-cpe-1"},
				},
				Ranges: []v6.Range{
					{
						Version: v6.Version{
							Type:       "semver",
							Constraint: ">=1.0.0, <2.0.0",
						},
						Fix: &v6.Fix{
							Version: "1.2.0",
							State:   "fixed",
						},
					},
				},
			},
		},
	}

	buf := bytes.Buffer{}
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	err := enc.Encode(row)
	require.NoError(t, err)

	expectedJSON := `{
  "vulnerability": {
    "id": "CVE-1234-5678",
    "description": "Test vulnerability",
    "provider": "provider1",
    "status": "active",
    "published_date": "2023-01-01T00:00:00Z",
    "modified_date": "2023-02-01T00:00:00Z",
    "known_exploited": [
      {
        "cve": "CVE-1234-5678",
        "vendor_project": "LinuxFoundation",
        "product": "Linux",
        "date_added": "2025-02-02",
        "required_action": "Yes",
        "due_date": "2025-02-02",
        "known_ransomware_campaign_use": "Known",
        "notes": "note!",
        "urls": [
          "https://example.com"
        ],
        "cwes": [
          "CWE-1234"
        ]
      }
    ],
    "epss": [
      {
        "cve": "CVE-1234-5678",
        "epss": 0.893,
        "percentile": 0.99,
        "date": "2025-02-24"
      }
    ]
  },
  "package": {
    "name": "pkg1",
    "ecosystem": "ecosystem1"
  },
  "cpe": "cpe:2.3:a:vendor1\\:2\\:3:product1\\/subproduct:*:*:*:*:*:*:*:*",
  "namespace": "namespace1",
  "detail": {
    "cves": [
      "CVE-1234-5678"
    ],
    "qualifiers": {
      "rpm_modularity": "modularity",
      "platform_cpes": [
        "platform-cpe-1"
      ]
    },
    "ranges": [
      {
        "version": {
          "type": "semver",
          "constraint": ">=1.0.0, <2.0.0"
        },
        "fix": {
          "version": "1.2.0",
          "state": "fixed"
        }
      }
    ]
  }
}
`

	if diff := cmp.Diff(expectedJSON, buf.String()); diff != "" {
		t.Errorf("unexpected JSON (-want +got):\n%s", diff)
	}
}

func TestAffectedPackages(t *testing.T) {
	mockReader := new(affectedMockReader)

	mockReader.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{
		{
			Package: &v6.Package{Name: "pkg1", Ecosystem: "ecosystem1"},
			OperatingSystem: &v6.OperatingSystem{
				Name:         "Linux",
				MajorVersion: "5",
				MinorVersion: "10",
			},
			Vulnerability: &v6.VulnerabilityHandle{
				ID:            1,
				Name:          "CVE-1234-5678",
				Provider:      &v6.Provider{ID: "provider1"},
				Status:        "active",
				PublishedDate: ptr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:  ptr(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
				BlobValue:     &v6.VulnerabilityBlob{Description: "Test vulnerability"},
			},
			BlobValue: &v6.PackageBlob{
				CVEs: []string{"CVE-1234-5678"},
				Ranges: []v6.Range{
					{
						Version: v6.Version{
							Type:       "semver",
							Constraint: ">=1.0.0, <2.0.0",
						},
						Fix: &v6.Fix{
							Version: "1.2.0",
							State:   "fixed",
						},
					},
				},
			},
		},
	}, nil)

	mockReader.On("GetUnaffectedPackages", mock.Anything, mock.Anything).Return([]v6.UnaffectedPackageHandle{
		{
			Package: &v6.Package{Name: "pkg1", Ecosystem: "ecosystem1"},
			OperatingSystem: &v6.OperatingSystem{
				Name:         "Linux",
				MajorVersion: "5",
				MinorVersion: "10",
			},
			Vulnerability: &v6.VulnerabilityHandle{
				ID:            2,
				Name:          "CVE-1234-5679",
				Provider:      &v6.Provider{ID: "provider2"},
				Status:        "active",
				PublishedDate: ptr(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:  ptr(time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)),
				BlobValue:     &v6.VulnerabilityBlob{Description: "Test vulnerability"},
			},
			BlobValue: &v6.PackageBlob{
				CVEs: []string{"CVE-1234-5679"},
				Ranges: []v6.Range{
					{
						Version: v6.Version{
							Type:       "semver",
							Constraint: ">=2.3.0",
						},
						Fix: &v6.Fix{
							Version: "2.2.0",
							State:   "fixed",
						},
					},
				},
			},
		},
	}, nil)

	mockReader.On("GetAffectedCPEs", mock.Anything, mock.Anything).Return([]v6.AffectedCPEHandle{
		{
			CPE: &v6.Cpe{Part: "a", Vendor: "vendor1", Product: "product1"},
			Vulnerability: &v6.VulnerabilityHandle{
				ID:        4,
				Name:      "CVE-9876-5432",
				Provider:  &v6.Provider{ID: "provider2"},
				BlobValue: &v6.VulnerabilityBlob{Description: "CPE vulnerability description"},
			},
			BlobValue: &v6.PackageBlob{
				CVEs: []string{"CVE-9876-5432"},
				Ranges: []v6.Range{
					{
						Version: v6.Version{
							Type:       "rpm",
							Constraint: ">=2.0.0, <3.0.0",
						},
						Fix: &v6.Fix{
							Version: "2.5.0",
							State:   "fixed",
						},
					},
				},
			},
		},
	}, nil)

	mockReader.On("GetUnaffectedCPEs", mock.Anything, mock.Anything).Return([]v6.UnaffectedCPEHandle{
		{
			CPE: &v6.Cpe{Part: "a", Vendor: "vendor1", Product: "product1"},
			Vulnerability: &v6.VulnerabilityHandle{
				ID:        3,
				Name:      "CVE-9876-5433",
				Provider:  &v6.Provider{ID: "provider2"},
				BlobValue: &v6.VulnerabilityBlob{Description: "CPE vulnerability description"},
			},
			BlobValue: &v6.PackageBlob{
				CVEs: []string{"CVE-9876-54311"},
				Ranges: []v6.Range{
					{
						Version: v6.Version{
							Type:       "rpm",
							Constraint: "= 7.5.0",
						},
						Fix: &v6.Fix{
							State: "not-affected",
						},
					},
				},
			},
		},
	}, nil)

	mockReader.On("GetKnownExploitedVulnerabilities", "CVE-1234-5678").Return([]v6.KnownExploitedVulnerabilityHandle{
		{
			Cve: "CVE-1234-5678",
			BlobValue: &v6.KnownExploitedVulnerabilityBlob{
				Cve:                        "CVE-1234-5678",
				VendorProject:              "LinuxFoundation",
				Product:                    "Linux",
				DateAdded:                  ptr(time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)),
				RequiredAction:             "Yes",
				DueDate:                    ptr(time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)),
				KnownRansomwareCampaignUse: "Known",
				Notes:                      "note!",
				URLs:                       []string{"https://example.com"},
				CWEs:                       []string{"CWE-1234"},
			},
		},
	}, nil)

	mockReader.On("GetKnownExploitedVulnerabilities", "CVE-1234-5679").Return([]v6.KnownExploitedVulnerabilityHandle{
		{
			Cve: "CVE-1234-5679",
			BlobValue: &v6.KnownExploitedVulnerabilityBlob{
				Cve:                        "CVE-1234-5679",
				VendorProject:              "LinuxFoundation",
				Product:                    "Linux",
				DateAdded:                  ptr(time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)),
				RequiredAction:             "Yes",
				DueDate:                    ptr(time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)),
				KnownRansomwareCampaignUse: "Known",
				Notes:                      "note!",
				URLs:                       []string{"https://example.com"},
				CWEs:                       []string{"CWE-1234"},
			},
		},
	}, nil)

	mockReader.On("GetKnownExploitedVulnerabilities", "CVE-9876-5432").Return([]v6.KnownExploitedVulnerabilityHandle{
		{
			Cve: "CVE-9876-5432",
			BlobValue: &v6.KnownExploitedVulnerabilityBlob{
				Cve:                        "CVE-9876-5432",
				VendorProject:              "vendor1",
				Product:                    "product1",
				DateAdded:                  ptr(time.Date(2025, 2, 3, 0, 0, 0, 0, time.UTC)),
				RequiredAction:             "Yes",
				DueDate:                    ptr(time.Date(2025, 2, 3, 0, 0, 0, 0, time.UTC)),
				KnownRansomwareCampaignUse: "Known",
				Notes:                      "note!",
				URLs:                       []string{"https://example.com"},
				CWEs:                       []string{"CWE-5678"},
			},
		},
	}, nil)

	mockReader.On("GetKnownExploitedVulnerabilities", "CVE-9876-5433").Return([]v6.KnownExploitedVulnerabilityHandle{
		{
			Cve: "CVE-9876-5433",
			BlobValue: &v6.KnownExploitedVulnerabilityBlob{
				Cve:                        "CVE-9876-5433",
				VendorProject:              "vendor1",
				Product:                    "product1",
				DateAdded:                  ptr(time.Date(2025, 2, 3, 0, 0, 0, 0, time.UTC)),
				RequiredAction:             "Yes",
				DueDate:                    ptr(time.Date(2025, 2, 3, 0, 0, 0, 0, time.UTC)),
				KnownRansomwareCampaignUse: "Known",
				Notes:                      "note!",
				URLs:                       []string{"https://example.com"},
				CWEs:                       []string{"CWE-5678"},
			},
		},
	}, nil)

	mockReader.On("GetEpss", "CVE-1234-5678").Return([]v6.EpssHandle{
		{
			Cve:        "CVE-1234-5678",
			Epss:       0.893,
			Percentile: 0.99,
			Date:       time.Date(2025, 2, 24, 0, 0, 0, 0, time.UTC),
		},
	}, nil)

	mockReader.On("GetEpss", "CVE-1234-5679").Return([]v6.EpssHandle{
		{
			Cve:        "CVE-1234-5679",
			Epss:       0.893,
			Percentile: 0.99,
			Date:       time.Date(2025, 2, 24, 0, 0, 0, 0, time.UTC),
		},
	}, nil)

	mockReader.On("GetEpss", "CVE-9876-5432").Return([]v6.EpssHandle{
		{
			Cve:        "CVE-9876-5432",
			Epss:       0.938,
			Percentile: 0.9222,
			Date:       time.Date(2025, 2, 25, 0, 0, 0, 0, time.UTC),
		},
	}, nil)

	mockReader.On("GetEpss", "CVE-9876-5433").Return([]v6.EpssHandle{
		{
			Cve:        "CVE-9876-5433",
			Epss:       0.938,
			Percentile: 0.9222,
			Date:       time.Date(2025, 2, 25, 0, 0, 0, 0, time.UTC),
		},
	}, nil)

	criteria := AffectedPackagesOptions{
		Vulnerability: v6.VulnerabilitySpecifiers{
			{Name: "CVE-1234-5678"},
		},
	}

	matches, err := FindMatches(mockReader, criteria)
	require.NoError(t, err)
	results := flatten(matches, func(m Match) []AffectedPackageInfo { return m.AffectedPackages })

	expected := []AffectedPackage{
		{
			Vulnerability: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "Test vulnerability"},
				Severity:          "unknown",
				Provider:          "provider1",
				Status:            "active",
				PublishedDate:     ptr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:      ptr(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
				KnownExploited: []KnownExploited{
					{
						CVE:                        "CVE-1234-5678",
						VendorProject:              "LinuxFoundation",
						Product:                    "Linux",
						DateAdded:                  "2025-02-02",
						RequiredAction:             "Yes",
						DueDate:                    "2025-02-02",
						KnownRansomwareCampaignUse: "Known",
						Notes:                      "note!",
						URLs:                       []string{"https://example.com"},
						CWEs:                       []string{"CWE-1234"},
					},
				},
				EPSS: []EPSS{
					{
						CVE:        "CVE-1234-5678",
						EPSS:       0.893,
						Percentile: 0.99,
						Date:       "2025-02-24",
					},
				},
			},
			AffectedPackageInfo: AffectedPackageInfo{
				OS:        &OperatingSystem{Name: "Linux", Version: "5.10"},
				Package:   &Package{Name: "pkg1", Ecosystem: "ecosystem1"},
				Namespace: "provider1:distro:Linux:5.10",
				Detail: v6.PackageBlob{
					CVEs: []string{"CVE-1234-5678"},
					Ranges: []v6.Range{
						{
							Version: v6.Version{
								Type:       "semver",
								Constraint: ">=1.0.0, <2.0.0",
							},
							Fix: &v6.Fix{
								Version: "1.2.0",
								State:   "fixed",
							},
						},
					},
				},
			},
		},
		{
			Vulnerability: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "CPE vulnerability description"},
				Severity:          "unknown",
				Provider:          "provider2",
				KnownExploited: []KnownExploited{
					{
						CVE:                        "CVE-9876-5432",
						VendorProject:              "vendor1",
						Product:                    "product1",
						DateAdded:                  "2025-02-03",
						RequiredAction:             "Yes",
						DueDate:                    "2025-02-03",
						KnownRansomwareCampaignUse: "Known",
						Notes:                      "note!",
						URLs:                       []string{"https://example.com"},
						CWEs:                       []string{"CWE-5678"},
					},
				},
				EPSS: []EPSS{
					{
						CVE:        "CVE-9876-5432",
						EPSS:       0.938,
						Percentile: 0.9222,
						Date:       "2025-02-25",
					},
				},
			},
			AffectedPackageInfo: AffectedPackageInfo{
				CPE:       &CPE{Part: "a", Vendor: "vendor1", Product: "product1"},
				Namespace: "provider2:cpe",
				Detail: v6.PackageBlob{
					CVEs: []string{"CVE-9876-5432"},
					Ranges: []v6.Range{
						{
							Version: v6.Version{
								Type:       "rpm",
								Constraint: ">=2.0.0, <3.0.0",
							},
							Fix: &v6.Fix{
								Version: "2.5.0",
								State:   "fixed",
							},
						},
					},
				},
			},
		},
	}

	if diff := cmp.Diff(expected, results, cmpOpts()...); diff != "" {
		t.Errorf("unexpected results (-want +got):\n%s", diff)
	}

	// unaffected records are only reported by matches, separate from the affected packages
	expectedUnaffected := []AffectedPackage{
		{
			Vulnerability: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "CPE vulnerability description"},
				Severity:          "unknown",
				Provider:          "provider2",
				KnownExploited: []KnownExploited{
					{
						CVE:                        "CVE-9876-5433",
						VendorProject:              "vendor1",
						Product:                    "product1",
						DateAdded:                  "2025-02-03",
						RequiredAction:             "Yes",
						DueDate:                    "2025-02-03",
						KnownRansomwareCampaignUse: "Known",
						Notes:                      "note!",
						URLs:                       []string{"https://example.com"},
						CWEs:                       []string{"CWE-5678"},
					},
				},
				EPSS: []EPSS{
					{
						CVE:        "CVE-9876-5433",
						EPSS:       0.938,
						Percentile: 0.9222,
						Date:       "2025-02-25",
					},
				},
			},
			AffectedPackageInfo: AffectedPackageInfo{
				CPE:       &CPE{Part: "a", Vendor: "vendor1", Product: "product1"},
				Namespace: "provider2:cpe",
				Detail: v6.PackageBlob{
					CVEs: []string{"CVE-9876-54311"},
					Ranges: []v6.Range{
						{
							Version: v6.Version{
								Type:       "rpm",
								Constraint: "= 7.5.0",
							},
							Fix: &v6.Fix{
								State: "not-affected",
							},
						},
					},
				},
			},
		},
		{
			Vulnerability: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "Test vulnerability"},
				Severity:          "unknown",
				Provider:          "provider2",
				Status:            "active",
				PublishedDate:     ptr(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:      ptr(time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)),
				KnownExploited: []KnownExploited{
					{
						CVE:                        "CVE-1234-5679",
						VendorProject:              "LinuxFoundation",
						Product:                    "Linux",
						DateAdded:                  "2025-02-02",
						RequiredAction:             "Yes",
						DueDate:                    "2025-02-02",
						KnownRansomwareCampaignUse: "Known",
						Notes:                      "note!",
						URLs:                       []string{"https://example.com"},
						CWEs:                       []string{"CWE-1234"},
					},
				},
				EPSS: []EPSS{
					{
						CVE:        "CVE-1234-5679",
						EPSS:       0.893,
						Percentile: 0.99,
						Date:       "2025-02-24",
					},
				},
			},
			AffectedPackageInfo: AffectedPackageInfo{
				OS:        &OperatingSystem{Name: "Linux", Version: "5.10"},
				Package:   &Package{Name: "pkg1", Ecosystem: "ecosystem1"},
				Namespace: "provider2:distro:Linux:5.10",
				Detail: v6.PackageBlob{
					CVEs: []string{"CVE-1234-5679"},
					Ranges: []v6.Range{
						{
							Version: v6.Version{
								Type:       "semver",
								Constraint: ">=2.3.0",
							},
							Fix: &v6.Fix{
								Version: "2.2.0",
								State:   "fixed",
							},
						},
					},
				},
			},
		},
	}

	// unaffected records are opt-in
	assert.Empty(t, flattenUnaffected(matches))
	matches, err = FindMatches(mockReader, criteria)
	require.NoError(t, err)
	assert.Empty(t, flattenUnaffected(matches))

	criteria.IncludeUnaffected = true
	matches, err = FindMatches(mockReader, criteria)
	require.NoError(t, err)
	if diff := cmp.Diff(expectedUnaffected, flattenUnaffected(matches), cmpOpts()...); diff != "" {
		t.Errorf("unexpected unaffected results (-want +got):\n%s", diff)
	}

	// fix states are not applied to unaffected records, which are only kept as context for the affected records
	// that match (none of the unaffected records here share a vulnerability with an affected record)
	criteria.FixedStates = []string{"fixed"}
	matches, err = FindMatches(mockReader, criteria)
	require.NoError(t, err)
	assert.Empty(t, flattenUnaffected(matches))
	assert.NotEmpty(t, matches)

	// not-affected selects all unaffected records regardless of how the provider stored the fix state, and
	// includes them without asking for unaffected records separately
	criteria.IncludeUnaffected = false
	criteria.FixedStates = []string{"not-affected"}
	matches, err = FindMatches(mockReader, criteria)
	require.NoError(t, err)
	if diff := cmp.Diff(expectedUnaffected, flattenUnaffected(matches), cmpOpts()...); diff != "" {
		t.Errorf("unexpected not-affected unaffected results (-want +got):\n%s", diff)
	}
	for _, m := range matches {
		assert.Empty(t, m.AffectedPackages)
	}
}

func TestPackageRecords_KeepUnaffectedForAffectedVulnerabilities(t *testing.T) {
	vuln := func(id v6.ID) *v6.VulnerabilityHandle { return &v6.VulnerabilityHandle{ID: id} }
	pkg := func(id v6.ID) affectedPackageWithDecorations {
		return affectedPackageWithDecorations{AffectedPackageHandle: v6.AffectedPackageHandle{Vulnerability: vuln(id)}}
	}
	cpe := func(id v6.ID) affectedCPEWithDecorations {
		return affectedCPEWithDecorations{AffectedCPEHandle: v6.AffectedCPEHandle{Vulnerability: vuln(id)}}
	}

	records := packageRecords{
		affectedPkgs:   []affectedPackageWithDecorations{pkg(1)},
		affectedCPEs:   []affectedCPEWithDecorations{cpe(2)},
		unaffectedPkgs: []affectedPackageWithDecorations{pkg(1), pkg(2), pkg(3), {}},
		unaffectedCPEs: []affectedCPEWithDecorations{cpe(2), cpe(3)},
	}
	records.keepUnaffectedForAffectedVulnerabilities()

	assert.Equal(t, []affectedPackageWithDecorations{pkg(1), pkg(2)}, records.unaffectedPkgs)
	assert.Equal(t, []affectedCPEWithDecorations{cpe(2)}, records.unaffectedCPEs)
}

// flattenUnaffected returns the unaffected records of the matches, ordered by namespace
func flattenUnaffected(matches Matches) []AffectedPackage {
	return flatten(matches, func(m Match) []AffectedPackageInfo { return m.Unaffected })
}

// flatten returns the selected records of the matches, ordered by namespace
func flatten(matches Matches, records func(Match) []AffectedPackageInfo) []AffectedPackage {
	var rows []AffectedPackage
	for _, m := range matches {
		for _, pkg := range records(m) {
			rows = append(rows, AffectedPackage{Vulnerability: m.Vulnerability, AffectedPackageInfo: pkg})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Namespace < rows[j].Namespace
	})
	return rows
}

func TestFindAffectedPackages(t *testing.T) {
	// this test is not meant to check the correctness of the results relative to the reader but instead make certain
	// that the correct calls are made to the reader based on the search criteria (we're wired up correctly).
	// Additional verifications are made to check that the combinations of different specs are handled correctly.
	type pkgCall struct {
		pkg     *v6.PackageSpecifier
		options *v6.GetPackageOptions
	}

	type cpeCall struct {
		cpe     *cpe.Attributes
		options *v6.GetCPEOptions
	}

	testCases := []struct {
		name             string
		config           AffectedPackagesOptions
		expectedPkgCalls []pkgCall
		expectedCPECalls []cpeCall
		expectedErr      error
	}{
		{
			name:        "no search criteria",
			config:      AffectedPackagesOptions{},
			expectedErr: ErrNoSearchCriteria,
		},
		{
			name: "os spec alone is not enough",
			config: AffectedPackagesOptions{
				OS: v6.OSSpecifiers{
					{Name: "ubuntu", MajorVersion: "20", MinorVersion: "04"},
				},
			},
			expectedErr: ErrNoSearchCriteria,
		},
		{
			name: "vuln spec provided",
			config: AffectedPackagesOptions{
				Vulnerability: v6.VulnerabilitySpecifiers{
					{Name: "CVE-2023-0001"},
				},
			},
			expectedPkgCalls: []pkgCall{
				{
					pkg: nil,
					options: &v6.GetPackageOptions{
						PreloadOS:            true,
						PreloadPackage:       true,
						PreloadVulnerability: true,
						PreloadBlob:          true,
						Vulnerabilities: v6.VulnerabilitySpecifiers{
							{Name: "CVE-2023-0001"},
						},
						Limit: 0,
					},
				},
			},
			expectedCPECalls: []cpeCall{
				{
					cpe: nil,
					options: &v6.GetCPEOptions{
						PreloadCPE:           true,
						PreloadVulnerability: true,
						PreloadBlob:          true,
						Vulnerabilities: v6.VulnerabilitySpecifiers{
							{Name: "CVE-2023-0001"},
						},
						Limit: 0,
					},
				},
			},
		},
		{
			name: "only cpe spec provided",
			config: AffectedPackagesOptions{
				Package: v6.PackageSpecifiers{
					{CPE: &cpe.Attributes{Part: "a", Vendor: "vendor1", Product: "product1"}},
				},
				CPE: v6.PackageSpecifiers{
					{CPE: &cpe.Attributes{Part: "a", Vendor: "vendor2", Product: "product2"}},
				},
			},
			expectedPkgCalls: []pkgCall{
				{
					pkg: &v6.PackageSpecifier{CPE: &cpe.Attributes{Part: "a", Vendor: "vendor1", Product: "product1"}},
					options: &v6.GetPackageOptions{
						PreloadOS:            true,
						PreloadPackage:       true,
						PreloadVulnerability: true,
						PreloadBlob:          true,
						Vulnerabilities:      nil,
						Limit:                0,
					},
				},
			},
			expectedCPECalls: []cpeCall{
				{
					cpe: &cpe.Attributes{Part: "a", Vendor: "vendor2", Product: "product2"},
					options: &v6.GetCPEOptions{
						PreloadCPE:           true,
						PreloadVulnerability: true,
						PreloadBlob:          true,
						Vulnerabilities:      nil,
						Limit:                0,
					},
				},
			},
			expectedErr: nil,
		},
		{
			name: "cpe + os spec provided",
			config: AffectedPackagesOptions{
				Package: v6.PackageSpecifiers{
					{CPE: &cpe.Attributes{Part: "a", Vendor: "vendor1", Product: "product1"}},
				},
				CPE: v6.PackageSpecifiers{
					{CPE: &cpe.Attributes{Part: "a", Vendor: "vendor2", Product: "product2"}},
				},
				OS: v6.OSSpecifiers{
					{Name: "debian", MajorVersion: "10"}, // this prevents an agnostic CPE search
				},
			},
			expectedPkgCalls: []pkgCall{
				{
					pkg: &v6.PackageSpecifier{CPE: &cpe.Attributes{Part: "a", Vendor: "vendor1", Product: "product1"}},
					options: &v6.GetPackageOptions{
						PreloadOS:            true,
						PreloadPackage:       true,
						PreloadVulnerability: true,
						PreloadBlob:          true,
						Vulnerabilities:      nil,
						OSs: v6.OSSpecifiers{
							{Name: "debian", MajorVersion: "10"},
						},
						Limit: 0,
					},
				},
			},
			expectedCPECalls: nil,
			expectedErr:      nil,
		},
		{
			name: "pkg spec provided",
			config: AffectedPackagesOptions{
				Package: v6.PackageSpecifiers{
					{Name: "test-package", Ecosystem: "npm"},
				},
			},
			expectedPkgCalls: []pkgCall{
				{
					pkg: &v6.PackageSpecifier{Name: "test-package", Ecosystem: "npm"},
					options: &v6.GetPackageOptions{
						PreloadOS:            true,
						PreloadPackage:       true,
						PreloadVulnerability: true,
						PreloadBlob:          true,
						Vulnerabilities:      nil,
						Limit:                0,
					},
				},
			},
			expectedCPECalls: nil,
		},

		{
			name: "pkg and os specs provided",
			config: AffectedPackagesOptions{
				Package: v6.PackageSpecifiers{
					{Name: "test-package", Ecosystem: "npm"},
				},
				OS: v6.OSSpecifiers{
					{Name: "debian", MajorVersion: "10"},
				},
			},
			expectedPkgCalls: []pkgCall{
				{
					pkg: &v6.PackageSpecifier{Name: "test-package", Ecosystem: "npm"},
					options: &v6.GetPackageOptions{
						PreloadOS:            true,
						PreloadPackage:       true,
						PreloadVulnerability: true,
						PreloadBlob:          true,
						OSs: v6.OSSpecifiers{
							{Name: "debian", MajorVersion: "10"},
						},
						Limit: 0,
					},
				},
			},
			expectedCPECalls: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := new(affectedMockReader)
			defer m.AssertExpectations(t)

			for _, expected := range tc.expectedPkgCalls {
				m.On("GetAffectedPackages", expected.pkg, mock.MatchedBy(func(actual *v6.GetPackageOptions) bool {
					return cmp.Equal(actual, expected.options)
				})).Return([]v6.AffectedPackageHandle{}, nil).Once()

				m.On("GetUnaffectedPackages", expected.pkg, mock.MatchedBy(func(actual *v6.GetPackageOptions) bool {
					return cmp.Equal(actual, expected.options)
				})).Return([]v6.UnaffectedPackageHandle{}, nil).Once()
			}

			for _, expected := range tc.expectedCPECalls {
				m.On("GetAffectedCPEs", expected.cpe, mock.MatchedBy(func(actual *v6.GetCPEOptions) bool {
					return cmp.Equal(actual, expected.options)
				})).Return([]v6.AffectedCPEHandle{}, nil).Once()

				m.On("GetUnaffectedCPEs", expected.cpe, mock.MatchedBy(func(actual *v6.GetCPEOptions) bool {
					return cmp.Equal(actual, expected.options)
				})).Return([]v6.UnaffectedCPEHandle{}, nil).Once()
			}

			// request every record so both sets of calls are checked
			_, err := findAffectedPackages(m, tc.config, allRecords)

			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFindAffectedPackages_RecordLimit(t *testing.T) {
	pkgLimit := func(limit int) any {
		return mock.MatchedBy(func(actual *v6.GetPackageOptions) bool { return actual.Limit == limit })
	}
	cpeLimit := func(limit int) any {
		return mock.MatchedBy(func(actual *v6.GetCPEOptions) bool { return actual.Limit == limit })
	}
	criteria := AffectedPackagesOptions{
		Vulnerability: v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001"}},
		RecordLimit:   3,
	}

	t.Run("unaffected queries get the full limit even when the affected records already add up past it", func(t *testing.T) {
		m := new(affectedMockReader)
		defer m.AssertExpectations(t)
		// each affected query stays under the limit, but together they are over it
		m.On("GetAffectedPackages", mock.Anything, pkgLimit(3)).Return([]v6.AffectedPackageHandle{{}, {}}, nil).Once()
		m.On("GetAffectedCPEs", mock.Anything, cpeLimit(3)).Return([]v6.AffectedCPEHandle{{}, {}}, nil).Once()
		m.On("GetUnaffectedPackages", mock.Anything, pkgLimit(3)).Return([]v6.UnaffectedPackageHandle{}, nil).Once()
		m.On("GetUnaffectedCPEs", mock.Anything, cpeLimit(3)).Return([]v6.UnaffectedCPEHandle{{}}, nil).Once()

		records, err := findAffectedPackages(m, criteria, allRecords)
		require.NoError(t, err)
		assert.Len(t, records.affectedPkgs, 2)
		assert.Len(t, records.affectedCPEs, 2)
		assert.Empty(t, records.unaffectedPkgs)
		assert.Len(t, records.unaffectedCPEs, 1)
	})

	t.Run("affected records reaching the limit skip the unaffected records", func(t *testing.T) {
		m := new(affectedMockReader)
		defer m.AssertExpectations(t)
		m.On("GetAffectedPackages", mock.Anything, pkgLimit(3)).Return([]v6.AffectedPackageHandle{{}, {}, {}}, v6.ErrLimitReached).Once()

		records, err := findAffectedPackages(m, criteria, allRecords)
		require.ErrorIs(t, err, v6.ErrLimitReached)
		assert.Len(t, records.affectedPkgs, 3)
		m.AssertNotCalled(t, "GetAffectedCPEs", mock.Anything, mock.Anything)
		m.AssertNotCalled(t, "GetUnaffectedPackages", mock.Anything, mock.Anything)
		m.AssertNotCalled(t, "GetUnaffectedCPEs", mock.Anything, mock.Anything)
	})

	t.Run("unaffected records reaching the limit are kept along with the limit error", func(t *testing.T) {
		m := new(affectedMockReader)
		defer m.AssertExpectations(t)
		m.On("GetAffectedPackages", mock.Anything, pkgLimit(3)).Return([]v6.AffectedPackageHandle{{}}, nil).Once()
		m.On("GetAffectedCPEs", mock.Anything, cpeLimit(3)).Return([]v6.AffectedCPEHandle{}, nil).Once()
		m.On("GetUnaffectedPackages", mock.Anything, pkgLimit(3)).Return([]v6.UnaffectedPackageHandle{{}, {}, {}}, v6.ErrLimitReached).Once()

		records, err := findAffectedPackages(m, criteria, allRecords)
		require.ErrorIs(t, err, v6.ErrLimitReached)
		assert.Len(t, records.affectedPkgs, 1)
		assert.Len(t, records.unaffectedPkgs, 3)
		m.AssertNotCalled(t, "GetUnaffectedCPEs", mock.Anything, mock.Anything)
	})

	t.Run("errors other than the limit drop every record", func(t *testing.T) {
		m := new(affectedMockReader)
		defer m.AssertExpectations(t)
		m.On("GetAffectedPackages", mock.Anything, pkgLimit(3)).Return([]v6.AffectedPackageHandle{{}}, nil).Once()
		m.On("GetAffectedCPEs", mock.Anything, cpeLimit(3)).Return([]v6.AffectedCPEHandle{}, nil).Once()
		m.On("GetUnaffectedPackages", mock.Anything, pkgLimit(3)).Return([]v6.UnaffectedPackageHandle{{}}, assert.AnError).Once()

		records, err := findAffectedPackages(m, criteria, allRecords)
		require.ErrorIs(t, err, assert.AnError)
		assert.Equal(t, packageRecords{}, records)
	})
}

func TestFindMatches_NotAffectedOnlySkipsAffectedRecords(t *testing.T) {
	m := new(affectedMockReader)
	defer m.AssertExpectations(t)

	// only unaffected records can be not-affected, so they get the whole record limit
	m.On("GetUnaffectedPackages", mock.Anything, mock.MatchedBy(func(actual *v6.GetPackageOptions) bool {
		return actual.Limit == 5
	})).Return([]v6.UnaffectedPackageHandle{}, nil).Once()
	m.On("GetUnaffectedCPEs", mock.Anything, mock.Anything).Return([]v6.UnaffectedCPEHandle{}, nil).Once()

	_, err := FindMatches(m, AffectedPackagesOptions{
		Vulnerability: v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001"}},
		RecordLimit:   5,
		FixedStates:   []string{"not-affected"},
	})
	require.NoError(t, err)
	m.AssertNotCalled(t, "GetAffectedPackages", mock.Anything, mock.Anything)
	m.AssertNotCalled(t, "GetAffectedCPEs", mock.Anything, mock.Anything)
}

func TestPackageRecords_DecorateOncePerVulnerability(t *testing.T) {
	m := new(affectedMockReader)
	defer m.AssertExpectations(t)
	m.On("GetKnownExploitedVulnerabilities", "CVE-2024-0001").Return([]v6.KnownExploitedVulnerabilityHandle{}, nil).Once()
	m.On("GetEpss", "CVE-2024-0001").Return([]v6.EpssHandle{}, nil).Once()

	vuln := &v6.VulnerabilityHandle{ID: 1, Name: "CVE-2024-0001"}
	records := packageRecords{
		affectedPkgs:   []affectedPackageWithDecorations{{AffectedPackageHandle: v6.AffectedPackageHandle{Vulnerability: vuln}}},
		affectedCPEs:   []affectedCPEWithDecorations{{AffectedCPEHandle: v6.AffectedCPEHandle{Vulnerability: vuln}}},
		unaffectedPkgs: []affectedPackageWithDecorations{{AffectedPackageHandle: v6.AffectedPackageHandle{Vulnerability: vuln}}},
	}
	records.decorate(m)
}

type affectedMockReader struct {
	mock.Mock
}

func (m *affectedMockReader) GetVulnerabilityAliases(names []string, limit int) ([]v6.VulnerabilityAlias, error) {
	args := m.Called(names, limit)
	return args.Get(0).([]v6.VulnerabilityAlias), args.Error(1)
}

func (m *affectedMockReader) GetAffectedPackages(pkgSpec *v6.PackageSpecifier, options *v6.GetPackageOptions) ([]v6.AffectedPackageHandle, error) {
	args := m.Called(pkgSpec, options)
	return args.Get(0).([]v6.AffectedPackageHandle), args.Error(1)
}

func (m *affectedMockReader) GetUnaffectedPackages(pkgSpec *v6.PackageSpecifier, options *v6.GetPackageOptions) ([]v6.UnaffectedPackageHandle, error) {
	args := m.Called(pkgSpec, options)
	return args.Get(0).([]v6.UnaffectedPackageHandle), args.Error(1)
}

func (m *affectedMockReader) GetAffectedCPEs(cpeSpec *cpe.Attributes, options *v6.GetCPEOptions) ([]v6.AffectedCPEHandle, error) {
	args := m.Called(cpeSpec, options)
	return args.Get(0).([]v6.AffectedCPEHandle), args.Error(1)
}

func (m *affectedMockReader) GetUnaffectedCPEs(cpeSpec *cpe.Attributes, options *v6.GetCPEOptions) ([]v6.UnaffectedCPEHandle, error) {
	args := m.Called(cpeSpec, options)
	return args.Get(0).([]v6.UnaffectedCPEHandle), args.Error(1)
}

func (m *affectedMockReader) GetKnownExploitedVulnerabilities(cve string) ([]v6.KnownExploitedVulnerabilityHandle, error) {
	args := m.Called(cve)
	return args.Get(0).([]v6.KnownExploitedVulnerabilityHandle), args.Error(1)
}

func (m *affectedMockReader) GetEpss(cve string) ([]v6.EpssHandle, error) {
	args := m.Called(cve)
	return args.Get(0).([]v6.EpssHandle), args.Error(1)
}

func (m *affectedMockReader) GetCWEs(cve string) ([]v6.CWEHandle, error) {
	args := m.Called(cve)
	return args.Get(0).([]v6.CWEHandle), args.Error(1)
}

func (m *affectedMockReader) GetSsvcs(cve string) ([]v6.SsvcHandle, error) {
	args := m.Called(cve)
	return args.Get(0).([]v6.SsvcHandle), args.Error(1)
}

func ptr[T any](t T) *T {
	return &t
}

func TestGetFixStateFromPackageBlob(t *testing.T) {
	tests := []struct {
		name     string
		blob     *v6.PackageBlob
		expected string
	}{
		{
			name:     "nil blob returns unknown",
			blob:     nil,
			expected: "unknown",
		},
		{
			name:     "empty blob returns unknown",
			blob:     &v6.PackageBlob{},
			expected: "unknown",
		},
		{
			name: "blob with fixed status",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State:   v6.FixedStatus,
							Version: "1.2.3",
						},
					},
				},
			},
			expected: "fixed",
		},
		{
			name: "blob with not-fixed status",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotFixedStatus,
						},
					},
				},
			},
			expected: "not-fixed",
		},
		{
			name: "blob with wont-fix status",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.WontFixStatus,
						},
					},
				},
			},
			expected: "wont-fix",
		},
		{
			name: "blob with no fix returns unknown",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: nil,
					},
				},
			},
			expected: "unknown",
		},
		{
			name: "blob with mixed statuses prefers fixed",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotFixedStatus,
						},
					},
					{
						Fix: &v6.Fix{
							State:   v6.FixedStatus,
							Version: "2.0.0",
						},
					},
				},
			},
			expected: "fixed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFixStateFromPackageBlob(tt.blob)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterByFixedStateForPackages(t *testing.T) {
	tests := []struct {
		name        string
		packages    []affectedPackageWithDecorations
		fixedStates []string
		expectedLen int
	}{
		{
			name: "empty fixed states returns all packages",
			packages: []affectedPackageWithDecorations{
				{AffectedPackageHandle: v6.AffectedPackageHandle{BlobValue: &v6.PackageBlob{}}},
				{AffectedPackageHandle: v6.AffectedPackageHandle{BlobValue: &v6.PackageBlob{}}},
			},
			fixedStates: []string{},
			expectedLen: 2,
		},
		{
			name: "filter by fixed state",
			packages: []affectedPackageWithDecorations{
				makeAffectedPackageWithFixState(v6.FixedStatus),
				makeAffectedPackageWithFixState(v6.NotFixedStatus),
			},
			fixedStates: []string{"fixed"},
			expectedLen: 1,
		},
		{
			name: "filter by multiple states",
			packages: []affectedPackageWithDecorations{
				makeAffectedPackageWithFixState(v6.FixedStatus),
				makeAffectedPackageWithFixState(v6.NotFixedStatus),
				makeAffectedPackageWithFixState(v6.WontFixStatus),
			},
			fixedStates: []string{"fixed", "wont-fix"},
			expectedLen: 2,
		},
		{
			name: "filter with no matches",
			packages: []affectedPackageWithDecorations{
				makeAffectedPackageWithFixState(v6.NotFixedStatus),
			},
			fixedStates: []string{"fixed"},
			expectedLen: 0,
		},
		{
			name: "packages with nil blob are filtered out",
			packages: []affectedPackageWithDecorations{
				makeAffectedPackageWithFixState(v6.FixedStatus),
				{AffectedPackageHandle: v6.AffectedPackageHandle{BlobValue: nil}},
			},
			fixedStates: []string{"fixed"},
			expectedLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterByFixedStateForPackages(tt.packages, tt.fixedStates)
			assert.Equal(t, tt.expectedLen, len(result))
		})
	}
}

func TestFilterByFixedStateForCPEs(t *testing.T) {
	tests := []struct {
		name        string
		cpes        []affectedCPEWithDecorations
		fixedStates []string
		expectedLen int
	}{
		{
			name: "empty fixed states returns all CPEs",
			cpes: []affectedCPEWithDecorations{
				{AffectedCPEHandle: v6.AffectedCPEHandle{BlobValue: &v6.PackageBlob{}}},
				{AffectedCPEHandle: v6.AffectedCPEHandle{BlobValue: &v6.PackageBlob{}}},
			},
			fixedStates: []string{},
			expectedLen: 2,
		},
		{
			name: "filter by fixed state",
			cpes: []affectedCPEWithDecorations{
				makeAffectedCPEWithFixState(v6.FixedStatus),
				makeAffectedCPEWithFixState(v6.NotFixedStatus),
			},
			fixedStates: []string{"fixed"},
			expectedLen: 1,
		},
		{
			name: "filter by multiple states",
			cpes: []affectedCPEWithDecorations{
				makeAffectedCPEWithFixState(v6.FixedStatus),
				makeAffectedCPEWithFixState(v6.NotFixedStatus),
				makeAffectedCPEWithFixState(v6.WontFixStatus),
			},
			fixedStates: []string{"not-fixed", "wont-fix"},
			expectedLen: 2,
		},
		{
			name: "CPEs with nil blob are filtered out",
			cpes: []affectedCPEWithDecorations{
				makeAffectedCPEWithFixState(v6.FixedStatus),
				{AffectedCPEHandle: v6.AffectedCPEHandle{BlobValue: nil}},
			},
			fixedStates: []string{"fixed"},
			expectedLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterByFixedStateForCPEs(tt.cpes, tt.fixedStates)
			assert.Equal(t, tt.expectedLen, len(result))
		})
	}
}

func makeAffectedPackageWithFixState(state v6.FixStatus) affectedPackageWithDecorations {
	return affectedPackageWithDecorations{
		AffectedPackageHandle: v6.AffectedPackageHandle{
			BlobValue: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State:   state,
							Version: "1.0.0",
						},
					},
				},
			},
		},
	}
}

func makeAffectedCPEWithFixState(state v6.FixStatus) affectedCPEWithDecorations {
	return affectedCPEWithDecorations{
		AffectedCPEHandle: v6.AffectedCPEHandle{
			BlobValue: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State:   state,
							Version: "1.0.0",
						},
					},
				},
			},
		},
	}
}
