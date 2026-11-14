package dbsearch

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/vulnerability"
)

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    []v6.Severity
		expected string
	}{
		{
			name:     "empty list",
			input:    []v6.Severity{},
			expected: vulnerability.UnknownSeverity.String(),
		},
		{
			name: "string severity",
			input: []v6.Severity{
				{
					Scheme: "HML",
					Value:  "high",
					Source: "nvd@nist.gov",
					Rank:   1,
				},
			},
			expected: "high",
		},
		{
			name: "CVSS severity",
			input: []v6.Severity{
				{
					Scheme: "CVSS_V3",
					Value: CVSSSeverity{
						Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Version: "3.1",
						Metrics: CvssMetrics{
							BaseScore: 9.8,
						},
					},
					Source: "nvd@nist.gov",
					Rank:   1,
				},
			},
			expected: "critical",
		},
		{
			name: "other value type",
			input: []v6.Severity{
				{
					Scheme: "OTHER",
					Value:  42.0,
					Source: "custom",
					Rank:   1,
				},
			},
			expected: "42",
		},
		{
			name: "multiple severities",
			input: []v6.Severity{
				{
					Scheme: "HML",
					Value:  "high",
					Source: "nvd@nist.gov",
					Rank:   1,
				},
				{
					Scheme: "CVSS_V3",
					Value: CVSSSeverity{
						Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Version: "3.1",
						Metrics: CvssMetrics{
							BaseScore: 9.8,
						},
					},
					Source: "nvd@nist.gov",
					Rank:   2,
				},
			},
			expected: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := getSeverity(tt.input)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestNewVulnerabilityRows(t *testing.T) {
	vap := vulnerabilityAffectedPackageJoin{
		Vulnerability: v6.VulnerabilityHandle{
			ID:            1,
			Name:          "CVE-1234-5678",
			Status:        "active",
			PublishedDate: ptr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
			ModifiedDate:  ptr(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
			WithdrawnDate: nil,
			Provider:      &v6.Provider{ID: "provider1"},
			BlobValue: &v6.VulnerabilityBlob{
				Description: "Test description",
				Severities: []v6.Severity{
					{
						Scheme: "CVSS_V3",
						Value: CVSSSeverity{
							Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							Version: "3.1",
							Metrics: CvssMetrics{
								BaseScore: 9.8,
							},
						},
						Source: "nvd@nist.gov",
						Rank:   1,
					},
				},
			},
		},
		OperatingSystems: []v6.OperatingSystem{
			{Name: "Linux", MajorVersion: "5", MinorVersion: "10"},
		},
		AffectedPackages: 5,
		vulnerabilityDecorations: vulnerabilityDecorations{
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
	}

	rows := newVulnerabilityRows(vap)
	expected := []Vulnerability{
		{
			VulnerabilityInfo: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{
					Description: "Test description",
					Severities: []v6.Severity{
						{
							Scheme: "CVSS_V3",
							Value: CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								Version: "3.1",
								Metrics: CvssMetrics{
									BaseScore: 9.8,
								},
							},
							Source: "nvd@nist.gov",
							Rank:   1,
						},
					},
				},
				Severity:      "critical",
				Provider:      "provider1",
				Status:        "active",
				PublishedDate: ptr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:  ptr(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
				WithdrawnDate: nil,
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
			OperatingSystems: []OperatingSystem{
				{Name: "Linux", Version: "5.10"},
			},
			AffectedPackages: 5,
		},
	}

	if diff := cmp.Diff(expected, rows, cmpOpts()...); diff != "" {
		t.Errorf("unexpected rows (-want +got):\n%s", diff)
	}
}

func TestVulnerabilities(t *testing.T) {
	mockReader := new(mockVulnReader)
	vulnSpecs := v6.VulnerabilitySpecifiers{
		{Name: "CVE-1234-5678"},
	}

	mockReader.On("GetVulnerabilities", mock.Anything, mock.Anything).Return([]v6.VulnerabilityHandle{
		{
			ID:            1,
			Name:          "CVE-1234-5678",
			Status:        "active",
			PublishedDate: ptr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
			ModifiedDate:  ptr(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
			Provider:      &v6.Provider{ID: "provider1"},
			BlobValue: &v6.VulnerabilityBlob{
				Description: "Test description",
				Severities: []v6.Severity{
					{
						Scheme: v6.SeveritySchemeCVSS,
						Value: v6.CVSSSeverity{
							Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
							Version: "3.1",
						},
						Source: "nvd",
						Rank:   1,
					},
				},
			},
		},
	}, nil)

	mockReader.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{
		{
			OperatingSystem: &v6.OperatingSystem{Name: "Linux", MajorVersion: "5", MinorVersion: "10"},
		},
	}, nil)

	mockReader.On("GetUnaffectedPackages", mock.Anything, mock.Anything).Return([]v6.UnaffectedPackageHandle{
		{
			VulnerabilityID: 1,
			OperatingSystem: &v6.OperatingSystem{Name: "Linux", MajorVersion: "5", MinorVersion: "10"},
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

	mockReader.On("GetEpss", "CVE-1234-5678").Return([]v6.EpssHandle{
		{
			Cve:        "CVE-1234-5678",
			Epss:       0.893,
			Percentile: 0.99,
			Date:       time.Date(2025, 2, 24, 0, 0, 0, 0, time.UTC),
		},
	}, nil)

	results, err := FindVulnerabilities(mockReader, VulnerabilitiesOptions{Vulnerability: vulnSpecs})
	require.NoError(t, err)

	expected := []Vulnerability{
		{
			VulnerabilityInfo: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{
					Description: "Test description",
					Severities: []v6.Severity{
						{
							Scheme: "CVSS",
							Value: CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								Version: "3.1",
								Metrics: CvssMetrics{
									BaseScore:           7.5,
									ExploitabilityScore: ptr(3.9),
									ImpactScore:         ptr(3.6),
								},
							},
							Source: "nvd",
							Rank:   1,
						},
					},
				},
				Severity:      "high",
				Provider:      "provider1",
				Status:        "active",
				PublishedDate: ptr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:  ptr(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
				WithdrawnDate: nil,
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
			OperatingSystems: []OperatingSystem{
				{Name: "Linux", Version: "5.10"},
			},
			AffectedPackages:   1,
			UnaffectedPackages: 1,
		},
	}

	if diff := cmp.Diff(expected, results, cmpOpts()...); diff != "" {
		t.Errorf("unexpected results (-want +got):\n%s", diff)
	}
}

func TestFindVulnerabilities_DecorationErrors(t *testing.T) {
	tests := []struct {
		name    string
		kevErr  error
		epssErr error
	}{
		{
			name:    "EPSS error is not fatal",
			epssErr: fmt.Errorf("unable to fetch EPSS metadata: record not found"),
		},
		{
			name:   "KEV error is not fatal",
			kevErr: fmt.Errorf("unable to fetch KEV records: record not found"),
		},
		{
			name:    "both EPSS and KEV errors are not fatal",
			kevErr:  fmt.Errorf("unable to fetch KEV records: record not found"),
			epssErr: fmt.Errorf("unable to fetch EPSS metadata: record not found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockReader := new(mockVulnReader)

			mockReader.On("GetVulnerabilities", mock.Anything, mock.Anything).Return([]v6.VulnerabilityHandle{
				{
					ID:       1,
					Name:     "CVE-2021-22947",
					Status:   "active",
					Provider: &v6.Provider{ID: "nvd"},
					BlobValue: &v6.VulnerabilityBlob{
						Description: "Test vuln",
					},
				},
			}, nil)

			mockReader.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{}, nil)

			mockReader.On("GetUnaffectedPackages", mock.Anything, mock.Anything).Return([]v6.UnaffectedPackageHandle{}, nil)

			mockReader.On("GetKnownExploitedVulnerabilities", "CVE-2021-22947").Return(
				[]v6.KnownExploitedVulnerabilityHandle{}, tt.kevErr,
			)

			mockReader.On("GetEpss", "CVE-2021-22947").Return(
				[]v6.EpssHandle{}, tt.epssErr,
			)

			results, err := FindVulnerabilities(mockReader, VulnerabilitiesOptions{
				Vulnerability: v6.VulnerabilitySpecifiers{{Name: "CVE-2021-22947"}},
			})

			require.NoError(t, err, "decoration errors should not propagate as fatal errors")
			require.Len(t, results, 1)
			require.Equal(t, "Test vuln", results[0].VulnerabilityBlob.Description)
			require.Empty(t, results[0].KnownExploited)
			require.Empty(t, results[0].EPSS)
		})
	}
}

func TestFindVulnerabilities_PackageCounts(t *testing.T) {
	linux := &v6.OperatingSystem{ID: 1, Name: "linux", MajorVersion: "5"}
	debian := &v6.OperatingSystem{ID: 2, Name: "debian", MajorVersion: "12"}

	tests := []struct {
		name       string
		affected   []v6.AffectedPackageHandle
		unaffected []v6.UnaffectedPackageHandle
		want       Vulnerability
	}{
		{
			name: "no records",
			want: Vulnerability{},
		},
		{
			name:     "affected only",
			affected: []v6.AffectedPackageHandle{{OperatingSystem: linux}, {OperatingSystem: linux}},
			want:     Vulnerability{OperatingSystems: []OperatingSystem{{Name: "linux", Version: "5"}}, AffectedPackages: 2},
		},
		{
			name:       "unaffected only, which does not report the operating system as affected",
			unaffected: []v6.UnaffectedPackageHandle{{VulnerabilityID: 1, OperatingSystem: debian}},
			want:       Vulnerability{UnaffectedPackages: 1},
		},
		{
			name:       "affected and unaffected are counted separately in a single row with only affected operating systems",
			affected:   []v6.AffectedPackageHandle{{OperatingSystem: linux}},
			unaffected: []v6.UnaffectedPackageHandle{{VulnerabilityID: 1, OperatingSystem: debian}, {VulnerabilityID: 1, OperatingSystem: nil}},
			want: Vulnerability{
				OperatingSystems:   []OperatingSystem{{Name: "linux", Version: "5"}},
				AffectedPackages:   1,
				UnaffectedPackages: 2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockReader := new(mockVulnReader)
			mockReader.On("GetVulnerabilities", mock.Anything, mock.Anything).Return([]v6.VulnerabilityHandle{
				{ID: 1, Name: "CVE-2024-0001", Provider: &v6.Provider{ID: "provider1"}},
			}, nil)

			// packages are fetched for the specific vulnerability record found, not by name
			byRecordID := mock.MatchedBy(func(opts *v6.GetPackageOptions) bool {
				return len(opts.Vulnerabilities) == 1 && opts.Vulnerabilities[0].ID == 1
			})
			mockReader.On("GetAffectedPackages", mock.Anything, byRecordID).Return(tt.affected, nil).Once()
			mockReader.On("GetUnaffectedPackages", mock.Anything, byRecordID).Return(tt.unaffected, nil).Once()
			mockReader.On("GetKnownExploitedVulnerabilities", mock.Anything).Return([]v6.KnownExploitedVulnerabilityHandle{}, nil)
			mockReader.On("GetEpss", mock.Anything).Return([]v6.EpssHandle{}, nil)

			results, err := FindVulnerabilities(mockReader, VulnerabilitiesOptions{
				Vulnerability: v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001"}},
			})
			require.NoError(t, err)
			mockReader.AssertExpectations(t)

			require.Len(t, results, 1)
			assert.Equal(t, tt.want.AffectedPackages, results[0].AffectedPackages)
			assert.Equal(t, tt.want.UnaffectedPackages, results[0].UnaffectedPackages)
			assert.ElementsMatch(t, tt.want.OperatingSystems, results[0].OperatingSystems)
		})
	}
}

func TestFindVulnerabilities_LimitKeepsPartialResults(t *testing.T) {
	t.Run("unaffected counts are exact and fetched in one query for all vulnerabilities", func(t *testing.T) {
		mockReader := new(mockVulnReader)
		defer mockReader.AssertExpectations(t)
		mockReader.On("GetVulnerabilities", mock.Anything, mock.Anything).Return([]v6.VulnerabilityHandle{
			{ID: 1, Name: "CVE-2024-0001", Provider: &v6.Provider{ID: "provider1"}},
			{ID: 2, Name: "CVE-2024-0002", Provider: &v6.Provider{ID: "provider1"}},
		}, nil)
		mockReader.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{}, nil)
		// unaffected records are only counted, so nothing is preloaded, and the record limit does not cap the counts
		batched := mock.MatchedBy(func(opts *v6.GetPackageOptions) bool {
			return !opts.PreloadOS && !opts.PreloadPackage && !opts.PreloadVulnerability && !opts.PreloadBlob && opts.Limit == 0 &&
				len(opts.Vulnerabilities) == 2 && opts.Vulnerabilities[0].ID == 1 && opts.Vulnerabilities[1].ID == 2
		})
		mockReader.On("GetUnaffectedPackages", mock.Anything, batched).Return([]v6.UnaffectedPackageHandle{
			{VulnerabilityID: 1}, {VulnerabilityID: 1}, {VulnerabilityID: 2},
		}, nil).Once()
		mockReader.On("GetKnownExploitedVulnerabilities", mock.Anything).Return([]v6.KnownExploitedVulnerabilityHandle{}, nil)
		mockReader.On("GetEpss", mock.Anything).Return([]v6.EpssHandle{}, nil)

		results, err := FindVulnerabilities(mockReader, VulnerabilitiesOptions{
			Vulnerability: v6.VulnerabilitySpecifiers{{Name: "CVE-2024"}},
			RecordLimit:   2,
		})
		require.NoError(t, err)
		require.Len(t, results, 2)
		counts := map[string]int{}
		for _, r := range results {
			counts[r.Model.Name] = r.UnaffectedPackages
		}
		assert.Equal(t, map[string]int{"CVE-2024-0001": 2, "CVE-2024-0002": 1}, counts)
	})

	t.Run("vulnerabilities found before the limit are kept", func(t *testing.T) {
		mockReader := new(mockVulnReader)
		mockReader.On("GetVulnerabilities", mock.Anything, mock.Anything).Return([]v6.VulnerabilityHandle{
			{ID: 1, Name: "CVE-2024-0001", Provider: &v6.Provider{ID: "provider1"}},
		}, v6.ErrLimitReached)
		mockReader.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{}, nil)
		mockReader.On("GetUnaffectedPackages", mock.Anything, mock.Anything).Return([]v6.UnaffectedPackageHandle{}, nil)
		mockReader.On("GetKnownExploitedVulnerabilities", mock.Anything).Return([]v6.KnownExploitedVulnerabilityHandle{}, nil)
		mockReader.On("GetEpss", mock.Anything).Return([]v6.EpssHandle{}, nil)

		results, err := FindVulnerabilities(mockReader, VulnerabilitiesOptions{
			Vulnerability: v6.VulnerabilitySpecifiers{{Name: "CVE-2024"}},
			RecordLimit:   1,
		})
		require.ErrorIs(t, err, v6.ErrLimitReached)
		require.Len(t, results, 1)
	})

	t.Run("affected packages found before the limit are still counted", func(t *testing.T) {
		linux := &v6.OperatingSystem{ID: 1, Name: "linux", MajorVersion: "5"}
		mockReader := new(mockVulnReader)
		mockReader.On("GetVulnerabilities", mock.Anything, mock.Anything).Return([]v6.VulnerabilityHandle{
			{ID: 1, Name: "CVE-2024-0001", Provider: &v6.Provider{ID: "provider1"}},
		}, nil)
		mockReader.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{
			{OperatingSystem: linux}, {OperatingSystem: linux},
		}, v6.ErrLimitReached)
		mockReader.On("GetUnaffectedPackages", mock.Anything, mock.Anything).Return([]v6.UnaffectedPackageHandle{}, nil)
		mockReader.On("GetKnownExploitedVulnerabilities", mock.Anything).Return([]v6.KnownExploitedVulnerabilityHandle{}, nil)
		mockReader.On("GetEpss", mock.Anything).Return([]v6.EpssHandle{}, nil)

		results, err := FindVulnerabilities(mockReader, VulnerabilitiesOptions{
			Vulnerability: v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001"}},
			RecordLimit:   2,
		})
		require.ErrorIs(t, err, v6.ErrLimitReached)
		require.Len(t, results, 1)
		assert.Equal(t, 2, results[0].AffectedPackages)
		assert.Equal(t, []OperatingSystem{{Name: "linux", Version: "5"}}, results[0].OperatingSystems)
	})

	t.Run("the record limit caps vulnerabilities across all specs", func(t *testing.T) {
		mockReader := new(mockVulnReader)
		defer mockReader.AssertExpectations(t)
		limitIs := func(limit int) any {
			return mock.MatchedBy(func(opts *v6.GetVulnerabilityOptions) bool { return opts.Limit == limit })
		}
		mockReader.On("GetVulnerabilities", &v6.VulnerabilitySpecifier{Name: "CVE-2024-0001"}, limitIs(3)).Return([]v6.VulnerabilityHandle{
			{ID: 1, Name: "CVE-2024-0001", Provider: &v6.Provider{ID: "provider1"}},
			{ID: 2, Name: "CVE-2024-0001", Provider: &v6.Provider{ID: "provider2"}},
		}, nil).Once()
		// the second spec only gets what is left of the limit
		mockReader.On("GetVulnerabilities", &v6.VulnerabilitySpecifier{Name: "CVE-2024-0002"}, limitIs(1)).Return([]v6.VulnerabilityHandle{
			{ID: 3, Name: "CVE-2024-0002", Provider: &v6.Provider{ID: "provider1"}},
		}, v6.ErrLimitReached).Once()
		mockReader.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{}, nil)
		mockReader.On("GetUnaffectedPackages", mock.Anything, mock.Anything).Return([]v6.UnaffectedPackageHandle{}, nil)
		mockReader.On("GetKnownExploitedVulnerabilities", mock.Anything).Return([]v6.KnownExploitedVulnerabilityHandle{}, nil)
		mockReader.On("GetEpss", mock.Anything).Return([]v6.EpssHandle{}, nil)

		results, err := FindVulnerabilities(mockReader, VulnerabilitiesOptions{
			Vulnerability: v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001"}, {Name: "CVE-2024-0002"}, {Name: "CVE-2024-0003"}},
			RecordLimit:   3,
		})
		require.ErrorIs(t, err, v6.ErrLimitReached)
		require.Len(t, results, 3)
	})
}

type mockVulnReader struct {
	mock.Mock
}

func (m *mockVulnReader) GetVulnerabilities(vuln *v6.VulnerabilitySpecifier, config *v6.GetVulnerabilityOptions) ([]v6.VulnerabilityHandle, error) {
	args := m.Called(vuln, config)
	return args.Get(0).([]v6.VulnerabilityHandle), args.Error(1)
}

func (m *mockVulnReader) GetVulnerabilityAliases(names []string, limit int) ([]v6.VulnerabilityAlias, error) {
	args := m.Called(names, limit)
	return args.Get(0).([]v6.VulnerabilityAlias), args.Error(1)
}

func (m *mockVulnReader) GetAffectedPackages(pkg *v6.PackageSpecifier, config *v6.GetPackageOptions) ([]v6.AffectedPackageHandle, error) {
	args := m.Called(pkg, config)
	return args.Get(0).([]v6.AffectedPackageHandle), args.Error(1)
}

func (m *mockVulnReader) GetUnaffectedPackages(pkg *v6.PackageSpecifier, config *v6.GetPackageOptions) ([]v6.UnaffectedPackageHandle, error) {
	args := m.Called(pkg, config)
	return args.Get(0).([]v6.UnaffectedPackageHandle), args.Error(1)
}

func (m *mockVulnReader) GetKnownExploitedVulnerabilities(cve string) ([]v6.KnownExploitedVulnerabilityHandle, error) {
	args := m.Called(cve)
	return args.Get(0).([]v6.KnownExploitedVulnerabilityHandle), args.Error(1)
}

func (m *mockVulnReader) GetEpss(cve string) ([]v6.EpssHandle, error) {
	args := m.Called(cve)
	return args.Get(0).([]v6.EpssHandle), args.Error(1)
}

func (m *mockVulnReader) GetCWEs(cve string) ([]v6.CWEHandle, error) {
	args := m.Called(cve)
	return args.Get(0).([]v6.CWEHandle), args.Error(1)
}

func (m *mockVulnReader) GetSsvcs(cve string) ([]v6.SsvcHandle, error) {
	args := m.Called(cve)
	return args.Get(0).([]v6.SsvcHandle), args.Error(1)
}

func cmpOpts() []cmp.Option {
	return []cmp.Option{
		cmpopts.IgnoreFields(AffectedPackageInfo{}, "Model"),
		cmpopts.IgnoreFields(VulnerabilityInfo{}, "Model"),
	}
}

// unaffectedByID returns one unaffected record for each vulnerability ID asked for
type unaffectedByID struct{}

func (unaffectedByID) GetUnaffectedPackages(_ *v6.PackageSpecifier, config *v6.GetPackageOptions) ([]v6.UnaffectedPackageHandle, error) {
	var found []v6.UnaffectedPackageHandle
	for _, spec := range config.Vulnerabilities {
		found = append(found, v6.UnaffectedPackageHandle{VulnerabilityID: spec.ID})
	}
	return found, nil
}

func TestCountUnaffectedPackages_DuplicateVulnerabilities(t *testing.T) {
	// the repeated vulnerability lands in a different batch than its first occurrence
	var pairs []vulnerabilityAffectedPackageJoin
	for id := range unaffectedCountBatchSize + 1 {
		pairs = append(pairs, vulnerabilityAffectedPackageJoin{Vulnerability: v6.VulnerabilityHandle{ID: v6.ID(id + 1)}})
	}
	pairs = append(pairs, pairs[0])

	counts, err := countUnaffectedPackages(unaffectedByID{}, pairs)
	require.NoError(t, err)
	assert.Len(t, counts, unaffectedCountBatchSize+1)
	assert.Equal(t, 1, counts[1])
}
