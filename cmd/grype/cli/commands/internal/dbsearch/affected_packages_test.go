package dbsearch

import (
	"encoding/json"
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
			PublishedDate: ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
			ModifiedDate:  ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
		},
		AffectedPackageInfo: AffectedPackageInfo{
			Package: &Package{Name: "pkg1", Ecosystem: "ecosystem1"},
			CPE:     &CPE{Part: "a", Vendor: "vendor1", Product: "product1"},
			Detail: v6.AffectedPackageBlob{
				CVEs: []string{"CVE-1234-5678"},
				Qualifiers: &v6.AffectedPackageQualifiers{
					RpmModularity: ptr("modularity"),
					PlatformCPEs:  []string{"platform-cpe-1"},
				},
				Ranges: []v6.AffectedRange{
					{
						Version: v6.AffectedVersion{
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

	data, err := json.Marshal(row)
	require.NoError(t, err)

	expectedJSON := `{
		"vulnerability":{
			"id":"CVE-1234-5678",
			"description":"Test vulnerability",
			"provider":"provider1",
			"status":"active",
			"published_date":"2023-01-01T00:00:00Z",
			"modified_date":"2023-02-01T00:00:00Z"
		},
		"package":{"name":"pkg1","ecosystem":"ecosystem1"},
		"cpe":"cpe:2.3:a:vendor1:product1:*:*:*:*:*:*",
		"detail":{
			"cves":["CVE-1234-5678"],
			"qualifiers":{
				"rpm_modularity":"modularity",
				"platform_cpes":["platform-cpe-1"]
			},
			"ranges":[{
				"version":{
					"type":"semver",
					"constraint":">=1.0.0, <2.0.0"
				},
				"fix":{
					"version":"1.2.0",
					"state":"fixed"
				}
			}]
		}
	}`

	assert.JSONEq(t, expectedJSON, string(data))
}

func TestNewAffectedPackageRows(t *testing.T) {
	affectedPkgs := []v6.AffectedPackageHandle{
		{
			Package: &v6.Package{Name: "pkg1", Ecosystem: "ecosystem1"},
			OperatingSystem: &v6.OperatingSystem{
				Name:         "Linux",
				MajorVersion: "5",
				MinorVersion: "10",
			},
			Vulnerability: &v6.VulnerabilityHandle{
				Name:          "CVE-1234-5678",
				Provider:      &v6.Provider{ID: "provider1"},
				Status:        "active",
				PublishedDate: ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:  ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
				BlobValue:     &v6.VulnerabilityBlob{Description: "Test vulnerability"},
			},
			BlobValue: &v6.AffectedPackageBlob{
				CVEs: []string{"CVE-1234-5678"},
				Qualifiers: &v6.AffectedPackageQualifiers{
					RpmModularity: ptr("modularity"),
					PlatformCPEs:  []string{"platform-cpe-1"},
				},
				Ranges: []v6.AffectedRange{
					{
						Version: v6.AffectedVersion{
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

	affectedCPEs := []v6.AffectedCPEHandle{
		{
			CPE: &v6.Cpe{Part: "a", Vendor: "vendor1", Product: "product1"},
			Vulnerability: &v6.VulnerabilityHandle{
				Name:      "CVE-9876-5432",
				Provider:  &v6.Provider{ID: "provider2"},
				BlobValue: &v6.VulnerabilityBlob{Description: "CPE vulnerability description"},
			},
			BlobValue: &v6.AffectedPackageBlob{
				CVEs: []string{"CVE-9876-5432"},
				Ranges: []v6.AffectedRange{
					{
						Version: v6.AffectedVersion{
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
	}

	rows := newAffectedPackageRows(affectedPkgs, affectedCPEs)
	expected := []AffectedPackage{
		{
			Vulnerability: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "Test vulnerability"},
				Provider:          "provider1",
				Status:            "active",
				PublishedDate:     ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:      ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
			},
			AffectedPackageInfo: AffectedPackageInfo{
				OS:      &OperatingSystem{Name: "Linux", Version: "5.10"},
				Package: &Package{Name: "pkg1", Ecosystem: "ecosystem1"},
				Detail: v6.AffectedPackageBlob{
					CVEs: []string{"CVE-1234-5678"},
					Qualifiers: &v6.AffectedPackageQualifiers{
						RpmModularity: ptr("modularity"),
						PlatformCPEs:  []string{"platform-cpe-1"},
					},
					Ranges: []v6.AffectedRange{
						{
							Version: v6.AffectedVersion{
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
				Provider:          "provider2",
			},
			AffectedPackageInfo: AffectedPackageInfo{
				CPE: &CPE{Part: "a", Vendor: "vendor1", Product: "product1"},
				Detail: v6.AffectedPackageBlob{
					CVEs: []string{"CVE-9876-5432"},
					Ranges: []v6.AffectedRange{
						{
							Version: v6.AffectedVersion{
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

	if diff := cmp.Diff(expected, rows, cmpOpts()...); diff != "" {
		t.Errorf("unexpected rows (-want +got):\n%s", diff)
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
				Name:          "CVE-1234-5678",
				Provider:      &v6.Provider{ID: "provider1"},
				Status:        "active",
				PublishedDate: ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:  ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
				BlobValue:     &v6.VulnerabilityBlob{Description: "Test vulnerability"},
			},
			BlobValue: &v6.AffectedPackageBlob{
				CVEs: []string{"CVE-1234-5678"},
				Ranges: []v6.AffectedRange{
					{
						Version: v6.AffectedVersion{
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

	mockReader.On("GetAffectedCPEs", mock.Anything, mock.Anything).Return([]v6.AffectedCPEHandle{
		{
			CPE: &v6.Cpe{Part: "a", Vendor: "vendor1", Product: "product1"},
			Vulnerability: &v6.VulnerabilityHandle{
				Name:      "CVE-9876-5432",
				Provider:  &v6.Provider{ID: "provider2"},
				BlobValue: &v6.VulnerabilityBlob{Description: "CPE vulnerability description"},
			},
			BlobValue: &v6.AffectedPackageBlob{
				CVEs: []string{"CVE-9876-5432"},
				Ranges: []v6.AffectedRange{
					{
						Version: v6.AffectedVersion{
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

	criteria := AffectedPackagesOptions{
		Vulnerability: v6.VulnerabilitySpecifiers{
			{Name: "CVE-1234-5678"},
		},
	}

	results, err := FindAffectedPackages(mockReader, criteria)
	require.NoError(t, err)

	expected := []AffectedPackage{
		{
			Vulnerability: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "Test vulnerability"},
				Provider:          "provider1",
				Status:            "active",
				PublishedDate:     ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:      ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
			},
			AffectedPackageInfo: AffectedPackageInfo{
				OS:      &OperatingSystem{Name: "Linux", Version: "5.10"},
				Package: &Package{Name: "pkg1", Ecosystem: "ecosystem1"},
				Detail: v6.AffectedPackageBlob{
					CVEs: []string{"CVE-1234-5678"},
					Ranges: []v6.AffectedRange{
						{
							Version: v6.AffectedVersion{
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
				Provider:          "provider2",
			},
			AffectedPackageInfo: AffectedPackageInfo{
				CPE: &CPE{Part: "a", Vendor: "vendor1", Product: "product1"},
				Detail: v6.AffectedPackageBlob{
					CVEs: []string{"CVE-9876-5432"},
					Ranges: []v6.AffectedRange{
						{
							Version: v6.AffectedVersion{
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
}

func TestFindAffectedPackages(t *testing.T) {
	// this test is not meant to check the correctness of the results relative to the reader but instead make certain
	// that the correct calls are made to the reader based on the search criteria (we're wired up correctly).
	// Additional verifications are made to check that the combinations of different specs are handled correctly.
	type pkgCall struct {
		pkg     *v6.PackageSpecifier
		options *v6.GetAffectedPackageOptions
	}

	type cpeCall struct {
		cpe     *cpe.Attributes
		options *v6.GetAffectedCPEOptions
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
					options: &v6.GetAffectedPackageOptions{
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
					options: &v6.GetAffectedCPEOptions{
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
					options: &v6.GetAffectedPackageOptions{
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
					options: &v6.GetAffectedCPEOptions{
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
					options: &v6.GetAffectedPackageOptions{
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
					options: &v6.GetAffectedPackageOptions{
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
					options: &v6.GetAffectedPackageOptions{
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
				m.On("GetAffectedPackages", expected.pkg, mock.MatchedBy(func(actual *v6.GetAffectedPackageOptions) bool {
					return cmp.Equal(actual, expected.options)
				})).Return([]v6.AffectedPackageHandle{}, nil).Once()
			}

			for _, expected := range tc.expectedCPECalls {
				m.On("GetAffectedCPEs", expected.cpe, mock.MatchedBy(func(actual *v6.GetAffectedCPEOptions) bool {
					return cmp.Equal(actual, expected.options)
				})).Return([]v6.AffectedCPEHandle{}, nil).Once()
			}

			_, _, err := findAffectedPackages(m, tc.config)

			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type affectedMockReader struct {
	mock.Mock
}

func (m *affectedMockReader) GetAffectedPackages(pkgSpec *v6.PackageSpecifier, options *v6.GetAffectedPackageOptions) ([]v6.AffectedPackageHandle, error) {
	args := m.Called(pkgSpec, options)
	return args.Get(0).([]v6.AffectedPackageHandle), args.Error(1)
}

func (m *affectedMockReader) GetAffectedCPEs(cpeSpec *cpe.Attributes, options *v6.GetAffectedCPEOptions) ([]v6.AffectedCPEHandle, error) {
	args := m.Called(cpeSpec, options)
	return args.Get(0).([]v6.AffectedCPEHandle), args.Error(1)
}

func ptr[T any](t T) *T {
	return &t
}
