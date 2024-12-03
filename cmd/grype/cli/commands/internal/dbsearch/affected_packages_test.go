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
	row := AffectedPackageTableRow{
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
					RpmModularity: "modularity",
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
			Package: &v6.Package{Name: "pkg1", Type: "ecosystem1"},
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
					RpmModularity: "modularity",
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
	expected := []AffectedPackageTableRow{
		{
			Vulnerability: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "Test vulnerability"},
				Provider:          "provider1",
				Status:            "active",
				PublishedDate:     ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:      ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
			},
			AffectedPackageInfo: AffectedPackageInfo{
				OS:      &OS{Family: "Linux", Version: "5.10"},
				Package: &Package{Name: "pkg1", Ecosystem: "ecosystem1"},
				Detail: v6.AffectedPackageBlob{
					CVEs: []string{"CVE-1234-5678"},
					Qualifiers: &v6.AffectedPackageQualifiers{
						RpmModularity: "modularity",
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

	if diff := cmp.Diff(expected, rows); diff != "" {
		t.Errorf("unexpected rows (-want +got):\n%s", diff)
	}
}

func TestAffectedPackages(t *testing.T) {
	mockReader := new(affectedMockReader)

	mockReader.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{
		{
			Package: &v6.Package{Name: "pkg1", Type: "ecosystem1"},
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

	results, err := AffectedPackages(mockReader, criteria)
	require.NoError(t, err)

	expected := []AffectedPackageTableRow{
		{
			Vulnerability: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "Test vulnerability"},
				Provider:          "provider1",
				Status:            "active",
				PublishedDate:     ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:      ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
			},
			AffectedPackageInfo: AffectedPackageInfo{
				OS:      &OS{Family: "Linux", Version: "5.10"},
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

	if diff := cmp.Diff(expected, results); diff != "" {
		t.Errorf("unexpected results (-want +got):\n%s", diff)
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
