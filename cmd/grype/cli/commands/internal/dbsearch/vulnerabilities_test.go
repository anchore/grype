package dbsearch

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestNewVulnerabilityRows(t *testing.T) {
	vap := vulnerabilityAffectedPackageJoin{
		Vulnerability: v6.VulnerabilityHandle{
			ID:            1,
			Name:          "CVE-1234-5678",
			Status:        "active",
			PublishedDate: ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
			ModifiedDate:  ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
			WithdrawnDate: nil,
			Provider:      &v6.Provider{ID: "provider1"},
			BlobValue:     &v6.VulnerabilityBlob{Description: "Test description"},
		},
		OperatingSystems: []v6.OperatingSystem{
			{Name: "Linux", MajorVersion: "5", MinorVersion: "10"},
		},
		AffectedPackages: 5,
	}

	rows := newVulnerabilityRows(vap)
	expected := []Vulnerability{
		{
			VulnerabilityInfo: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "Test description"},
				Provider:          "provider1",
				Status:            "active",
				PublishedDate:     ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:      ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
				WithdrawnDate:     nil,
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
			PublishedDate: ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
			ModifiedDate:  ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
			Provider:      &v6.Provider{ID: "provider1"},
			BlobValue:     &v6.VulnerabilityBlob{Description: "Test description"},
		},
	}, nil)

	mockReader.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{
		{
			OperatingSystem: &v6.OperatingSystem{Name: "Linux", MajorVersion: "5", MinorVersion: "10"},
		},
	}, nil)

	results, err := FindVulnerabilities(mockReader, VulnerabilitiesOptions{Vulnerability: vulnSpecs})
	require.NoError(t, err)

	expected := []Vulnerability{
		{
			VulnerabilityInfo: VulnerabilityInfo{
				VulnerabilityBlob: v6.VulnerabilityBlob{Description: "Test description"},
				Provider:          "provider1",
				Status:            "active",
				PublishedDate:     ptrTime(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				ModifiedDate:      ptrTime(time.Date(2023, 2, 1, 0, 0, 0, 0, time.UTC)),
				WithdrawnDate:     nil,
			},
			OperatingSystems: []OperatingSystem{
				{Name: "Linux", Version: "5.10"},
			},
			AffectedPackages: 1,
		},
	}

	if diff := cmp.Diff(expected, results, cmpOpts()...); diff != "" {
		t.Errorf("unexpected results (-want +got):\n%s", diff)
	}
}

type mockVulnReader struct {
	mock.Mock
}

func (m *mockVulnReader) GetVulnerabilities(vuln *v6.VulnerabilitySpecifier, config *v6.GetVulnerabilityOptions) ([]v6.VulnerabilityHandle, error) {
	args := m.Called(vuln, config)
	return args.Get(0).([]v6.VulnerabilityHandle), args.Error(1)
}

func (m *mockVulnReader) GetAffectedPackages(pkg *v6.PackageSpecifier, config *v6.GetAffectedPackageOptions) ([]v6.AffectedPackageHandle, error) {
	args := m.Called(pkg, config)
	return args.Get(0).([]v6.AffectedPackageHandle), args.Error(1)
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func cmpOpts() []cmp.Option {
	return []cmp.Option{
		cmpopts.IgnoreFields(AffectedPackageInfo{}, "Model"),
		cmpopts.IgnoreFields(VulnerabilityInfo{}, "Model"),
	}
}
