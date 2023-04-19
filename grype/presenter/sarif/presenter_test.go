package sarif

import (
	"bytes"
	"flag"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update .golden files for sarif presenters")

func TestSarifPresenter(t *testing.T) {
	tests := []struct {
		name   string
		scheme source.Scheme
	}{
		{
			name:   "directory",
			scheme: source.DirectoryScheme,
		},
		{
			name:   "image",
			scheme: source.ImageScheme,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buffer bytes.Buffer
			matches, packages, context, metadataProvider, _, _ := models.GenerateAnalysis(t, tc.scheme)

			pb := models.PresenterConfig{
				Matches:          matches,
				Packages:         packages,
				Context:          context,
				MetadataProvider: metadataProvider,
			}

			pres := NewPresenter(pb)
			err := pres.Present(&buffer)
			if err != nil {
				t.Fatal(err)
			}

			actual := buffer.Bytes()
			if *update {
				testutils.UpdateGoldenFileContents(t, actual)
			}

			var expected = testutils.GetGoldenFileContents(t)
			actual = models.Redact(actual)
			expected = models.Redact(expected)

			if !bytes.Equal(expected, actual) {
				assert.JSONEq(t, string(expected), string(actual))
			}
		})
	}
}

func Test_locationPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		scheme   source.Scheme
		real     string
		virtual  string
		expected string
	}{
		{
			name:     "dir:.",
			scheme:   source.DirectoryScheme,
			path:     ".",
			real:     "/home/usr/file",
			virtual:  "file",
			expected: "file",
		},
		{
			name:     "dir:./",
			scheme:   source.DirectoryScheme,
			path:     "./",
			real:     "/home/usr/file",
			virtual:  "file",
			expected: "file",
		},
		{
			name:     "dir:./someplace",
			scheme:   source.DirectoryScheme,
			path:     "./someplace",
			real:     "/home/usr/file",
			virtual:  "file",
			expected: "someplace/file",
		},
		{
			name:     "dir:/someplace",
			scheme:   source.DirectoryScheme,
			path:     "/someplace",
			real:     "file",
			expected: "/someplace/file",
		},
		{
			name:     "dir:/someplace symlink",
			scheme:   source.DirectoryScheme,
			path:     "/someplace",
			real:     "/someplace/usr/file",
			virtual:  "file",
			expected: "/someplace/file",
		},
		{
			name:     "dir:/someplace absolute",
			scheme:   source.DirectoryScheme,
			path:     "/someplace",
			real:     "/usr/file",
			expected: "/usr/file",
		},
		{
			name:     "file:/someplace/file",
			scheme:   source.FileScheme,
			path:     "/someplace/file",
			real:     "/usr/file",
			expected: "/usr/file",
		},
		{
			name:     "file:/someplace/file relative",
			scheme:   source.FileScheme,
			path:     "/someplace/file",
			real:     "file",
			expected: "file",
		},
		{
			name:     "image",
			scheme:   source.ImageScheme,
			path:     "alpine:latest",
			real:     "/etc/file",
			expected: "/etc/file",
		},
		{
			name:     "image symlink",
			scheme:   source.ImageScheme,
			path:     "alpine:latest",
			real:     "/etc/elsewhere/file",
			virtual:  "/etc/file",
			expected: "/etc/file",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pres := createDirPresenter(t, test.path)
			pres.srcMetadata = &source.Metadata{
				Scheme: test.scheme,
				Path:   test.path,
			}

			path := pres.packagePath(pkg.Package{
				Locations: source.NewLocationSet(
					source.NewVirtualLocation(test.real, test.virtual),
				),
			})

			assert.Equal(t, test.expected, path)
		})
	}
}

func createDirPresenter(t *testing.T, path string) *Presenter {
	matches, packages, _, metadataProvider, _, _ := models.GenerateAnalysis(t, source.DirectoryScheme)
	s, err := source.NewFromDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		MetadataProvider: metadataProvider,
		Context: pkg.Context{
			Source: &s.Metadata,
		},
	}

	pres := NewPresenter(pb)

	return pres
}

func TestToSarifReport(t *testing.T) {
	tt := []struct {
		name      string
		scheme    source.Scheme
		locations map[string]string
	}{
		{
			name:   "directory",
			scheme: source.DirectoryScheme,
			locations: map[string]string{
				"CVE-1999-0001-package-1": "/some/path/somefile-1.txt",
				"CVE-1999-0002-package-2": "/some/path/somefile-2.txt",
			},
		},
		{
			name:   "image",
			scheme: source.ImageScheme,
			locations: map[string]string{
				"CVE-1999-0001-package-1": "image/somefile-1.txt",
				"CVE-1999-0002-package-2": "image/somefile-2.txt",
			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			matches, packages, context, metadataProvider, _, _ := models.GenerateAnalysis(t, tc.scheme)

			pb := models.PresenterConfig{
				Matches:          matches,
				Packages:         packages,
				MetadataProvider: metadataProvider,
				Context:          context,
			}

			pres := NewPresenter(pb)

			report, err := pres.toSarifReport()
			assert.NoError(t, err)

			assert.Len(t, report.Runs, 1)
			assert.NotEmpty(t, report.Runs)
			assert.NotEmpty(t, report.Runs[0].Results)
			assert.NotEmpty(t, report.Runs[0].Tool.Driver)
			assert.NotEmpty(t, report.Runs[0].Tool.Driver.Rules)

			// Sorted by vulnID, pkg name, ...
			run := report.Runs[0]
			assert.Len(t, run.Tool.Driver.Rules, 2)
			assert.Equal(t, "CVE-1999-0001-package-1", run.Tool.Driver.Rules[0].ID)
			assert.Equal(t, "CVE-1999-0002-package-2", run.Tool.Driver.Rules[1].ID)

			assert.Len(t, run.Results, 2)
			result := run.Results[0]
			assert.Equal(t, "CVE-1999-0001-package-1", *result.RuleID)
			assert.Len(t, result.Locations, 1)
			location := result.Locations[0]
			expectedLocation, ok := tc.locations[*result.RuleID]
			if !ok {
				t.Fatalf("no expected location for %s", *result.RuleID)
			}
			assert.Equal(t, expectedLocation, *location.PhysicalLocation.ArtifactLocation.URI)

			result = run.Results[1]
			assert.Equal(t, "CVE-1999-0002-package-2", *result.RuleID)
			assert.Len(t, result.Locations, 1)
			location = result.Locations[0]
			expectedLocation, ok = tc.locations[*result.RuleID]
			if !ok {
				t.Fatalf("no expected location for %s", *result.RuleID)
			}
			assert.Equal(t, expectedLocation, *location.PhysicalLocation.ArtifactLocation.URI)
		})
	}

}

type NilMetadataProvider struct{}

func (m *NilMetadataProvider) GetMetadata(_, _ string) (*vulnerability.Metadata, error) {
	return nil, nil
}

type MockMetadataProvider struct{}

func (m *MockMetadataProvider) GetMetadata(id, namespace string) (*vulnerability.Metadata, error) {
	cvss := func(id string, namespace string, scores ...float64) vulnerability.Metadata {
		values := make([]vulnerability.Cvss, len(scores))
		for _, score := range scores {
			values = append(values, vulnerability.Cvss{
				Metrics: vulnerability.CvssMetrics{
					BaseScore: score,
				},
			})
		}
		return vulnerability.Metadata{
			ID:        id,
			Namespace: namespace,
			Cvss:      values,
		}
	}
	values := []vulnerability.Metadata{
		cvss("1", "nvd:cpe", 1),
		cvss("1", "not-nvd", 2),
		cvss("2", "not-nvd", 3, 4),
	}
	for _, v := range values {
		if v.ID == id && v.Namespace == namespace {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func Test_cvssScoreWithNilMetadata(t *testing.T) {
	pres := Presenter{
		metadataProvider: &NilMetadataProvider{},
	}
	score := pres.cvssScore(vulnerability.Vulnerability{
		ID:        "id",
		Namespace: "namespace",
	})
	assert.Equal(t, float64(-1), score)
}

func Test_cvssScore(t *testing.T) {
	tests := []struct {
		name          string
		vulnerability vulnerability.Vulnerability
		expected      float64
	}{
		{
			name: "none",
			vulnerability: vulnerability.Vulnerability{
				ID: "4",
				RelatedVulnerabilities: []vulnerability.Reference{
					{
						ID:        "7",
						Namespace: "nvd:cpe",
					},
				},
			},
			expected: -1,
		},
		{
			name: "direct",
			vulnerability: vulnerability.Vulnerability{
				ID:        "2",
				Namespace: "not-nvd",
				RelatedVulnerabilities: []vulnerability.Reference{
					{
						ID:        "1",
						Namespace: "nvd:cpe",
					},
				},
			},
			expected: 4,
		},
		{
			name: "related not nvd",
			vulnerability: vulnerability.Vulnerability{
				ID:        "1",
				Namespace: "nvd:cpe",
				RelatedVulnerabilities: []vulnerability.Reference{
					{
						ID:        "1",
						Namespace: "nvd:cpe",
					},
					{
						ID:        "1",
						Namespace: "not-nvd",
					},
				},
			},
			expected: 2,
		},
		{
			name: "related nvd",
			vulnerability: vulnerability.Vulnerability{
				ID:        "4",
				Namespace: "not-nvd",
				RelatedVulnerabilities: []vulnerability.Reference{
					{
						ID:        "1",
						Namespace: "nvd:cpe",
					},
					{
						ID:        "7",
						Namespace: "not-nvd",
					},
				},
			},
			expected: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pres := Presenter{
				metadataProvider: &MockMetadataProvider{},
			}
			score := pres.cvssScore(test.vulnerability)
			assert.Equal(t, test.expected, score)
		})
	}
}
