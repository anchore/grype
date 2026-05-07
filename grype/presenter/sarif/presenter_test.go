package sarif

import (
	"bytes"
	"flag"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal/testutils"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

var updateSnapshot = flag.Bool("update", false, "update .golden files for sarif presenters")

func TestSarifPresenter(t *testing.T) {
	tests := []struct {
		name   string
		scheme internal.SyftSource
	}{
		{
			name:   "directory",
			scheme: internal.DirectorySource,
		},
		{
			name:   "image",
			scheme: internal.ImageSource,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buffer bytes.Buffer

			pb := internal.GeneratePresenterConfig(t, tc.scheme)

			pres := NewPresenter(pb)
			err := pres.Present(&buffer)
			if err != nil {
				t.Fatal(err)
			}

			actual := buffer.Bytes()
			if *updateSnapshot {
				testutils.UpdateGoldenFileContents(t, actual)
			}

			var expected = testutils.GetGoldenFileContents(t)
			actual = internal.Redact(actual)
			expected = internal.Redact(expected)

			if d := cmp.Diff(string(expected), string(actual)); d != "" {
				t.Fatalf("(-want +got):\n%s", d)
			}
		})
	}
}

func Test_SarifIsValid(t *testing.T) {
	sch, err := jsonschema.NewCompiler().Compile("testdata/sarif-schema-2.1.0.json")
	require.NoError(t, err)

	tests := []struct {
		name   string
		scheme internal.SyftSource
	}{
		{
			name:   "directory",
			scheme: internal.DirectorySource,
		},
		{
			name:   "image",
			scheme: internal.ImageSource,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buffer bytes.Buffer

			pb := internal.GeneratePresenterConfig(t, tc.scheme)

			pres := NewPresenter(pb)
			err := pres.Present(&buffer)
			require.NoError(t, err)

			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(buffer.Bytes()))
			require.NoError(t, err)

			err = sch.Validate(inst)
			require.NoError(t, err, "SARIF output does not conform to schema")
		})
	}
}

func Test_locationPath(t *testing.T) {
	tests := []struct {
		name     string
		metadata any
		real     string
		virtual  string
		expected string
	}{
		{
			name: "dir:.",
			metadata: source.DirectoryMetadata{
				Path: ".",
			},
			real:     "/home/usr/file",
			virtual:  "file",
			expected: "file",
		},
		{
			name: "dir:./",
			metadata: source.DirectoryMetadata{
				Path: "./",
			},
			real:     "/home/usr/file",
			virtual:  "file",
			expected: "file",
		},
		{
			name: "dir:./someplace",
			metadata: source.DirectoryMetadata{
				Path: "./someplace",
			},
			real:     "/home/usr/file",
			virtual:  "file",
			expected: "someplace/file",
		},
		{
			name: "dir:/someplace",
			metadata: source.DirectoryMetadata{
				Path: "/someplace",
			},
			real:     "file",
			expected: "/someplace/file",
		},
		{
			name: "dir:/someplace symlink",
			metadata: source.DirectoryMetadata{
				Path: "/someplace",
			},
			real:     "/someplace/usr/file",
			virtual:  "file",
			expected: "/someplace/file",
		},
		{
			name: "dir:/someplace absolute",
			metadata: source.DirectoryMetadata{
				Path: "/someplace",
			},
			real:     "/usr/file",
			expected: "/usr/file",
		},
		{
			name: "file:/someplace/file",
			metadata: source.FileMetadata{
				Path: "/someplace/file",
			},
			real:     "/usr/file",
			expected: "/usr/file",
		},
		{
			name: "file:/someplace/file relative",
			metadata: source.FileMetadata{
				Path: "/someplace/file",
			},
			real:     "file",
			expected: "file",
		},
		{
			name: "image",
			metadata: source.ImageMetadata{
				UserInput: "alpine:latest",
			},
			real:     "/etc/file",
			expected: "/etc/file",
		},
		{
			name: "image symlink",
			metadata: source.ImageMetadata{
				UserInput: "alpine:latest",
			},
			real:     "/etc/elsewhere/file",
			virtual:  "/etc/file",
			expected: "/etc/file",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pres := createDirPresenter(t)
			pres.src = source.Description{
				Metadata: test.metadata,
			}

			path := pres.packagePath(models.Package{
				Locations: file.NewLocationSet(
					file.NewVirtualLocation(test.real, test.virtual),
				).ToSlice(),
			})

			assert.Equal(t, test.expected, path)
		})
	}
}

func createDirPresenter(t *testing.T) *Presenter {
	d := t.TempDir()
	newSrc, err := directorysource.NewFromPath(d)
	if err != nil {
		t.Fatal(err)
	}

	pb := internal.GeneratePresenterConfig(t, internal.DirectorySource)
	pb.SBOM.Source = newSrc.Describe()

	pres := NewPresenter(pb)

	return pres
}

func TestToSarifReport(t *testing.T) {
	tt := []struct {
		name      string
		scheme    internal.SyftSource
		locations map[string]string
	}{
		{
			name:   "directory",
			scheme: internal.DirectorySource,
			locations: map[string]string{
				"CVE-1999-0001-package-1": "/some/path/somefile-1.txt",
				"CVE-1999-0002-package-2": "/some/path/somefile-2.txt",
			},
		},
		{
			name:   "image",
			scheme: internal.ImageSource,
			locations: map[string]string{
				"CVE-1999-0001-package-1": "user-input/somefile-1.txt",
				"CVE-1999-0002-package-2": "user-input/somefile-2.txt",
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pb := internal.GeneratePresenterConfig(t, tc.scheme)

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
			assert.Equal(t, "note", *result.Level)
			assert.Len(t, result.Locations, 1)
			location := result.Locations[0]
			expectedLocation, ok := tc.locations[*result.RuleID]
			if !ok {
				t.Fatalf("no expected location for %s", *result.RuleID)
			}
			assert.Equal(t, expectedLocation, *location.PhysicalLocation.ArtifactLocation.URI)

			result = run.Results[1]
			assert.Equal(t, "CVE-1999-0002-package-2", *result.RuleID)
			assert.Equal(t, "error", *result.Level)
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

func Test_cvssScoreWithMissingMetadata(t *testing.T) {
	score := cvssScore(models.Match{
		Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:        "id",
				Namespace: "namespace",
			},
		},
	})
	assert.Equal(t, float64(-1), score)
}

func Test_cvssScore(t *testing.T) {

	cvss := func(id string, namespace string, scores ...float64) models.VulnerabilityMetadata {
		values := make([]models.Cvss, 0, len(scores))
		for _, score := range scores {
			values = append(values, models.Cvss{
				Metrics: models.CvssMetrics{
					BaseScore: score,
				},
			})
		}
		return models.VulnerabilityMetadata{
			ID:        id,
			Namespace: namespace,
			Cvss:      values,
		}
	}

	nvd1 := cvss("1", "nvd:cpe", 1)
	notNvd1 := cvss("1", "not-nvd", 2)
	notNvd2 := cvss("2", "not-nvd", 3, 4)

	tests := []struct {
		name     string
		match    models.Match
		expected float64
	}{
		{
			name: "none",
			match: models.Match{
				Vulnerability: models.Vulnerability{
					VulnerabilityMetadata: models.VulnerabilityMetadata{
						ID: "4",
					},
				},
				RelatedVulnerabilities: []models.VulnerabilityMetadata{
					{
						ID:        "7",
						Namespace: "nvd:cpe",
						// intentionally missing info...
					},
				},
			},
			expected: -1,
		},
		{
			name: "direct",
			match: models.Match{
				Vulnerability: models.Vulnerability{
					VulnerabilityMetadata: notNvd2,
				},
				RelatedVulnerabilities: []models.VulnerabilityMetadata{
					nvd1,
				},
			},
			expected: 4,
		},
		{
			name: "related not nvd",
			match: models.Match{
				Vulnerability: models.Vulnerability{
					VulnerabilityMetadata: nvd1,
				},
				RelatedVulnerabilities: []models.VulnerabilityMetadata{
					nvd1,
					notNvd1,
				},
			},
			expected: 2,
		},
		{
			name: "related nvd",
			match: models.Match{
				Vulnerability: models.Vulnerability{
					VulnerabilityMetadata: models.VulnerabilityMetadata{
						ID:        "4",
						Namespace: "not-nvd",
						// intentionally missing info...
					},
				},
				RelatedVulnerabilities: []models.VulnerabilityMetadata{
					nvd1,
					{
						ID:        "7",
						Namespace: "not-nvd",
						// intentionally missing info...
					},
				},
			},
			expected: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			score := cvssScore(test.match)
			assert.Equal(t, test.expected, score)
		})
	}
}

func Test_helpURI(t *testing.T) {
	tests := []struct {
		name       string
		dataSource string
		urls       []string
		expected   string
	}{
		{
			name:       "dataSource preferred over urls",
			dataSource: "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
			urls:       []string{"https://example.com/advisory"},
			expected:   "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
		},
		{
			name:     "first url used when no dataSource",
			urls:     []string{"https://github.com/advisories/GHSA-xxxx-yyyy-zzzz", "https://example.com/other"},
			expected: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
		},
		{
			name:       "dataSource used when no urls",
			dataSource: "https://nvd.nist.gov/vuln/detail/CVE-2021-5678",
			expected:   "https://nvd.nist.gov/vuln/detail/CVE-2021-5678",
		},
		{
			name:     "fallback to grype repo when no dataSource or urls",
			expected: "https://github.com/anchore/grype",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := models.Match{
				Vulnerability: models.Vulnerability{
					VulnerabilityMetadata: models.VulnerabilityMetadata{
						ID:         "CVE-2021-0000",
						DataSource: tc.dataSource,
						URLs:       tc.urls,
					},
				},
			}
			assert.Equal(t, tc.expected, helpURI(m))
		})
	}
}

func Test_imageShortPathName(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		expected string
	}{
		{
			name:     "valid single name",
			in:       "simple.-_name",
			expected: "simple.-_name",
		},
		{
			name:     "valid name in org",
			in:       "some-org/some-image",
			expected: "some-image",
		},
		{
			name:     "name and org with many invalid chars",
			in:       "some/*^&$#%$#@*(}{<><./,valid-()(#)@!(~@#$#%^&**[]{-chars",
			expected: "valid--chars",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := imageShortPathName(
				source.Description{
					Name:     test.in,
					Metadata: nil,
				},
			)

			assert.Equal(t, test.expected, got)
		})
	}
}
