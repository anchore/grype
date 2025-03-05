package sarif

import (
	"bytes"
	"flag"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

var updateSnapshot = flag.Bool("update-sarif", false, "update .golden files for sarif presenters")
var validatorImage = "ghcr.io/anchore/sarif-validator:0.1.0@sha256:a0729d695e023740f5df6bcb50d134e88149bea59c63a896a204e88f62b564c6"

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
		tc := tc
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

			if !bytes.Equal(expected, actual) {
				assert.JSONEq(t, string(expected), string(actual))
			}
		})
	}
}

func Test_SarifIsValid(t *testing.T) {
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

			cmd := exec.Command("docker", "run", "--rm", "-i", validatorImage)

			out := bytes.Buffer{}
			cmd.Stdout = &out
			cmd.Stderr = &out

			// pipe to the docker command
			cmd.Stdin = &buffer

			err = cmd.Run()
			if err != nil || cmd.ProcessState.ExitCode() != 0 {
				// valid
				t.Fatalf("error validating SARIF document: %s", out.String())
			}
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
		tc := tc
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
