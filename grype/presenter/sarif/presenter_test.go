package sarif

import (
	"bytes"
	"flag"
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/imagetest"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for sarif presenters")

func createResults() (match.Matches, []pkg.Package) {

	pkg1 := pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
		Locations: source.NewLocationSet(
			source.Location{
				Coordinates: source.Coordinates{
					RealPath:     "etc/pkg-1",
					FileSystemID: "sha256:asdf",
				},
			},
		),
	}
	pkg2 := pkg.Package{
		ID:      "package-2-id",
		Name:    "package-2",
		Version: "2.0.1",
		Type:    syftPkg.DebPkg,
		Licenses: []string{
			"MIT",
			"Apache-v2",
		},
		Locations: source.NewLocationSet(
			source.Location{
				Coordinates: source.Coordinates{
					RealPath:     "pkg-2",
					FileSystemID: "sha256:asdf",
				},
			},
		),
	}

	var match1 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0001",
			Namespace: "source-1",
		},
		Package: pkg1,
		Details: []match.Detail{
			{
				Type:    match.ExactDirectMatch,
				Matcher: match.DpkgMatcher,
			},
		},
	}

	var match2 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0002",
			Namespace: "source-2",
		},
		Package: pkg2,
		Details: []match.Detail{
			{
				Type:    match.ExactIndirectMatch,
				Matcher: match.DpkgMatcher,
				SearchedBy: map[string]interface{}{
					"some": "key",
				},
			},
		},
	}

	matches := match.NewMatches()

	matches.Add(match1, match2)

	return matches, []pkg.Package{pkg1, pkg2}
}

func createImagePresenter(t *testing.T) *Presenter {
	matches, packages := createResults()

	img := imagetest.GetFixtureImage(t, "docker-archive", "image-simple")
	s, err := source.NewFromImage(img, "user-input")
	if err != nil {
		t.Fatal(err)
	}

	// This accounts for the non-deterministic digest value that we end up with when
	// we build a container image dynamically during testing. Ultimately, we should
	// use a golden image as a test fixture in place of building this image during
	// testing. At that time, this line will no longer be necessary.
	//
	// This value is sourced from the "version" node in "./test-fixtures/snapshot/TestSarifImgsPresenter.golden"
	s.Metadata.ImageMetadata.ManifestDigest = "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368"

	pres := NewPresenter(matches, packages, &s.Metadata, models.NewMetadataMock())

	return pres
}

func createDirPresenter(t *testing.T, path string) *Presenter {
	matches, packages := createResults()

	s, err := source.NewFromDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	pres := NewPresenter(matches, packages, &s.Metadata, models.NewMetadataMock())

	return pres
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
					source.Location{
						Coordinates: source.Coordinates{
							RealPath: test.real,
						},
						VirtualPath: test.virtual,
					},
				),
			})

			assert.Equal(t, test.expected, path)
		})
	}
}

func Test_imageToSarifReport(t *testing.T) {
	pres := createImagePresenter(t)
	s, err := pres.toSarifReport()
	assert.NoError(t, err)

	assert.Len(t, s.Runs, 1)

	run := s.Runs[0]

	// Sorted by vulnID, pkg name, ...
	assert.Len(t, run.Tool.Driver.Rules, 2)
	assert.Equal(t, "CVE-1999-0001-package-1", run.Tool.Driver.Rules[0].ID)
	assert.Equal(t, "CVE-1999-0002-package-2", run.Tool.Driver.Rules[1].ID)

	assert.Len(t, run.Results, 2)
	result := run.Results[0]
	assert.Equal(t, "CVE-1999-0001-package-1", *result.RuleID)
	assert.Len(t, result.Locations, 1)
	location := result.Locations[0]
	assert.Equal(t, "image/etc/pkg-1", *location.PhysicalLocation.ArtifactLocation.URI)

	result = run.Results[1]
	assert.Equal(t, "CVE-1999-0002-package-2", *result.RuleID)
	assert.Len(t, result.Locations, 1)
	location = result.Locations[0]
	assert.Equal(t, "image/pkg-2", *location.PhysicalLocation.ArtifactLocation.URI)
}

func Test_dirToSarifReport(t *testing.T) {
	pres := createDirPresenter(t, "/abs/path")
	s, err := pres.toSarifReport()
	assert.NoError(t, err)

	assert.Len(t, s.Runs, 1)

	run := s.Runs[0]

	// Sorted by vulnID, pkg name, ...
	assert.Len(t, run.Tool.Driver.Rules, 2)
	assert.Equal(t, "CVE-1999-0001-package-1", run.Tool.Driver.Rules[0].ID)
	assert.Equal(t, "CVE-1999-0002-package-2", run.Tool.Driver.Rules[1].ID)

	assert.Len(t, run.Results, 2)
	result := run.Results[0]
	assert.Equal(t, "CVE-1999-0001-package-1", *result.RuleID)
	assert.Len(t, result.Locations, 1)
	location := result.Locations[0]
	assert.Equal(t, "/abs/path/etc/pkg-1", *location.PhysicalLocation.ArtifactLocation.URI)

	result = run.Results[1]
	assert.Equal(t, "CVE-1999-0002-package-2", *result.RuleID)
	assert.Len(t, result.Locations, 1)
	location = result.Locations[0]
	assert.Equal(t, "/abs/path/pkg-2", *location.PhysicalLocation.ArtifactLocation.URI)
}

func TestSarifPresenterImage(t *testing.T) {
	var buffer bytes.Buffer

	pres := createImagePresenter(t)

	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}

	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which are tested independently
	actual = redact(actual)
	expected = redact(expected)

	assert.JSONEq(t, string(expected), string(actual))
}

func TestSarifPresenterDir(t *testing.T) {
	var buffer bytes.Buffer
	pres := createDirPresenter(t, ".")

	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}

	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which are tested independently
	actual = redact(actual)
	expected = redact(expected)

	assert.JSONEq(t, string(expected), string(actual))
}

func redact(s []byte) []byte {
	for _, pattern := range []*regexp.Regexp{} {
		s = pattern.ReplaceAll(s, []byte("redacted"))
	}
	return s
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
		cvss("1", "nvd", 1),
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
						Namespace: "nvd",
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
						Namespace: "nvd",
					},
				},
			},
			expected: 4,
		},
		{
			name: "related not nvd",
			vulnerability: vulnerability.Vulnerability{
				ID:        "1",
				Namespace: "nvd",
				RelatedVulnerabilities: []vulnerability.Reference{
					{
						ID:        "1",
						Namespace: "nvd",
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
						Namespace: "nvd",
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
