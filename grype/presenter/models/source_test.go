package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	syftSource "github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/testutil"
)

func TestNewSource(t *testing.T) {
	// there isn't a great way to programmatically find only source metadata types in the pkg package, so we'll add them here.
	grypeOnlySources := []any{
		pkg.SBOMFileMetadata{},
		pkg.PURLLiteralMetadata{},
		pkg.CPELiteralMetadata{},
	}

	tracker := testutil.NewSourceMetadataCompletionTester(t)
	tracker.Expect(grypeOnlySources...)

	testCases := []struct {
		name     string
		metadata syftSource.Description
		expected source
	}{
		{
			name: "image",
			metadata: syftSource.Description{
				Metadata: syftSource.ImageMetadata{
					UserInput:      "abc",
					ID:             "def",
					ManifestDigest: "abcdef",
					Size:           100,
				},
			},
			expected: source{
				Type: "image",
				Target: syftSource.ImageMetadata{
					UserInput:      "abc",
					ID:             "def",
					ManifestDigest: "abcdef",
					Size:           100,
					RepoDigests:    []string{},
					Tags:           []string{},
				},
			},
		},
		{
			name: "directory",
			metadata: syftSource.Description{
				Metadata: syftSource.DirectoryMetadata{
					Path: "/foo/bar",
				},
			},
			expected: source{
				Type:   "directory",
				Target: "/foo/bar",
			},
		},
		{
			name: "file",
			metadata: syftSource.Description{
				Metadata: syftSource.FileMetadata{
					Path: "/foo/bar/test.zip",
				},
			},
			expected: source{
				Type:   "file",
				Target: "/foo/bar/test.zip",
			},
		},
		{
			name: "purl-file",
			metadata: syftSource.Description{
				Metadata: pkg.SBOMFileMetadata{
					Path: "/path/to/purls.txt",
				},
			},
			expected: source{
				Type:   "sbom-file",
				Target: "/path/to/purls.txt",
			},
		},
		{
			name: "purl-literal",
			metadata: syftSource.Description{
				Metadata: pkg.PURLLiteralMetadata{
					PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
				},
			},
			expected: source{
				Type:   "purl",
				Target: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			},
		},
		{
			name: "cpe-literal",
			metadata: syftSource.Description{
				Metadata: pkg.CPELiteralMetadata{
					CPE: "cpe:/a:apache:log4j:2.14.1",
				},
			},
			expected: source{
				Type:   "cpe",
				Target: "cpe:/a:apache:log4j:2.14.1",
			},
		},
		{
			name: "snap metadata",
			metadata: syftSource.Description{
				Name:     "a-snap",
				Version:  "10.2.3",
				Metadata: syftSource.SnapMetadata{},
			},
			expected: source{
				Type:   "snap",
				Target: "a-snap@10.2.3",
			},
		},
		{
			name: "oci metadata",
			metadata: syftSource.Description{
				Metadata: syftSource.OCIModelMetadata{
					UserInput:      "ai-model",
					ID:             "ai-model-edf",
					ManifestDigest: "abcdef",
					Size:           100,
				},
			},
			expected: source{
				Type: "oci-model",
				Target: syftSource.OCIModelMetadata{
					UserInput:      "ai-model",
					ID:             "ai-model-edf",
					ManifestDigest: "abcdef",
					Size:           100,
					RepoDigests:    []string{},
					Tags:           []string{},
				},
			},
		},
		{
			name: "nil metadata",
			metadata: syftSource.Description{
				Metadata: nil,
			},
			expected: source{
				Type:   "unknown",
				Target: "unknown",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := newSource(testCase.metadata)
			require.NoError(t, err)

			assert.Equal(t, testCase.expected, actual)
			tracker.Tested(t, testCase.metadata.Metadata)
		})
	}
}
