package models

import (
	"testing"

	"github.com/stretchr/testify/require"

	syftSource "github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestNewSource(t *testing.T) {
	testCases := []struct {
		name     string
		metadata syftSource.Metadata
		expected source
	}{
		{
			name: "image",
			metadata: syftSource.Metadata{
				Scheme: syftSource.ImageScheme,
				ImageMetadata: syftSource.ImageMetadata{
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
				},
			},
		},
		{
			name: "directory",
			metadata: syftSource.Metadata{
				Scheme: syftSource.DirectoryScheme,
				Path:   "/foo/bar",
			},
			expected: source{
				Type:   "directory",
				Target: "/foo/bar",
			},
		},
		{
			name: "file",
			metadata: syftSource.Metadata{
				Scheme: syftSource.FileScheme,
				Path:   "/foo/bar/test.zip",
			},
			expected: source{
				Type:   "file",
				Target: "/foo/bar/test.zip",
			},
		},
	}

	var testedSchemes []syftSource.Scheme

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := newSource(testCase.metadata)
			require.NoError(t, err)

			assert.Equal(t, testCase.expected, actual)
			testedSchemes = append(testedSchemes, testCase.metadata.Scheme)
		})
	}

	// Ensure we have test coverage for all possible syftSource.Scheme values.
	assert.ElementsMatchf(t, syftSource.AllSchemes, testedSchemes, "not all scheme values are being tested")
}
