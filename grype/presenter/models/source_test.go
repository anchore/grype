package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	syftSource "github.com/anchore/syft/syft/source"
)

func TestNewSource(t *testing.T) {
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
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := newSource(testCase.metadata)
			require.NoError(t, err)

			assert.Equal(t, testCase.expected, actual)
		})
	}
}
