package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

func TestHasRapidFortMarkerInResolver(t *testing.T) {
	tests := []struct {
		name     string
		resolver file.PathResolver
		expected bool
	}{
		{
			name:     "nil resolver returns false",
			resolver: nil,
			expected: false,
		},
		{
			name:     "resolver without marker returns false",
			resolver: file.NewMockResolverForPaths("/etc/os-release", "/usr/bin/ls"),
			expected: false,
		},
		{
			name:     "resolver containing the marker path returns true",
			resolver: file.NewMockResolverForPaths("/etc/os-release", RapidFortMarkerPath),
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, hasRapidFortMarkerInResolver(test.resolver))
		})
	}
}

func TestHasRapidFortMarkerInSBOM(t *testing.T) {
	tests := []struct {
		name     string
		sbom     *sbom.SBOM
		expected bool
	}{
		{
			name:     "nil SBOM returns false",
			sbom:     nil,
			expected: false,
		},
		{
			name:     "empty file catalog returns false",
			sbom:     &sbom.SBOM{Artifacts: sbom.Artifacts{FileMetadata: map[file.Coordinates]file.Metadata{}}},
			expected: false,
		},
		{
			name: "catalog without marker path returns false",
			sbom: &sbom.SBOM{Artifacts: sbom.Artifacts{FileMetadata: map[file.Coordinates]file.Metadata{
				{RealPath: "/etc/os-release"}: {},
				{RealPath: "/usr/bin/ls"}:     {},
			}}},
			expected: false,
		},
		{
			name: "catalog containing the marker path returns true",
			sbom: &sbom.SBOM{Artifacts: sbom.Artifacts{FileMetadata: map[file.Coordinates]file.Metadata{
				{RealPath: "/etc/os-release"}:   {},
				{RealPath: RapidFortMarkerPath}: {},
			}}},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, hasRapidFortMarkerInSBOM(test.sbom))
		})
	}
}
