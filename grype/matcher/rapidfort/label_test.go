package rapidfort

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/source"
)

func TestIsRapidFortImage(t *testing.T) {
	tests := []struct {
		name     string
		src      *source.Description
		expected bool
	}{
		{
			name:     "nil source returns false",
			src:      nil,
			expected: false,
		},
		{
			name: "non-image source (no ImageMetadata) returns false",
			src: &source.Description{
				Metadata: source.DirectoryMetadata{},
			},
			expected: false,
		},
		{
			name: "image with rapidfort maintainer label matches",
			src: &source.Description{
				Metadata: source.ImageMetadata{
					Labels: map[string]string{
						"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
					},
				},
			},
			expected: true,
		},
		{
			name: "label key is case-insensitive",
			src: &source.Description{
				Metadata: source.ImageMetadata{
					Labels: map[string]string{
						"Maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
					},
				},
			},
			expected: true,
		},
		{
			name: "label value prefix is case-insensitive",
			src: &source.Description{
				Metadata: source.ImageMetadata{
					Labels: map[string]string{
						"maintainer": "RAPIDFORT Automation",
					},
				},
			},
			expected: true,
		},
		{
			name: "non-rapidfort maintainer label does not match",
			src: &source.Description{
				Metadata: source.ImageMetadata{
					Labels: map[string]string{
						"maintainer": "Other Vendor <other@example.com>",
					},
				},
			},
			expected: false,
		},
		{
			name: "image with no labels returns false",
			src: &source.Description{
				Metadata: source.ImageMetadata{
					Labels: map[string]string{},
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, IsRapidFortImage(test.src))
		})
	}
}
