package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
)

func TestUpstreamPackages(t *testing.T) {
	tests := []struct {
		name     string
		pkg      Package
		expected []Package
	}{
		{
			name: "no upstreams results in empty list",
			pkg: Package{
				Name:    "name",
				Version: "version",
			},
			expected: nil,
		},
		{
			name: "with upstream name",
			pkg: Package{
				Name:    "name",
				Version: "version",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:name:name:version:*:*:*:*:*:*:*", ""),
				},
				Upstreams: []UpstreamPackage{
					{
						Name: "new-name",
					},
				},
			},
			expected: []Package{
				{
					Name:    "new-name", // new
					Version: "version",  // original
					CPEs: []cpe.CPE{
						// name and vendor replaced
						cpe.Must("cpe:2.3:*:new-name:new-name:version:*:*:*:*:*:*:*", ""),
					},
					// no upstreams
				},
			},
		},
		{
			name: "with upstream name and version",
			pkg: Package{
				Name:    "name",
				Version: "version",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:name:name:version:*:*:*:*:*:*:*", ""),
				},
				Upstreams: []UpstreamPackage{
					{
						Name:    "new-name",
						Version: "new-version",
					},
				},
			},
			expected: []Package{
				{
					Name:    "new-name",    // new
					Version: "new-version", // new
					CPEs: []cpe.CPE{
						// name, vendor, and version replaced
						cpe.Must("cpe:2.3:*:new-name:new-name:new-version:*:*:*:*:*:*:*", ""),
					},
					// no upstreams
				},
			},
		},
		{
			name: "no upstream name results in no package",
			pkg: Package{
				Name:    "name",
				Version: "version",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:name:name:version:*:*:*:*:*:*:*", ""),
				},
				Upstreams: []UpstreamPackage{
					{
						// note: invalid without a name
						Version: "new-version",
					},
				},
			},
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actual []Package
			actual = append(actual, UpstreamPackages(tt.pkg)...)
			assert.Equalf(t, tt.expected, actual, "UpstreamPackages(%v)", tt.pkg)
		})
	}
}
