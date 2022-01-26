package pkg

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
	"testing"
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
				CPEs: []pkg.CPE{
					must(pkg.NewCPE("cpe:2.3:*:name:name:version:*:*:*:*:*:*:*")),
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
					CPEs: []pkg.CPE{
						// name and vendor replaced
						must(pkg.NewCPE("cpe:2.3:*:new-name:new-name:version:*:*:*:*:*:*:*")),
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
				CPEs: []pkg.CPE{
					must(pkg.NewCPE("cpe:2.3:*:name:name:version:*:*:*:*:*:*:*")),
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
					CPEs: []pkg.CPE{
						// name, vendor, and version replaced
						must(pkg.NewCPE("cpe:2.3:*:new-name:new-name:new-version:*:*:*:*:*:*:*")),
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
				CPEs: []pkg.CPE{
					must(pkg.NewCPE("cpe:2.3:*:name:name:version:*:*:*:*:*:*:*")),
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
			for upstream := range UpstreamPackages(tt.pkg) {
				actual = append(actual, upstream)
			}
			assert.Equalf(t, tt.expected, actual, "UpstreamPackages(%v)", tt.pkg)
		})
	}
}
