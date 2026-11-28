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
				Arch:    "x86_64",
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
					Arch:    "src",      // upstreams are source packages, whatever the binary's arch
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
					Arch:    "src",         // upstreams are source packages
					CPEs: []cpe.CPE{
						// name, vendor, and version replaced
						cpe.Must("cpe:2.3:*:new-name:new-name:new-version:*:*:*:*:*:*:*", ""),
					},
					// no upstreams
				},
			},
		},
		{
			name: "package name inside another field is not rewritten",
			pkg: Package{
				Name:    "git",
				Version: "2.40.0-1",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:git_project:git:2.40.0:*:*:*:*:*:*:*", ""),
				},
				Upstreams: []UpstreamPackage{
					{
						Name:    "git-src",
						Version: "2.40.0",
					},
				},
			},
			expected: []Package{
				{
					Name:    "git-src",
					Version: "2.40.0",
					Arch:    "src",
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:git_project:git-src:2.40.0:*:*:*:*:*:*:*", ""),
					},
				},
			},
		},
		{
			name: "short package name does not blank the CPE",
			pkg: Package{
				Name:    "c",
				Version: "1.0-1",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:canonical:c:1.0:*:*:*:*:*:*:*", ""),
				},
				Upstreams: []UpstreamPackage{
					{
						Name:    "c-lang",
						Version: "1.0",
					},
				},
			},
			expected: []Package{
				{
					Name:    "c-lang",
					Version: "1.0",
					Arch:    "src",
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:canonical:c-lang:1.0:*:*:*:*:*:*:*", ""),
					},
				},
			},
		},
		{
			name: "cpe for a different product is left alone",
			pkg: Package{
				Name:    "akhq-bin",
				Version: "0.25.0-r0",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:io.netty:netty-common:0.25.0-r0:*:*:*:*:maven:*:*", ""),
				},
				Upstreams: []UpstreamPackage{
					{
						Name: "akhq",
					},
				},
			},
			expected: []Package{
				{
					Name:    "akhq",
					Version: "0.25.0-r0",
					Arch:    "src",
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:io.netty:netty-common:0.25.0-r0:*:*:*:*:maven:*:*", ""),
					},
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
