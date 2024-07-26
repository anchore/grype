package rpmmodularity

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

func TestRpmModularity_Satisfied(t *testing.T) {
	oracle, _ := distro.New(distro.OracleLinux, "8")

	tests := []struct {
		name          string
		rpmModularity qualifier.Qualifier
		pkg           pkg.Package
		distro        *distro.Distro
		satisfied     bool
	}{
		{
			name:          "non rpm metadata",
			rpmModularity: New("test:1"),
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{},
			},
			distro:    nil,
			satisfied: false,
		},
		{
			name:          "module with package rpm metadata lacking actual metadata 1",
			rpmModularity: New("test:1"),
			pkg:           pkg.Package{Metadata: nil},
			distro:        nil,
			satisfied:     true,
		},
		{
			name:          "empty module with rpm metadata lacking actual metadata 2",
			rpmModularity: New(""),
			pkg:           pkg.Package{Metadata: nil},
			distro:        nil,
			satisfied:     true,
		},
		{
			name:          "no modularity label with no module",
			rpmModularity: New(""),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				Epoch: nil,
			}},
			distro:    nil,
			satisfied: true,
		},
		{
			name:          "no modularity label with module",
			rpmModularity: New("abc"),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				Epoch: nil,
			}},
			distro:    nil,
			satisfied: true,
		},
		{
			name:          "modularity label with no module",
			rpmModularity: New(""),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				ModularityLabel: strRef("x:3:1234567:abcd"),
			}},
			distro:    nil,
			satisfied: false,
		},
		{
			name:          "modularity label in module",
			rpmModularity: New("x:3"),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				ModularityLabel: strRef("x:3:1234567:abcd"),
			}},
			distro:    nil,
			satisfied: true,
		},
		{
			name:          "modularity label not in module",
			rpmModularity: New("x:3"),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				ModularityLabel: strRef("x:1:1234567:abcd"),
			}},
			distro:    nil,
			satisfied: false,
		},
		{
			name:          "modularity label is positively blank",
			rpmModularity: New(""),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				ModularityLabel: strRef(""),
			}},
			distro:    nil,
			satisfied: true,
		},
		{
			name:          "modularity label is missing (assume we cannot verify that capability)",
			rpmModularity: New(""),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				ModularityLabel: nil,
			}},
			distro:    nil,
			satisfied: true,
		},
		{
			name:          "default appstream for oraclelinux (treat as missing)",
			rpmModularity: New("nodejs:16"),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				ModularityLabel: strRef(""),
			}},
			distro:    oracle,
			satisfied: true,
		},
		{
			name:          "non-default appstream for oraclelinux matches vuln modularity",
			rpmModularity: New("nodejs:16"),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				ModularityLabel: strRef("nodejs:16:blah"),
			}},
			distro:    oracle,
			satisfied: true,
		},
		{
			name:          "non-default appstream for oraclelinux does not match vuln modularity",
			rpmModularity: New("nodejs:17"),
			pkg: pkg.Package{Metadata: pkg.RpmMetadata{
				ModularityLabel: strRef("nodejs:16:blah"),
			}},
			distro:    oracle,
			satisfied: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := test.rpmModularity.Satisfied(test.distro, test.pkg)
			assert.NoError(t, err)
			assert.Equal(t, test.satisfied, s)
		})
	}
}

func strRef(s string) *string {
	return &s
}
