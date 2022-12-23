package rpmmodularity

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

func TestRpmModularity_Satisfied(t *testing.T) {
	tests := []struct {
		name          string
		rpmModularity qualifier.Qualifier
		pkg           pkg.Package
		satisfied     bool
	}{
		{
			name:          "non rpm metadata",
			rpmModularity: New("test:1"),
			pkg:           pkg.Package{MetadataType: pkg.UnknownMetadataType},
			satisfied:     false,
		},
		{
			name:          "invalid rpm metadata",
			rpmModularity: New("test:1"),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.GolangMetadata{
				BuildSettings:     nil,
				GoCompiledVersion: "",
				Architecture:      "",
				H1Digest:          "",
				MainModule:        "",
			}},
			satisfied: true,
		},
		{
			name:          "module with package rpm metadata lacking actual metadata 1",
			rpmModularity: New("test:1"),
			pkg:           pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: nil},
			satisfied:     true,
		},
		{
			name:          "empty module with rpm metadata lacking actual metadata 2",
			rpmModularity: New(""),
			pkg:           pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: nil},
			satisfied:     true,
		},
		{
			name:          "no modularity label with no module",
			rpmModularity: New(""),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.RpmMetadata{
				Epoch: nil,
			}},
			satisfied: true,
		},
		{
			name:          "no modularity label with module",
			rpmModularity: New("abc"),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.RpmMetadata{
				Epoch: nil,
			}},
			satisfied: true,
		},
		{
			name:          "modularity label with no module",
			rpmModularity: New(""),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.RpmMetadata{
				Epoch:           nil,
				ModularityLabel: "x:3:1234567:abcd",
			}},
			satisfied: false,
		},
		{
			name:          "modularity label in module",
			rpmModularity: New("x:3"),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.RpmMetadata{
				Epoch:           nil,
				ModularityLabel: "x:3:1234567:abcd",
			}},
			satisfied: true,
		},
		{
			name:          "modularity label not in module",
			rpmModularity: New("x:3"),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.RpmMetadata{
				Epoch:           nil,
				ModularityLabel: "x:1:1234567:abcd",
			}},
			satisfied: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := test.rpmModularity.Satisfied(test.pkg)
			assert.NoError(t, err)
			assert.Equal(t, test.satisfied, s)
		})
	}
}
