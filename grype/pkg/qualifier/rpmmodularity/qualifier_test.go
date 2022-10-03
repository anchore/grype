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
			rpmModularity: NewRpmModularityQualifier("test:1"),
			pkg:           pkg.Package{MetadataType: pkg.UnknownMetadataType},
			satisfied:     false,
		},
		{
			name:          "invalid rpm metadata",
			rpmModularity: NewRpmModularityQualifier("test:1"),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.GolangBinMetadata{
				BuildSettings:     nil,
				GoCompiledVersion: "",
				Architecture:      "",
				H1Digest:          "",
				MainModule:        "",
			}},
			satisfied: true,
		},
		{
			name:          "rpm metadata lacking actual metadata 1",
			rpmModularity: NewRpmModularityQualifier("test:1"),
			pkg:           pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: nil},
			satisfied:     false,
		},
		{
			name:          "rpm metadata lacking actual metadata 2",
			rpmModularity: NewRpmModularityQualifier(""),
			pkg:           pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: nil},
			satisfied:     true,
		},
		{
			name:          "no modularity label with no module",
			rpmModularity: NewRpmModularityQualifier(""),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.RpmMetadata{
				Epoch: nil,
			}},
			satisfied: true,
		},
		{
			name:          "no modularity label with module",
			rpmModularity: NewRpmModularityQualifier("abc"),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.RpmMetadata{
				Epoch: nil,
			}},
			satisfied: false,
		},
		{
			name:          "modularity label with no module",
			rpmModularity: NewRpmModularityQualifier(""),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.RpmMetadata{
				Epoch:           nil,
				ModularityLabel: "x:3:1234567:abcd",
			}},
			satisfied: false,
		},
		{
			name:          "modularity label in module",
			rpmModularity: NewRpmModularityQualifier("x:3"),
			pkg: pkg.Package{MetadataType: pkg.RpmMetadataType, Metadata: pkg.RpmMetadata{
				Epoch:           nil,
				ModularityLabel: "x:3:1234567:abcd",
			}},
			satisfied: true,
		},
		{
			name:          "modularity label not in module",
			rpmModularity: NewRpmModularityQualifier("x:3"),
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
