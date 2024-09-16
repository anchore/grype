package packagemetadata

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
)

func TestAllNames(t *testing.T) {
	// note: this is a form of completion testing relative to the current code base.

	expected, err := DiscoverTypeNames()
	require.NoError(t, err)

	actual := AllTypeNames()

	// ensure that the codebase (from ast analysis) reflects the latest code generated state
	if !assert.ElementsMatch(t, expected, actual) {
		t.Errorf("metadata types not fully represented: \n%s", cmp.Diff(expected, actual))
		t.Log("did you add a new pkg.*Metadata type without updating the JSON schema?")
		t.Log("if so, you need to update the schema version and regenerate the JSON schema (make generate-json-schema)")
	}

	for _, ty := range AllTypes() {
		assert.NotEmpty(t, JSONName(ty), "metadata type %q does not have a JSON name", ty)
	}
}

func TestReflectTypeFromJSONName(t *testing.T) {

	tests := []struct {
		name       string
		lookup     string
		wantRecord reflect.Type
	}{
		{
			name:       "GolangBinMetadata lookup",
			lookup:     "GolangBinMetadata",
			wantRecord: reflect.TypeOf(pkg.GolangBinMetadata{}),
		},
		{
			name:       "GolangModMetadata lookup",
			lookup:     "GolangModMetadata",
			wantRecord: reflect.TypeOf(pkg.GolangModMetadata{}),
		},
		{
			name:       "JavaMetadata lookup",
			lookup:     "JavaMetadata",
			wantRecord: reflect.TypeOf(pkg.JavaMetadata{}),
		},
		{
			name:       "RpmMetadata lookup",
			lookup:     "RpmMetadata",
			wantRecord: reflect.TypeOf(pkg.RpmMetadata{}),
		},
		{
			name:       "JavaVMInstallationMetadata lookup",
			lookup:     "JavaVMInstallationMetadata",
			wantRecord: reflect.TypeOf(pkg.JavaVMInstallationMetadata{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReflectTypeFromJSONName(tt.lookup)
			assert.Equal(t, tt.wantRecord.Name(), got.Name())
		})
	}
}
