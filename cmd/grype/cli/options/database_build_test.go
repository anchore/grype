package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlattenCSV(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nil", in: nil, want: nil},
		// flattenCSV short-circuits on empty: it returns the input as-is, so an empty slice
		// stays an empty slice rather than being normalized to nil.
		{name: "empty", in: []string{}, want: []string{}},
		{name: "single", in: []string{"alpine"}, want: []string{"alpine"}},
		{name: "csv in one entry", in: []string{"alpine,alma,rhel"}, want: []string{"alpine", "alma", "rhel"}},
		{name: "multiple entries", in: []string{"alpine", "alma"}, want: []string{"alpine", "alma"}},
		{name: "mixed csv + entries", in: []string{"alpine,alma", "rhel"}, want: []string{"alpine", "alma", "rhel"}},
		{name: "whitespace tolerated", in: []string{" alpine , alma "}, want: []string{"alpine", "alma"}},
		{name: "empty segments dropped", in: []string{"alpine,,", ",alma"}, want: []string{"alpine", "alma"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, flattenCSV(tt.in))
		})
	}
}

func TestStringMap_String(t *testing.T) {
	tests := []struct {
		name string
		m    stringMap
		want string
	}{
		{name: "nil", m: nil, want: "{}"},
		{name: "empty", m: stringMap{}, want: "{}"},
		{name: "single entry", m: stringMap{"foo": "bar"}, want: "{foo: bar}"},
		{name: "deterministic key order", m: stringMap{"b": "2", "a": "1", "c": "3"}, want: "{a: 1, b: 2, c: 3}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.m.String())
		})
	}
}

func TestDatabaseBuild_PostLoad_FlattensProviderName(t *testing.T) {
	opts := DefaultDatabaseBuild()
	opts.Provider.IncludeFilter = []string{"alpine,alma", "rhel"}

	require.NoError(t, opts.PostLoad())

	assert.Equal(t, []string{"alpine", "alma", "rhel"}, opts.Provider.IncludeFilter)
}

func TestDefaultDatabaseBuild_NonZeroDefaults(t *testing.T) {
	opts := DefaultDatabaseBuild()

	// guard against regressions in defaults that the grype-db-manager + CI rely on
	assert.Equal(t, "./build", opts.Dir)
	assert.Equal(t, "./data", opts.Provider.Root)
	assert.Equal(t, "docker", opts.Provider.Vunnel.Executor)
	assert.Equal(t, "ghcr.io/anchore/vunnel", opts.Provider.Vunnel.DockerImage)
	assert.Equal(t, "latest", opts.Provider.Vunnel.DockerTag)
	assert.Equal(t, 4, opts.Pull.Parallelism)
	assert.NotNil(t, opts.CompressorCommands, "CompressorCommands must be a non-nil stringMap so YAML serialization emits '{}' instead of 'null'")
	assert.NotNil(t, opts.Provider.Vunnel.Env, "Env must be a non-nil stringMap so YAML serialization emits '{}' instead of 'null'")
}
