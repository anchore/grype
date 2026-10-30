package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	validator "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/anchore/fangs"
	"github.com/anchore/grype/cmd/grype/cli/options"
)

func TestConfigSchemaUpToDate(t *testing.T) {
	generated := string(encode(buildConfigSchema()))
	dir := filepath.Join(repoRoot(), "schema", "grype", "config", "json")

	for _, name := range []string{fmt.Sprintf("schema-%s.json", options.ConfigSchemaVersion), "schema-latest.json"} {
		committed, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err, "run 'make generate:json-schema' to create the config schema")
		assert.Equal(t, string(committed), generated, "%s is out of date: run 'make generate:json-schema' (bump options.ConfigSchemaVersion if it refuses to overwrite)", name)
	}
}

func TestConfigSchemaKeys(t *testing.T) {
	root := buildConfigSchema()

	present := []string{
		"sort-by",               // squashed named field
		"db.cache-dir",          // squashed embedded struct
		"match.java.using-cpes", // squashed embedded matcher config
		"dev.profile",           // clio development config...
		"dev.db.debug",          // ...merged with the grype developer config
		"log.verbosity",         // loadable even though hidden from `grype config`
		"ignore-wontfix",        // mapstructure name, not the yaml name
		"external-sources.maven.search-maven-upstream",
		"ignore[].package.name",
		"output[]",
		"profiles",
	}
	for _, path := range present {
		assert.NotNil(t, lookupSchema(root, path), "expected config key %q", path)
	}

	absent := []string{
		"SortBy",
		"DatabaseCommand",
		"ignore-states",
		"external-sources.maven.search-upstream",
	}
	for _, path := range absent {
		assert.Nil(t, lookupSchema(root, path), "unexpected config key %q", path)
	}
}

func TestConfigSchemaAcceptsDefaultConfig(t *testing.T) {
	sch := compileConfigSchema(t)

	// the same rendering `grype config` produces
	summary := fangs.Summarize(fangs.NewConfig("grype"), fangs.DescriptionProviders(), nil, configValues()...)

	require.NoError(t, validateConfig(t, sch, summary), summary)
}

func TestConfigSchemaAcceptsRepoFixtures(t *testing.T) {
	sch := compileConfigSchema(t)

	fixtures := []string{
		"test/cli/testdata/configs/dir1/.grype.yaml",
		"test/cli/testdata/configs/dir2/.grype.yaml",
		"test/cli/testdata/test-ignore-reason/config-with-ignore.yaml",
		"test/grype-test-config.yaml",
		"test/ignore-att-signature.yaml",
		"test/integration/.grype.yaml",
	}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join(repoRoot(), filepath.FromSlash(fixture)))
			require.NoError(t, err)

			require.NoError(t, validateConfig(t, sch, string(content)))
		})
	}
}

func TestConfigSchemaValidation(t *testing.T) {
	sch := compileConfigSchema(t)

	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name:   "list given as a comma-separated string",
			config: "output: json,table\n",
		},
		{
			name:   "list given as an array",
			config: "output:\n  - json\n  - table=report.txt\n",
		},
		{
			name:   "profile with a partial config",
			config: "profiles:\n  ci:\n    fail-on-severity: high\n",
		},
		{
			name:   "duration",
			config: "db:\n  max-allowed-built-age: 72h\n",
		},
		{
			name:   "empty section",
			config: "match:\n",
		},
		{
			name:    "unknown top-level key",
			config:  "fail-on-serverity: high\n",
			wantErr: true,
		},
		{
			name:    "unknown nested key",
			config:  "match:\n  java:\n    using-cpe: true\n",
			wantErr: true,
		},
		{
			name:    "unknown ignore rule key",
			config:  "ignore:\n  - vulnerablity: CVE-2021-1234\n",
			wantErr: true,
		},
		{
			name:    "unknown key within a profile",
			config:  "profiles:\n  ci:\n    fail-on-serverity: high\n",
			wantErr: true,
		},
		{
			name:    "value not in the allowed set",
			config:  "fail-on-severity: severe\n",
			wantErr: true,
		},
		{
			name:    "invalid duration",
			config:  "db:\n  max-allowed-built-age: soon\n",
			wantErr: true,
		},
		{
			name:    "wrong value type",
			config:  "check-for-app-update: sometimes\n",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(t, sch, tt.config)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestConfigWalkerRejectsUnsupportedFields(t *testing.T) {
	type withMap struct {
		Values map[string]string `mapstructure:"values"`
	}
	type withoutTag struct {
		Value string
	}

	w := configWalker{descriptions: fangs.DescriptionProviders()}
	for _, cfg := range []any{&withMap{}, &withoutTag{}} {
		assert.Panics(t, func() {
			w.walkStruct(newObjectSchema(), reflect.ValueOf(cfg), nil)
		}, "%T", cfg)
	}
}

func compileConfigSchema(t *testing.T) *validator.Schema {
	t.Helper()

	doc, err := validator.UnmarshalJSON(bytes.NewReader(encode(buildConfigSchema())))
	require.NoError(t, err)

	c := validator.NewCompiler()
	require.NoError(t, c.AddResource("config.schema.json", doc))

	sch, err := c.Compile("config.schema.json")
	require.NoError(t, err)
	return sch
}

func validateConfig(t *testing.T, sch *validator.Schema, content string) error {
	t.Helper()

	var cfg any
	require.NoError(t, yaml.Unmarshal([]byte(content), &cfg))

	// round-trip through JSON so the validator only sees JSON value types
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)

	inst, err := validator.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)

	return sch.Validate(inst)
}
