package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
)

func main() {
	compose(dbsearch.Matches{}, "db-search", dbsearch.MatchesSchemaVersion)
	compose(dbsearch.Vulnerabilities{}, "db-search-vuln", dbsearch.VulnerabilitiesSchemaVersion)
}

func compose(document any, component, version string) {
	write(encode(build(document, component, version)), component, version)
}

func write(schema []byte, component, version string) {
	parent := filepath.Join(repoRoot(), "schema", "grype", component, "json")
	schemaPath := filepath.Join(parent, fmt.Sprintf("schema-%s.json", version))
	latestSchemaPath := filepath.Join(parent, "schema-latest.json")

	if _, err := os.Stat(schemaPath); !os.IsNotExist(err) {
		// check if the schema is the same...
		existingFh, err := os.Open(schemaPath)
		if err != nil {
			panic(err)
		}

		existingSchemaBytes, err := io.ReadAll(existingFh)
		if err != nil {
			panic(err)
		}

		if bytes.Equal(existingSchemaBytes, schema) {
			// the generated schema is the same, bail with no error :)
			fmt.Printf("No change to the existing %q schema!\n", component)
			return
		}

		// the generated schema is different, bail with error :(
		fmt.Printf("Cowardly refusing to overwrite existing %q schema (%s)!\nSee the README.md for how to increment\n", component, schemaPath)
		os.Exit(1)
	}

	fh, err := os.Create(schemaPath)
	if err != nil {
		panic(err)
	}
	defer fh.Close()

	_, err = fh.Write(schema)
	if err != nil {
		panic(err)
	}

	latestFile, err := os.Create(latestSchemaPath)
	if err != nil {
		panic(err)
	}
	defer latestFile.Close()

	_, err = latestFile.Write(schema)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Wrote new %q schema to %q\n", component, schemaPath)
}

func encode(schema *jsonschema.Schema) []byte {
	newSchemaBuffer := new(bytes.Buffer)
	enc := json.NewEncoder(newSchemaBuffer)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(&schema)
	if err != nil {
		panic(err)
	}

	return newSchemaBuffer.Bytes()
}

func build(document any, component, version string) *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		BaseSchemaID:              schemaID(component, version),
		AllowAdditionalProperties: true,
		Namer: func(r reflect.Type) string {
			return strings.TrimPrefix(r.Name(), "JSON")
		},
	}

	documentSchema := reflector.ReflectFromType(reflect.TypeOf(document))

	return documentSchema
}

func schemaID(component, version string) jsonschema.ID {
	return jsonschema.ID(fmt.Sprintf("anchore.io/schema/grype/%s/json/%s", component, version))
}

func repoRoot() string {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		panic(fmt.Errorf("unable to find repo root dir: %+v", err))
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		panic(fmt.Errorf("unable to get abs path to repo root: %w", err))
	}
	return absRepoRoot
}
