package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/invopop/jsonschema"
	"golang.org/x/tools/go/packages"

	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
)

func main() {
	pkgPatterns := []string{"../dbsearch", "../../../../../../grype/db/v6"}

	comments := parseCommentsFromPackages(pkgPatterns)
	fmt.Printf("Extracted field comments from %d structs\n", len(comments))

	compose(dbsearch.Matches{}, "db-search", dbsearch.MatchesSchemaVersion, comments)
	compose(dbsearch.Vulnerabilities{}, "db-search-vuln", dbsearch.VulnerabilitiesSchemaVersion, comments)
}

func compose(document any, component, version string, comments map[string]map[string]string) {
	write(encode(build(document, component, version, comments)), component, version)
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

func build(document any, component, version string, comments map[string]map[string]string) *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		BaseSchemaID:              schemaID(component, version),
		AllowAdditionalProperties: true,
		Namer: func(r reflect.Type) string {
			return strings.TrimPrefix(r.Name(), "JSON")
		},
	}

	documentSchema := reflector.ReflectFromType(reflect.TypeOf(document))

	for structName, fields := range comments {
		if structSchema, exists := documentSchema.Definitions[structName]; exists {
			if structSchema.Definitions == nil {
				structSchema.Definitions = make(map[string]*jsonschema.Schema)
			}
			for fieldName, comment := range fields {
				if fieldName == "" {
					// struct-level comment
					structSchema.Description = comment
					continue
				}
				// field level comment
				if comment == "" {
					continue
				}
				if _, exists := structSchema.Properties.Get(fieldName); exists {
					fieldSchema, exists := structSchema.Definitions[fieldName]
					if exists {
						fieldSchema.Description = comment
					} else {
						fieldSchema = &jsonschema.Schema{
							Description: comment,
						}
					}
					structSchema.Definitions[fieldName] = fieldSchema
				}
			}
			documentSchema.Definitions[structName] = structSchema
		}
	}

	return documentSchema
}

// parseCommentsFromPackages scans multiple packages and collects field comments for structs.
func parseCommentsFromPackages(pkgPatterns []string) map[string]map[string]string {
	commentMap := make(map[string]map[string]string)

	cfg := &packages.Config{
		Mode: packages.NeedFiles | packages.NeedSyntax | packages.NeedDeps | packages.NeedImports,
	}
	pkgs, err := packages.Load(cfg, pkgPatterns...)
	if err != nil {
		panic(fmt.Errorf("failed to load packages: %w", err))
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			fileComments := parseFileComments(file)
			for structName, fields := range fileComments {
				if _, exists := commentMap[structName]; !exists {
					commentMap[structName] = fields
				}
			}
		}
	}
	return commentMap
}

// parseFileComments extracts comments for structs and their fields in a single file.
func parseFileComments(node *ast.File) map[string]map[string]string {
	commentMap := make(map[string]map[string]string)

	ast.Inspect(node, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}

		structName := ts.Name.Name
		fieldComments := make(map[string]string)

		// extract struct-level comment
		if ts.Doc != nil {
			structComment := strings.TrimSpace(ts.Doc.Text())
			if !strings.Contains(structComment, "TODO:") {
				fieldComments[""] = cleanComment(structComment)
			}
		}

		// extract field-level comments
		for _, field := range st.Fields.List {
			if len(field.Names) == 0 {
				continue
			}
			fieldName := field.Names[0].Name
			jsonTag := getJSONTag(field)

			if field.Doc != nil {
				comment := strings.TrimSpace(field.Doc.Text())
				if strings.Contains(comment, "TODO:") {
					continue
				}
				if jsonTag != "" {
					fieldComments[jsonTag] = cleanComment(comment)
				} else {
					fieldComments[fieldName] = cleanComment(comment)
				}
			}
		}

		if len(fieldComments) > 0 {
			commentMap[structName] = fieldComments
		}
		return true
	})

	return commentMap
}

func cleanComment(comment string) string {
	// remove the first word, since that is the field name (if following go-doc patterns)
	split := strings.SplitN(comment, " ", 2)
	if len(split) > 1 {
		comment = split[1]
	}

	return strings.TrimSpace(strings.ReplaceAll(comment, "\"", "'"))
}

func getJSONTag(field *ast.Field) string {
	if field.Tag != nil {
		tagValue := strings.Trim(field.Tag.Value, "`")
		structTag := reflect.StructTag(tagValue)
		if jsonTag, ok := structTag.Lookup("json"); ok {
			jsonParts := strings.Split(jsonTag, ",")
			return strings.TrimSpace(jsonParts[0])
		}
	}
	return ""
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
