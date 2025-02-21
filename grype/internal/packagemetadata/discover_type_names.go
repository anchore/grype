package packagemetadata

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/scylladb/go-set/strset"
)

var metadataExceptions = strset.New(
	"FileMetadata",
	"PURLFileMetadata",
	"PURLLiteralMetadata",
	"CPELiteralMetadata",
)

func DiscoverTypeNames() ([]string, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(root, "grype/pkg/*.go"))
	if err != nil {
		return nil, err
	}
	return findMetadataDefinitionNames(files...)
}

func RepoRoot() (string, error) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		return "", fmt.Errorf("unable to get abs path to repo root: %w", err)
	}
	return absRepoRoot, nil
}

func findMetadataDefinitionNames(paths ...string) ([]string, error) {
	names := strset.New()
	usedNames := strset.New()
	for _, path := range paths {
		metadataDefinitions, usedTypeNames, err := findMetadataDefinitionNamesInFile(path)
		if err != nil {
			return nil, err
		}

		// useful for debugging...
		// fmt.Println(path)
		// fmt.Println("Defs:", metadataDefinitions)
		// fmt.Println("Used Types:", usedTypeNames)
		// fmt.Println()

		names.Add(metadataDefinitions...)
		usedNames.Add(usedTypeNames...)
	}

	// any definition that is used within another struct should not be considered a top-level metadata definition
	names.Remove(usedNames.List()...)

	strNames := names.List()
	sort.Strings(strNames)

	// note: 3 is a point-in-time gut check. This number could be updated if new metadata definitions are added, but is not required.
	// it is really intended to catch any major issues with the generation process that would generate, say, 0 definitions.
	if len(strNames) < 3 {
		return nil, fmt.Errorf("not enough metadata definitions found: discovered %d ", len(strNames))
	}

	return strNames, nil
}

func findMetadataDefinitionNamesInFile(path string) ([]string, []string, error) {
	// set up the parser
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil, err
	}

	var metadataDefinitions []string
	var usedTypeNames []string
	for _, decl := range f.Decls {
		// check if the declaration is a type declaration
		spec, ok := decl.(*ast.GenDecl)
		if !ok || spec.Tok != token.TYPE {
			continue
		}

		// loop over all types declared in the type declaration
		for _, typ := range spec.Specs {
			// check if the type is a struct type
			spec, ok := typ.(*ast.TypeSpec)
			if !ok || spec.Type == nil {
				continue
			}

			structType, ok := spec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			// check if the struct type ends with "Metadata"
			name := spec.Name.String()

			// only look for exported types that end with "Metadata"
			if isMetadataTypeCandidate(name) {
				// print the full declaration of the struct type
				metadataDefinitions = append(metadataDefinitions, name)
				usedTypeNames = append(usedTypeNames, typeNamesUsedInStruct(structType)...)
			}
		}
	}
	return metadataDefinitions, usedTypeNames, nil
}

func typeNamesUsedInStruct(structType *ast.StructType) []string {
	// recursively find all type names used in the struct type
	var names []string
	for i := range structType.Fields.List {
		// capture names of all of the types (not field names)
		ast.Inspect(structType.Fields.List[i].Type, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}

			// add the type name to the list
			names = append(names, ident.Name)

			// continue inspecting
			return true
		})
	}

	return names
}

func isMetadataTypeCandidate(name string) bool {
	return len(name) > 0 &&
		strings.HasSuffix(name, "Metadata") &&
		unicode.IsUpper(rune(name[0])) && // must be exported
		!metadataExceptions.Has(name)
}
