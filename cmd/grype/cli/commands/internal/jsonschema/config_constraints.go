package main

import (
	"fmt"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
)

// constraint narrows the generated schema of a single config key
type constraint func(*jsonschema.Schema)

// configConstraints maps a dotted config path to a constraint; "[]" addresses array items (e.g. "ignore[].fix-state").
// Every path must exist in the generated schema, otherwise generation fails.
var configConstraints = map[string]constraint{
	// "" is the unset state, which skips the severity check
	"fail-on-severity": enum(append([]string{""}, severityNames()...)...),
	"sort-by":          enum(stringsOf(models.SortStrategies())...),

	// TODO: remaining constraints
}

func enum(values ...string) constraint {
	return func(s *jsonschema.Schema) {
		for _, v := range values {
			s.Enum = append(s.Enum, v)
		}
	}
}

func pattern(re string) constraint {
	return func(s *jsonschema.Schema) {
		s.Pattern = re
	}
}

func stringsOf[T ~string](values []T) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}

func severityNames() []string {
	var out []string
	for _, s := range vulnerability.AllSeverities() {
		out = append(out, s.String())
	}
	return out
}

func applyConstraints(root *jsonschema.Schema) {
	for path, c := range configConstraints {
		s := lookupSchema(root, path)
		if s == nil {
			panic(fmt.Sprintf("config constraint path %q does not exist in the schema", path))
		}
		c(s)
	}
}

func lookupSchema(root *jsonschema.Schema, path string) *jsonschema.Schema {
	s := root
	for part := range strings.SplitSeq(path, ".") {
		name, items := strings.CutSuffix(part, "[]")
		if s.Properties == nil {
			return nil
		}
		next, ok := s.Properties.Get(name)
		if !ok {
			return nil
		}
		if items {
			next = arrayItems(next)
			if next == nil {
				return nil
			}
		}
		s = next
	}
	return s
}

// arrayItems returns the item schema of an array, including the array form of a list-or-string value
func arrayItems(s *jsonschema.Schema) *jsonschema.Schema {
	if s.Type == jsonTypeArray {
		return s.Items
	}
	for _, alt := range s.OneOf {
		if alt.Type == jsonTypeArray {
			return alt.Items
		}
	}
	return nil
}
