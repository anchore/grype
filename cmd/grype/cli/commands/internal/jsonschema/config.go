package main

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/discard"
	"github.com/anchore/grype/cmd/grype/cli/options"
)

// configTagName must match the tag fangs uses when loading configuration files
const configTagName = "mapstructure"

// durationPattern matches strings accepted by time.ParseDuration
const durationPattern = `^[-+]?(0|([0-9]*(\.[0-9]*)?(ns|us|µs|μs|ms|s|m|h))+)$`

var durationType = reflect.TypeFor[time.Duration]()

// defaults that depend on the machine generating the schema
var configDefaultsSkipped = map[string]bool{
	"db.cache-dir": true,
}

// configValues returns the default configuration objects whose union makes up the grype configuration file
func configValues() []any {
	return []any{
		&clio.Config{
			Log: &clio.LoggingConfig{Level: logger.WarnLevel},
			Dev: &clio.DevelopmentConfig{},
		},
		options.DefaultGrype(clio.Identification{Name: "grype"}),
	}
}

func buildConfigSchema() *jsonschema.Schema {
	values := configValues()

	// flags are registered only so their usage text can serve as a description fallback, as `grype config` does
	cmd := &cobra.Command{}
	fangs.AddFlags(discard.New(), cmd.Flags(), values...)

	w := configWalker{
		descriptions: fangs.DescriptionProviders(
			fangs.NewFieldDescriber(values...),
			fangs.NewStructDescriptionTagProvider(),
			fangs.NewCommandFlagDescriptionProvider(configTagName, cmd),
		),
	}

	root := newObjectSchema()
	for _, v := range values {
		w.walkStruct(root, reflect.ValueOf(v), nil)
	}

	if _, exists := root.Properties.Get("profiles"); exists {
		panic("config key \"profiles\" collides with the fangs profile key")
	}
	root.Properties.Set("profiles", &jsonschema.Schema{
		Type:                 "object",
		Description:          "named partial configurations applied over the top-level configuration with --profile <name>",
		AdditionalProperties: &jsonschema.Schema{Ref: "#"},
	})

	applyConstraints(root)

	// draft-07 has the broadest support across editors (yaml-language-server) and schemastore.org
	root.Version = "http://json-schema.org/draft-07/schema#"
	root.ID = schemaID("config", options.ConfigSchemaVersion)
	root.Title = "Grype configuration"
	root.Description = "configuration file for grype (e.g. .grype.yaml, .grype/config.yaml)"

	return root
}

// configWalker mirrors the field handling of fangs (load + summarize) so the schema describes exactly the keys grype reads
type configWalker struct {
	descriptions fangs.DescriptionProvider
}

func (w configWalker) walkStruct(obj *jsonschema.Schema, v reflect.Value, path []string) {
	v = derefValue(v)
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !includeConfigField(f) {
			continue
		}

		key, squash, ok := configFieldKey(f, path)
		if !ok {
			continue
		}

		if squash {
			w.walkStruct(obj, v.Field(i), path)
			continue
		}

		w.walkField(obj, f, v.Field(i), append(slices.Clone(path), key))
	}
}

func (w configWalker) walkField(obj *jsonschema.Schema, f reflect.StructField, v reflect.Value, path []string) {
	key := path[len(path)-1]
	description := w.descriptions.GetDescription(v, f)
	base := derefValue(v)

	if base.Kind() == reflect.Struct {
		sub, exists := obj.Properties.Get(key)
		switch {
		case !exists:
			sub = newObjectSchema()
			obj.Properties.Set(key, sub)
		case sub.Type != "object":
			panic(fmt.Sprintf("config key %q is defined as both a value and a section", dotted(path)))
		}
		if sub.Description == "" {
			sub.Description = description
		}
		w.walkStruct(sub, base, path)
		return
	}

	if _, exists := obj.Properties.Get(key); exists {
		panic(fmt.Sprintf("config key %q is defined more than once", dotted(path)))
	}

	s := w.valueSchema(base, path)
	s.Description = description
	if !configDefaultsSkipped[dotted(path)] {
		s.Default = defaultValue(base)
	}
	obj.Properties.Set(key, s)
}

func (w configWalker) valueSchema(v reflect.Value, path []string) *jsonschema.Schema {
	t := v.Type()
	if t == durationType {
		return &jsonschema.Schema{Type: "string", Pattern: durationPattern}
	}

	switch t.Kind() {
	case reflect.Bool:
		return &jsonschema.Schema{Type: "boolean"}
	case reflect.String:
		return &jsonschema.Schema{Type: "string"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &jsonschema.Schema{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return &jsonschema.Schema{Type: "number"}
	case reflect.Slice:
		elem := t.Elem()
		for elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		switch elem.Kind() {
		case reflect.String:
			// viper also decodes a comma-separated string into a []string
			return &jsonschema.Schema{OneOf: []*jsonschema.Schema{
				{Type: "array", Items: &jsonschema.Schema{Type: "string"}},
				{Type: "string"},
			}}
		case reflect.Struct:
			items := newObjectSchema()
			itemPath := slices.Clone(path)
			itemPath[len(itemPath)-1] += "[]"
			w.walkStruct(items, reflect.New(elem), itemPath)
			return &jsonschema.Schema{Type: "array", Items: items}
		default:
		}
	default:
	}

	panic(fmt.Sprintf("unsupported config type %s at %q", t, dotted(path)))
}

func newObjectSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:                 "object",
		Properties:           jsonschema.NewProperties(),
		AdditionalProperties: jsonschema.FalseSchema,
	}
}

// includeConfigField matches fangs' includeField
func includeConfigField(f reflect.StructField) bool {
	return (f.Anonymous && f.Type.Kind() != reflect.Pointer) || f.IsExported()
}

func configFieldKey(f reflect.StructField, path []string) (key string, squash bool, ok bool) {
	tag, found := f.Tag.Lookup(configTagName)
	if !found {
		panic(fmt.Sprintf("config field %s at %q has no %s tag", f.Name, dotted(path), configTagName))
	}
	parts := strings.Split(tag, ",")
	switch {
	case parts[0] == "-":
		return "", false, false
	case slices.Contains(parts[1:], "squash"):
		return "", true, true
	case parts[0] == "":
		panic(fmt.Sprintf("config field %s at %q has no %s key name", f.Name, dotted(path), configTagName))
	}
	return parts[0], false, true
}

// derefValue follows pointers, substituting a zero value for nil pointers (as fangs does)
func derefValue(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v = reflect.New(v.Type().Elem())
		}
		v = v.Elem()
	}
	return v
}

func defaultValue(v reflect.Value) any {
	if v.Type() == durationType {
		return time.Duration(v.Int()).String()
	}

	switch v.Kind() {
	case reflect.Bool:
		return v.Bool()
	case reflect.String:
		if v.Len() == 0 {
			return nil
		}
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint()
	case reflect.Float32, reflect.Float64:
		return v.Float()
	case reflect.Slice:
		if v.Len() == 0 || v.Type().Elem().Kind() != reflect.String {
			return nil
		}
		out := make([]string, v.Len())
		for i := range out {
			out[i] = v.Index(i).String()
		}
		return out
	default:
		return nil
	}
}

func dotted(path []string) string {
	return strings.Join(path, ".")
}
