// This program regenerates the osvmodel package from the upstream OSV
// JSON schema (github.com/ossf/osv-schema).
//
// It writes into the parent osvmodel directory:
//   - schema-v1.json                  pinned upstream schema (latest v1.* tag)
//   - schema-v1.tag                   the upstream tag the pinned schema came from
//   - vulnerability_v1_generated.go   the Go model emitted from that schema
//
// Run via `make generate:osv-model` (regenerates from the committed pin) or
// `make update:osv-model` (fetches latest v1 upstream, then regenerates).
//
// Navigation through the schema is hand-coded for the known top-level types
// (Vulnerability, Affected, Package, Range, Event, Severity, Reference,
// Credit). Within each type, struct fields and enum constants are driven by
// the schema, so additions upstream surface as new Go fields / constants on
// the next regen. If upstream renames a top-level property the navigator
// panics, surfacing the diff for human review.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/dave/jennifer/jen"
)

const (
	releasesAPI   = "https://api.github.com/repos/ossf/osv-schema/releases/latest"
	schemaURLFmt  = "https://raw.githubusercontent.com/ossf/osv-schema/%s/validation/schema.json"
	pinnedFile    = "schema-v1.json"
	pinnedTagFile = "schema-v1.tag" // single-line file: the upstream tag the pinned schema came from
	generatedFile = "vulnerability_v1_generated.go"
	pkgName       = "osvmodel"
	requirePrefix = "v1."
)

// Schema is a partial JSON Schema decode sufficient for the OSV vocabulary.
// Anything we don't use upstream is ignored.
type Schema struct {
	Type        json.RawMessage    `json:"type,omitempty"` // string or []string; absent means free-form
	Properties  map[string]*Schema `json:"properties,omitempty"`
	Items       *Schema            `json:"items,omitempty"`
	Ref         string             `json:"$ref,omitempty"`
	Enum        []string           `json:"enum,omitempty"`
	Format      string             `json:"format,omitempty"`
	OneOf       []*Schema          `json:"oneOf,omitempty"`
	Required    []string           `json:"required,omitempty"`
	Defs        map[string]*Schema `json:"$defs,omitempty"`
	Description string             `json:"description,omitempty"`
}

// typeIs reports whether the schema's type contains the given JSON-Schema
// type name. JSON Schema allows `"type": "object"` and `"type": ["array",
// "null"]` — both are handled.
func (s *Schema) typeIs(name string) bool {
	if len(s.Type) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(s.Type, &single); err == nil {
		return single == name
	}
	var multi []string
	if err := json.Unmarshal(s.Type, &multi); err == nil {
		for _, t := range multi {
			if t == name {
				return true
			}
		}
	}
	return false
}

// packageDir returns the absolute path to the osvmodel package (one level up
// from this generator). Anchoring to the source-file location via
// runtime.Caller keeps output paths stable regardless of caller CWD.
func packageDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller(0) failed; can't locate generator source")
	}
	return filepath.Dir(filepath.Dir(thisFile))
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	pull := flag.Bool("pull", false,
		"fetch the latest v1 schema from upstream and overwrite the pinned schema-v1.json before regenerating")
	flag.Parse()

	tag, schemaBytes, err := loadSchema(*pull)
	if err != nil {
		return err
	}
	if schemaBytes == nil {
		// Soft refusal path (upstream cut a major version we don't handle).
		return nil
	}

	var root Schema
	if err := json.Unmarshal(schemaBytes, &root); err != nil {
		return fmt.Errorf("parse schema JSON: %w", err)
	}

	code, err := emit(&root, tag)
	if err != nil {
		return fmt.Errorf("emit Go model: %w", err)
	}
	if err := atomicWrite(filepath.Join(packageDir(), generatedFile), code); err != nil {
		return fmt.Errorf("write %s: %w", generatedFile, err)
	}
	fmt.Printf("regenerated %s from osv-schema %s\n", generatedFile, tag)
	return nil
}

// loadSchema returns the schema bytes plus the upstream tag they came from.
//
// When pull is false, it reads the committed schema-v1.json and schema-v1.tag
// — both stable, offline, deterministic. CI drift checks and `go generate`
// use this path so the generated file is bit-for-bit reproducible from the
// committed pin.
//
// When pull is true, it fetches the latest v1 release tag, downloads the
// schema at that tag, and writes both the schema and the tag to disk before
// returning. This is the cron/"bump upstream" path.
//
// Returns (tag, nil, nil) to signal a soft refusal (upstream cut a major
// version we don't handle).
func loadSchema(pull bool) (string, []byte, error) {
	if !pull {
		data, err := os.ReadFile(filepath.Join(packageDir(), pinnedFile))
		if err != nil {
			return "", nil, fmt.Errorf("read pinned %s: %w (run with --pull to fetch upstream)", pinnedFile, err)
		}
		tagBytes, err := os.ReadFile(filepath.Join(packageDir(), pinnedTagFile))
		if err != nil {
			return "", nil, fmt.Errorf("read pinned %s: %w (run with --pull to fetch upstream)", pinnedTagFile, err)
		}
		return strings.TrimSpace(string(tagBytes)), data, nil
	}

	tag, err := latestReleaseTag()
	if err != nil {
		return "", nil, fmt.Errorf("fetch latest release tag: %w", err)
	}
	if !strings.HasPrefix(tag, requirePrefix) {
		// Soft refusal: a fork-update bot calling this should exit clean,
		// the cron PR will simply be empty, and a human picks up the major bump.
		fmt.Fprintf(os.Stderr,
			"upstream cut %s; refusing to overwrite the %s* track.\n"+
				"manual steps to handle a major bump:\n"+
				"  1. copy schema-v1.json to schema-v1-final.json (preserve old track)\n"+
				"  2. write a new generator for v2 (likely a fork of this file)\n"+
				"  3. emit a parallel vulnerability_v2_generated.go\n",
			tag, requirePrefix)
		return tag, nil, nil
	}

	body, err := fetchBytes(fmt.Sprintf(schemaURLFmt, tag))
	if err != nil {
		return "", nil, fmt.Errorf("fetch schema at %s: %w", tag, err)
	}
	if err := atomicWrite(filepath.Join(packageDir(), pinnedFile), body); err != nil {
		return "", nil, fmt.Errorf("write %s: %w", pinnedFile, err)
	}
	if err := atomicWrite(filepath.Join(packageDir(), pinnedTagFile), []byte(tag+"\n")); err != nil {
		return "", nil, fmt.Errorf("write %s: %w", pinnedTagFile, err)
	}
	return tag, body, nil
}

// ============================================================================
// HTTP
// ============================================================================

func latestReleaseTag() (string, error) {
	req, _ := http.NewRequest(http.MethodGet, releasesAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	// Cron runs that hit the unauthenticated rate limit (60/hr) should set this.
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("%s: %s: %s", releasesAPI, resp.Status, b)
	}
	var r struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	if r.TagName == "" {
		return "", errors.New("no tag_name in release response")
	}
	return r.TagName, nil
}

func fetchBytes(url string) ([]byte, error) {
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ============================================================================
// Schema navigation helpers
//
// These walk the OSV schema by name and panic with an explanatory message if
// upstream rearranged something the generator depends on.
// ============================================================================

func navProp(s *Schema, name, ctx string) *Schema {
	if s == nil || s.Properties == nil {
		panic(fmt.Sprintf("expected %s.%s but parent has no properties", ctx, name))
	}
	p, ok := s.Properties[name]
	if !ok {
		panic(fmt.Sprintf("expected %s.%s in schema but it was missing", ctx, name))
	}
	return p
}

func navItems(s *Schema, ctx string) *Schema {
	if s == nil || s.Items == nil {
		panic(fmt.Sprintf("expected %s to be an array with items but it had no items", ctx))
	}
	return s.Items
}

func navRef(root *Schema, ref, ctx string) *Schema {
	if !strings.HasPrefix(ref, "#/$defs/") {
		panic(fmt.Sprintf("%s: unsupported ref %q (only #/$defs/* refs handled)", ctx, ref))
	}
	name := strings.TrimPrefix(ref, "#/$defs/")
	d, ok := root.Defs[name]
	if !ok {
		panic(fmt.Sprintf("%s: ref %s not found in $defs", ctx, ref))
	}
	return d
}

// ============================================================================
// Code emission
// ============================================================================

// nestedType maps a schema location to the Go type name emitted from it,
// with optional per-field type overrides for properties that should resolve
// to a named subtype rather than the default inferred from the schema.
type nestedType struct {
	goName     string                // type name in generated Go
	navigate   func(*Schema) *Schema // returns the object-schema for this type
	fieldTypes map[string]jen.Code   // explicit Go type for specific JSON properties (overrides type inference)
}

func nestedTypes(root *Schema) []nestedType {
	severityDef := navRef(root, "#/$defs/severity", "vulnerability.severity")
	return []nestedType{
		vulnerabilityNestedType(),
		affectedNestedType(),
		packageNestedType(),
		rangeNestedType(),
		eventNestedType(),
		severityNestedType(severityDef),
		referenceNestedType(),
		creditNestedType(),
	}
}

func vulnerabilityNestedType() nestedType {
	return nestedType{
		goName:   "Vulnerability",
		navigate: func(s *Schema) *Schema { return s },
		fieldTypes: map[string]jen.Code{
			"affected":   jen.Index().Id("Affected"),
			"severity":   jen.Index().Id("Severity"),
			"references": jen.Index().Id("Reference"),
			"credits":    jen.Index().Id("Credit"),
		},
	}
}

func affectedNestedType() nestedType {
	return nestedType{
		goName: "Affected",
		navigate: func(s *Schema) *Schema {
			return navItems(navProp(s, "affected", "vulnerability"), "vulnerability.affected")
		},
		fieldTypes: map[string]jen.Code{
			"package":  jen.Id("Package"),
			"severity": jen.Index().Id("Severity"),
			"ranges":   jen.Index().Id("Range"),
		},
	}
}

func packageNestedType() nestedType {
	return nestedType{
		goName: "Package",
		navigate: func(s *Schema) *Schema {
			return navProp(navItems(navProp(s, "affected", "vulnerability"), "vulnerability.affected"), "package", "affected")
		},
	}
}

func rangeNestedType() nestedType {
	return nestedType{
		goName: "Range",
		navigate: func(s *Schema) *Schema {
			return navItems(navProp(navItems(navProp(s, "affected", "vulnerability"), "vulnerability.affected"), "ranges", "affected"), "affected.ranges")
		},
		fieldTypes: map[string]jen.Code{
			"type":   jen.Id("RangeType"),
			"events": jen.Index().Id("Event"),
		},
	}
}

// Events are a oneOf union ({introduced} | {fixed} | {last_affected} | {limit}).
// Flatten the union into a single struct: every event field is optional and
// callers inspect the non-empty one(s). Hand-built since the schema's `oneOf`
// doesn't expose the union members as `properties` at this node.
func eventNestedType() nestedType {
	return nestedType{
		goName: "Event",
		navigate: func(*Schema) *Schema {
			return &Schema{
				Type: json.RawMessage(`"object"`),
				Properties: map[string]*Schema{
					"introduced":    {Type: json.RawMessage(`"string"`)},
					"fixed":         {Type: json.RawMessage(`"string"`)},
					"last_affected": {Type: json.RawMessage(`"string"`)},
					"limit":         {Type: json.RawMessage(`"string"`)},
				},
			}
		},
	}
}

func severityNestedType(severityDef *Schema) nestedType {
	return nestedType{
		goName:     "Severity",
		navigate:   func(*Schema) *Schema { return navItems(severityDef, "severity") },
		fieldTypes: map[string]jen.Code{"type": jen.Id("SeverityType")},
	}
}

func referenceNestedType() nestedType {
	return nestedType{
		goName: "Reference",
		navigate: func(s *Schema) *Schema {
			return navItems(navProp(s, "references", "vulnerability"), "vulnerability.references")
		},
		fieldTypes: map[string]jen.Code{"type": jen.Id("ReferenceType")},
	}
}

func creditNestedType() nestedType {
	return nestedType{
		goName: "Credit",
		navigate: func(s *Schema) *Schema {
			return navItems(navProp(s, "credits", "vulnerability"), "vulnerability.credits")
		},
		fieldTypes: map[string]jen.Code{"type": jen.Id("CreditType")},
	}
}

// enumSpec describes one typed-string enum to emit. The enum *values* are
// pulled from the schema (so new variants surface automatically); the type
// name and per-value constant names come from the table.
type enumSpec struct {
	typeName   string
	schemaPath string                // for error messages
	navigate   func(*Schema) *Schema // returns the schema for the enum field
	constName  func(value string) string
}

func enumSpecs(root *Schema) []enumSpec {
	severityDef := navRef(root, "#/$defs/severity", "vulnerability.severity")
	return []enumSpec{
		{
			typeName:   "RangeType",
			schemaPath: "affected.ranges.type",
			navigate: func(s *Schema) *Schema {
				return navProp(
					navItems(navProp(navItems(navProp(s, "affected", "vuln"), "affected"), "ranges", "affected"), "ranges"),
					"type", "range")
			},
			constName: rangeTypeConst,
		},
		{
			typeName:   "ReferenceType",
			schemaPath: "references.type",
			navigate: func(s *Schema) *Schema {
				return navProp(navItems(navProp(s, "references", "vuln"), "references"), "type", "reference")
			},
			constName: referenceTypeConst,
		},
		{
			typeName:   "SeverityType",
			schemaPath: "severity.type",
			navigate: func(*Schema) *Schema {
				return navProp(navItems(severityDef, "severity"), "type", "severity")
			},
			constName: severityTypeConst,
		},
		{
			typeName:   "CreditType",
			schemaPath: "credits.type",
			navigate: func(s *Schema) *Schema {
				return navProp(navItems(navProp(s, "credits", "vuln"), "credits"), "type", "credit")
			},
			constName: creditTypeConst,
		},
	}
}

// rangeTypeConst maps an upstream enum value to the Go constant name. The
// override switch preserves established names (RangeSemVer not RangeSEMVER);
// new values fall through to PascalCase ("FOO" → "RangeFoo").
func rangeTypeConst(value string) string {
	switch value {
	case "GIT":
		return "RangeGit"
	case "SEMVER":
		return "RangeSemVer"
	case "ECOSYSTEM":
		return "RangeEcosystem"
	}
	return "Range" + titleCaseEnumValue(value)
}

func referenceTypeConst(value string) string {
	return "Reference" + titleCaseEnumValue(value)
}

func severityTypeConst(value string) string {
	// CVSS_V2 → SeverityCVSSV2 (collapsed; the naive split would give
	// SeverityCvssV2 which loses the canonical CVSS initialism).
	switch value {
	case "CVSS_V2":
		return "SeverityCVSSV2"
	case "CVSS_V3":
		return "SeverityCVSSV3"
	case "CVSS_V4":
		return "SeverityCVSSV4"
	}
	return "Severity" + titleCaseEnumValue(value)
}

func creditTypeConst(value string) string {
	return "Credit" + titleCaseEnumValue(value)
}

// titleCaseEnumValue turns "SCREAMING_SNAKE_CASE" or "lowercase" or "MixedCase"
// into Go-idiomatic PascalCase. "REMEDIATION_DEVELOPER" → "RemediationDeveloper".
func titleCaseEnumValue(s string) string {
	parts := strings.Split(s, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	return strings.Join(parts, "")
}

// initialisms records JSON property name fragments that should be ALL CAPS
// when converted to Go identifiers. Anything not listed is title-cased.
var initialisms = map[string]string{
	"id":   "ID",
	"url":  "URL",
	"cvss": "CVSS",
	"cpe":  "CPE",
	"cpes": "CPEs",
}

// goFieldName converts a snake_case JSON property name to a Go field name.
func goFieldName(jsonName string) string {
	parts := strings.Split(jsonName, "_")
	for i, p := range parts {
		if up, ok := initialisms[p]; ok {
			parts[i] = up
			continue
		}
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

// fieldType returns the jen Code for one schema property's Go type, given any
// explicit override from the nested-type table.
func fieldType(prop *Schema, jsonName string, override jen.Code, ctx string) jen.Code {
	if override != nil {
		return override
	}
	// $defs refs we know about.
	if prop.Ref != "" {
		switch prop.Ref {
		case "#/$defs/timestamp":
			return jen.Qual("time", "Time")
		case "#/$defs/severity":
			return jen.Index().Id("Severity")
		case "#/$defs/prefix", "#/$defs/ecosystemName", "#/$defs/ecosystemWithSuffix", "#/$defs/ecosystemSuffix":
			return jen.String()
		default:
			panic(fmt.Sprintf("%s.%s: unsupported $ref %q (extend fieldType)", ctx, jsonName, prop.Ref))
		}
	}
	switch {
	case prop.typeIs("string"):
		return jen.String()
	case prop.typeIs("array"):
		if prop.Items == nil {
			return jen.Index().Any()
		}
		// Array of strings is the only inline-string-array case we need.
		if prop.Items.typeIs("string") {
			return jen.Index().String()
		}
		// Arrays of objects must be handled via an override in nestedTypes.
		panic(fmt.Sprintf("%s.%s: array of non-string items needs an explicit override", ctx, jsonName))
	case prop.typeIs("object"):
		// Free-form object → map[string]any. Named subobjects must come via override.
		if len(prop.Properties) == 0 {
			return jen.Map(jen.String()).Any()
		}
		panic(fmt.Sprintf("%s.%s: nested object without an override (extend nestedTypes)", ctx, jsonName))
	}
	panic(fmt.Sprintf("%s.%s: cannot infer Go type from schema", ctx, jsonName))
}

func emit(root *Schema, tag string) ([]byte, error) {
	f := jen.NewFile(pkgName)
	f.HeaderComment("Code generated by ./generate/main.go from osv-schema " + tag + ". DO NOT EDIT.")
	f.HeaderComment("Regenerate via: make generate:osv-model")
	f.HeaderComment("Source: github.com/ossf/osv-schema@" + tag + " (validation/schema.json)")
	f.HeaderComment("")
	f.HeaderComment("Package osvmodel is grype's representation of an OSV record. It mirrors")
	f.HeaderComment("the upstream OSV schema (https://ossf.github.io/osv-schema/) without")
	f.HeaderComment("taking a runtime dependency on any third-party OSV library: parsing goes")
	f.HeaderComment("through standard encoding/json into these structs.")
	f.HeaderComment("")
	f.HeaderComment("Strategy authors who want a field that isn't here yet should regenerate")
	f.HeaderComment("(make generate:osv-model) after bumping the pinned schema-v1.json; once")
	f.HeaderComment("upstream has the field, regeneration surfaces it as a Go field for free.")

	// Emit struct types.
	for _, nt := range nestedTypes(root) {
		emitStruct(f, root, nt)
	}

	// Emit enum types + constants.
	for _, es := range enumSpecs(root) {
		emitEnum(f, root, es)
	}

	var buf bytes.Buffer
	if err := f.Render(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func emitStruct(f *jen.File, root *Schema, nt nestedType) {
	obj := nt.navigate(root)
	if obj == nil {
		panic(fmt.Sprintf("emitStruct: %s navigation returned nil", nt.goName))
	}
	if obj.Properties == nil {
		panic(fmt.Sprintf("emitStruct: %s has no properties", nt.goName))
	}

	// Sort property names for stable output.
	jsonNames := make([]string, 0, len(obj.Properties))
	for k := range obj.Properties {
		jsonNames = append(jsonNames, k)
	}
	sort.Strings(jsonNames)

	fields := make([]jen.Code, 0, len(jsonNames))
	for _, jsonName := range jsonNames {
		prop := obj.Properties[jsonName]
		typ := fieldType(prop, jsonName, nt.fieldTypes[jsonName], nt.goName)
		fields = append(fields,
			jen.Id(goFieldName(jsonName)).Add(typ).Tag(map[string]string{"json": jsonName + ",omitempty"}),
		)
	}
	f.Type().Id(nt.goName).Struct(fields...)
}

func emitEnum(f *jen.File, root *Schema, es enumSpec) {
	field := es.navigate(root)
	if field == nil || len(field.Enum) == 0 {
		panic(fmt.Sprintf("emitEnum: %s has no enum values at %s", es.typeName, es.schemaPath))
	}

	f.Type().Id(es.typeName).String()

	// Sort enum values for stable output (does not affect semantics).
	values := append([]string{}, field.Enum...)
	sort.Strings(values)

	f.Const().DefsFunc(func(g *jen.Group) {
		for _, v := range values {
			g.Id(es.constName(v)).Id(es.typeName).Op("=").Lit(v)
		}
	})
}
