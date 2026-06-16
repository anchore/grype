// This program regenerates the osvmodel package from a pinned JSON Schema.
//
// It writes into the parent osvmodel directory:
//   - schema-v1.json                  pinned upstream schema
//   - schema-v1.tag                   the upstream tag the pinned schema came from
//   - vulnerability_generated.go   Go model emitted from that schema
//
// Run via `make generate:osv-model` (regenerates from the committed pin) or
// `make update:osv-model` (fetches latest v1 upstream, then regenerates).
//
// Design: this is a small, general JSON-Schema → Go translator with opinions
// baked in. It has no OSV-specific knowledge. Schema changes that stay
// within the JSON Schema features we handle are absorbed automatically;
// anything outside that subset panics with a message naming the schema
// fragment that surprised us, so the cron PR fails loudly and a human knows
// exactly what to extend.
//
// The opinions:
//
//  1. Value types, never pointers. Optional fields get `,omitempty`;
//     absent/zero distinctions are not preserved.
//  2. encoding/json tags only. No yaml, mapstructure, omitzero.
//  3. Required vs optional: properties listed in `required` get no
//     `,omitempty`; everything else gets it.
//  4. No validation methods generated.
//  5. Field naming: snake_case → PascalCase, with an initialism table
//     (id → ID, url → URL, cvss → CVSS, etc.).
//  6. Type naming: $def keys become PascalCase. Inline objects/enums get
//     a synthesized name of <ParentType><FieldName>.
//  7. `format: "date-time"` → time.Time (no Timestamp alias).
//  8. `"type": ["X", "null"]` → "X" (null is dropped).
//  9. `oneOf` where every branch is an object schema with properties →
//     flattened into a single struct with all branches' properties (all
//     optional). Other oneOf/allOf is stripped — it's validation, not
//     structure.
//  10. Object with no properties → `map[string]any` inline at use sites.
//     String $defs with no enum → inlined as `string` at use sites.
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
	pinnedTagFile = "schema-v1.tag"
	generatedFile = "vulnerability_generated.go"
	pkgName       = "osvmodel"
	requirePrefix = "v1."
)

// JSON Schema type constants (avoid string literals repeated through the walker).
const (
	jsObject   = "object"
	jsArray    = "array"
	jsString   = "string"
	jsInteger  = "integer"
	jsNumber   = "number"
	jsBoolean  = "boolean"
	fmtDateTim = "date-time"
)

// ============================================================================
// Schema
// ============================================================================

// Schema is the subset of JSON Schema we read.
type Schema struct {
	Type        json.RawMessage    `json:"type,omitempty"`
	Title       string             `json:"title,omitempty"`
	Format      string             `json:"format,omitempty"`
	Enum        []string           `json:"enum,omitempty"`
	Properties  map[string]*Schema `json:"properties,omitempty"`
	Required    []string           `json:"required,omitempty"`
	Items       *Schema            `json:"items,omitempty"`
	Ref         string             `json:"$ref,omitempty"`
	OneOf       []*Schema          `json:"oneOf,omitempty"`
	Defs        map[string]*Schema `json:"$defs,omitempty"`
	Description string             `json:"description,omitempty"`
}

// jsonType returns the JSON-Schema "type" as a string, picking the first
// non-null entry from a union. Returns "" if no type is set.
func (s *Schema) jsonType() string {
	if len(s.Type) == 0 {
		return ""
	}
	var single string
	if err := json.Unmarshal(s.Type, &single); err == nil {
		return single
	}
	var multi []string
	if err := json.Unmarshal(s.Type, &multi); err == nil {
		for _, t := range multi {
			if t != "null" {
				return t
			}
		}
	}
	return ""
}

// ============================================================================
// Generation entry point
// ============================================================================

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	pull := flag.Bool("pull", false,
		"fetch the latest v1 schema from upstream and overwrite the pinned schema-v1.json before regenerating")
	rootName := flag.String("root", "Vulnerability",
		"name to use for the top-level struct (defaults to the schema title if empty)")
	flag.Parse()

	tag, schemaBytes, err := loadSchema(*pull)
	if err != nil {
		return err
	}
	if schemaBytes == nil {
		return nil // soft refusal path
	}

	var root Schema
	if err := json.Unmarshal(schemaBytes, &root); err != nil {
		return fmt.Errorf("parse schema JSON: %w", err)
	}
	collapseOneOfsInPlace(&root)

	out, err := emit(&root, tag, *rootName)
	if err != nil {
		return fmt.Errorf("emit Go model: %w", err)
	}
	if err := atomicWrite(filepath.Join(packageDir(), generatedFile), out); err != nil {
		return fmt.Errorf("write %s: %w", generatedFile, err)
	}
	fmt.Printf("regenerated %s from osv-schema %s\n", generatedFile, tag)
	return nil
}

// packageDir returns the absolute path to the osvmodel package.
func packageDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller(0) failed; can't locate generator source")
	}
	return filepath.Dir(filepath.Dir(thisFile))
}

// ============================================================================
// Schema loading (pinned vs fetched)
// ============================================================================

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
		fmt.Fprintf(os.Stderr,
			"upstream cut %s; refusing to overwrite the %s* track.\n"+
				"  manual steps to handle a major bump:\n"+
				"  1. copy schema-v1.json to schema-v1-final.json (preserve old track)\n"+
				"  2. start a schema-v2.json + vulnerability_v2_generated.go track\n",
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

func latestReleaseTag() (string, error) {
	req, _ := http.NewRequest(http.MethodGet, releasesAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
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
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ============================================================================
// Walker + registry
//
// The generator has two phases:
//   1. Discover. Walk the schema, collect every fragment that needs a named
//      Go type. $def entries get names from their keys; inline objects and
//      inline enums get names synthesized from <ParentType><FieldName>.
//   2. Emit. For each registered type, emit Go via jen. Field types
//      reference other registered types by name.
// ============================================================================

type registry struct {
	root      *entry            // top-level type (from schema title)
	defs      map[string]*entry // ref → entry, e.g. "#/$defs/severity" → Severity
	defOrder  []string          // sorted $def keys, for stable emission
	inline    []*entry          // inline types in discovery order
	seen      map[*Schema]*entry
	usedNames map[string]bool
}

type entry struct {
	name   string
	schema *Schema
}

func newRegistry() *registry {
	return &registry{
		defs:      map[string]*entry{},
		seen:      map[*Schema]*entry{},
		usedNames: map[string]bool{},
	}
}

func (r *registry) reserve(name string) string {
	if !r.usedNames[name] {
		r.usedNames[name] = true
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s%d", name, i)
		if !r.usedNames[candidate] {
			r.usedNames[candidate] = true
			return candidate
		}
	}
}

// registerDef registers a $def under "#/$defs/<key>".
func (r *registry) registerDef(key string, s *Schema) {
	name := r.reserve(goTypeName(key))
	e := &entry{name: name, schema: s}
	r.defs["#/$defs/"+key] = e
	r.seen[s] = e
	r.defOrder = append(r.defOrder, key)
}

// registerRoot registers the root schema under the chosen name (CLI flag,
// falling back to the schema's title, then "Root").
func (r *registry) registerRoot(s *Schema, rootName string) {
	name := rootName
	if name == "" {
		name = s.Title
	}
	if name == "" {
		name = "Root"
	}
	name = r.reserve(goTypeName(name))
	e := &entry{name: name, schema: s}
	r.root = e
	r.seen[s] = e
}

// registerInline registers a previously-unseen inline object/enum schema.
// preferred is the name we'd like to use (field name, kept short); fallback
// is the parent-prefixed name to fall back to if `preferred` is already in
// use. Returns the assigned Go name.
func (r *registry) registerInline(s *Schema, preferred, fallback string) string {
	if existing, ok := r.seen[s]; ok {
		return existing.name
	}
	candidate := goTypeName(preferred)
	if r.usedNames[candidate] {
		candidate = goTypeName(fallback)
	}
	name := r.reserve(candidate)
	e := &entry{name: name, schema: s}
	r.seen[s] = e
	r.inline = append(r.inline, e)
	return name
}

// pruneUnreachable drops $def entries that aren't referenced from the root
// (transitively). The OSV schema has $defs that exist only as validation
// constraints (e.g. an `ecosystemName` enum that no field $refs — fields
// $ref a different `ecosystemWithSuffix` regex pattern). Emitting them as
// orphan Go types adds noise without giving callers anything to use.
func (r *registry) pruneUnreachable() {
	live := map[*entry]bool{r.root: true}
	for _, e := range r.inline {
		live[e] = true
	}
	// Walk the schemas of every live entry; mark every $def it references.
	queue := append([]*entry{r.root}, r.inline...)
	for len(queue) > 0 {
		e := queue[0]
		queue = queue[1:]
		r.walkRefs(e.schema, func(target *entry) {
			if !live[target] {
				live[target] = true
				queue = append(queue, target)
			}
		})
	}
	// Filter defOrder to live entries only.
	keptOrder := make([]string, 0, len(r.defOrder))
	for _, k := range r.defOrder {
		if live[r.defs["#/$defs/"+k]] {
			keptOrder = append(keptOrder, k)
		}
	}
	r.defOrder = keptOrder
}

// walkRefs visits every $ref-able schema reachable from s and invokes fn
// with the referenced entry. Used by pruneUnreachable to compute liveness.
func (r *registry) walkRefs(s *Schema, fn func(*entry)) {
	if s == nil {
		return
	}
	if s.Ref != "" {
		if e, ok := r.defs[s.Ref]; ok {
			fn(e)
		}
	}
	for _, p := range s.Properties {
		r.walkRefs(p, fn)
	}
	if s.Items != nil {
		r.walkRefs(s.Items, fn)
	}
}

// discover walks every registered type's schema, calling registerInline for
// inline objects/enums that need names. It runs until quiescent: each new
// inline type registered may itself contain further inline types.
func (r *registry) discover() {
	visit := func(e *entry) { r.walkForInline(e.schema, e.name) }
	visit(r.root)
	for _, k := range r.defOrder {
		visit(r.defs["#/$defs/"+k])
	}
	// inline may grow while we iterate; range over indices.
	for i := 0; i < len(r.inline); i++ {
		visit(r.inline[i])
	}
}

// walkForInline walks one schema's fields, registering inline children.
// parent is the Go name of the containing type; we use it as the fallback
// name component when a field's preferred name collides.
func (r *registry) walkForInline(s *Schema, parent string) {
	switch s.jsonType() {
	case jsObject:
		for _, fname := range sortedKeys(s.Properties) {
			r.discoverField(s.Properties[fname], fname, parent)
		}
	case jsArray:
		// an array $def is transparent: the element takes the def's own name
		// and refs resolve to []<DefName>. Walk the element's children under
		// the def name so inline enums read as <Def>Type (e.g. SeverityType),
		// not <Def>EntryType. The element itself is emitted under the def name
		// in emitType, so we don't register a separate type for it here.
		if s.Items != nil {
			r.walkForInline(s.Items, parent)
		}
	}
}

// discoverField walks one property's schema, registering any inline type it
// needs. field is the property's name; parent is the containing Go type
// name (used for collision-fallback naming).
//
// Naming policy: inline objects prefer just the field name (short); on
// collision, fall back to <parent><field>. Inline enums always use
// <parent><field> because property names like "type" repeat across schemas.
// When the property is an array of inline objects, the element type uses
// the singularized field name (so `affected.ranges` items are named
// `Range`, not `Ranges`).
func (r *registry) discoverField(s *Schema, field, parent string) {
	switch {
	case s.Ref != "":
		// refs resolve at use site via r.defs — nothing to register here
	case len(s.Enum) > 0 && s.jsonType() == jsString:
		// Enum: always parent-prefixed (avoids cross-parent collisions on
		// generic field names like "type").
		r.registerInline(s, parent+goTypeName(field), parent+goTypeName(field))
	case s.jsonType() == jsObject && len(s.Properties) > 0:
		name := r.registerInline(s, field, parent+goTypeName(field))
		r.walkForInline(s, name)
	case s.jsonType() == jsArray && s.Items != nil:
		// The element of an array property is conceptually singular, so
		// singularize the field name for the element type.
		r.discoverField(s.Items, singularize(field), parent)
	}
}

// ============================================================================
// Emission
// ============================================================================

func emit(root *Schema, tag, rootName string) ([]byte, error) {
	r := newRegistry()

	// Pre-register every $def so refs resolve during inline discovery.
	for _, k := range sortedKeys(root.Defs) {
		r.registerDef(k, root.Defs[k])
	}
	r.registerRoot(root, rootName)
	r.discover()
	r.pruneUnreachable()

	f := jen.NewFile(pkgName)
	f.HeaderComment("Code generated by ./generate/main.go from osv-schema " + tag + ". DO NOT EDIT.")
	f.HeaderComment("Regenerate via: make generate:osv-model")
	f.HeaderComment("Source: github.com/ossf/osv-schema@" + tag + " (validation/schema.json)")
	f.HeaderComment("")
	f.HeaderComment("Package osvmodel is grype's representation of an OSV record.")

	// Emit root, then $defs (alphabetical), then inline (discovery order).
	emitType(f, r.root, r)
	for _, k := range r.defOrder {
		emitType(f, r.defs["#/$defs/"+k], r)
	}
	for _, e := range r.inline {
		emitType(f, e, r)
	}

	var buf bytes.Buffer
	if err := f.Render(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// emitType writes the Go type declaration for a single entry. Schemas that
// add no information at the type level (a string $def with no enum; a
// free-form object $def with no properties; a date-time-shaped string $def)
// are skipped — at use sites we substitute the underlying primitive directly.
// Emitting orphan aliases makes the generated file longer without giving
// callers anything to use.
func emitType(f *jen.File, e *entry, r *registry) {
	s := e.schema
	switch {
	case len(s.Enum) > 0:
		emitEnum(f, e.name, s)
	case s.jsonType() == jsObject && len(s.Properties) > 0:
		emitStruct(f, e.name, s, r)
	case s.jsonType() == jsArray && namedArrayElement(s):
		// transparent array def: emit the element under the def's name (refs
		// resolve to []<DefName>), so `severity` becomes a Severity element
		// struct used as []Severity — consistent with every other collection.
		if len(s.Items.Enum) > 0 {
			emitEnum(f, e.name, s.Items)
		} else {
			emitStruct(f, e.name, s.Items, r)
		}
	case s.jsonType() == jsArray && s.Items != nil:
		// primitive-element array def: a named slice alias (no element type).
		f.Type().Id(e.name).Index().Add(goType(s.Items, r))
		// no string/object aliases (inlined at use sites)
	}
}

func emitStruct(f *jen.File, name string, s *Schema, r *registry) {
	required := map[string]bool{}
	for _, p := range s.Required {
		required[p] = true
	}
	fields := make([]jen.Code, 0, len(s.Properties))
	for _, propName := range sortedKeys(s.Properties) {
		tag := propName
		if !required[propName] {
			tag += ",omitempty"
		}
		fields = append(fields,
			jen.Id(goFieldName(propName)).
				Add(goType(s.Properties[propName], r)).
				Tag(map[string]string{"json": tag}),
		)
	}
	f.Type().Id(name).Struct(fields...)
}

func emitEnum(f *jen.File, name string, s *Schema) {
	f.Type().Id(name).String()
	values := append([]string{}, s.Enum...)
	sort.Strings(values)
	prefix := strings.TrimSuffix(name, "Type")
	f.Const().DefsFunc(func(g *jen.Group) {
		for _, v := range values {
			g.Id(prefix + enumValueSuffix(v)).Id(name).Op("=").Lit(v)
		}
	})
}

// goType returns the jen.Code for the Go type of a schema fragment (a field
// type, array element, etc). For refs and inline named types, it returns an
// identifier. For primitives, it returns the primitive type directly.
func goType(s *Schema, r *registry) jen.Code {
	if s.Ref != "" {
		e, ok := r.defs[s.Ref]
		if !ok {
			panic(fmt.Sprintf("unknown $ref %s — upstream may have changed shape", s.Ref))
		}
		return refType(e)
	}
	if e, ok := r.seen[s]; ok {
		return jen.Id(e.name)
	}

	switch s.jsonType() {
	case jsString:
		if s.Format == fmtDateTim {
			return jen.Qual("time", "Time")
		}
		return jen.String()
	case jsInteger:
		return jen.Int()
	case jsNumber:
		return jen.Float64()
	case jsBoolean:
		return jen.Bool()
	case jsArray:
		if s.Items == nil {
			return jen.Index().Any()
		}
		return jen.Index().Add(goType(s.Items, r))
	case jsObject:
		// inline free-form object → map[string]any
		return jen.Map(jen.String()).Any()
	}
	// Unknown / underspecified — fall back to any.
	return jen.Any()
}

// refType returns the Go type for a $ref target. For "primitive-ish" $defs
// (a plain string alias, or an array alias whose element is a primitive) we
// emit the underlying type inline at use sites — callers don't see a
// typed-string wrapper unless the def actually carries an enum.
func refType(e *entry) jen.Code {
	s := e.schema
	if s.jsonType() == jsString && len(s.Enum) == 0 && s.Format != fmtDateTim {
		return jen.String()
	}
	if s.jsonType() == jsString && s.Format == fmtDateTim {
		return jen.Qual("time", "Time")
	}
	if s.jsonType() == jsArray && namedArrayElement(s) {
		// transparent array def: the element is named after the def and is
		// referenced as a slice (e.g. severity → []Severity).
		return jen.Index().Add(jen.Id(e.name))
	}
	return jen.Id(e.name)
}

// namedArrayElement reports whether an array schema's element warrants its own
// named Go type (an object with properties or an enum), as opposed to a
// primitive that's inlined. Such array $defs are emitted transparently: the
// element takes the def's name and refs resolve to []<DefName>.
func namedArrayElement(s *Schema) bool {
	if s.Items == nil {
		return false
	}
	it := s.Items
	return len(it.Enum) > 0 || (it.jsonType() == jsObject && len(it.Properties) > 0)
}

// ============================================================================
// oneOf merging (one-shot in-place pre-pass)
// ============================================================================

// collapseOneOfsInPlace walks the schema and, wherever a node's oneOf branches
// are all object schemas with properties, merges those properties into the
// node and clears the oneOf. Mutating in place keeps schema-pointer identity
// stable across the discover/emit phases — the registry uses pointers as keys.
// Non-mergeable oneOfs are left alone (we'll panic on them if they actually
// affect emission, which means a human needs to look).
func collapseOneOfsInPlace(s *Schema) {
	if s == nil {
		return
	}
	// Recurse first so nested branches collapse before we look at this one.
	for _, p := range s.Properties {
		collapseOneOfsInPlace(p)
	}
	if s.Items != nil {
		collapseOneOfsInPlace(s.Items)
	}
	for _, d := range s.Defs {
		collapseOneOfsInPlace(d)
	}
	for _, b := range s.OneOf {
		collapseOneOfsInPlace(b)
	}

	if len(s.OneOf) == 0 {
		return
	}
	for _, b := range s.OneOf {
		if b.jsonType() != jsObject || len(b.Properties) == 0 {
			return // not all object-with-properties; leave oneOf untouched
		}
	}
	if s.Properties == nil {
		s.Properties = map[string]*Schema{}
	}
	for _, b := range s.OneOf {
		for k, v := range b.Properties {
			if _, exists := s.Properties[k]; !exists {
				s.Properties[k] = v
			}
		}
	}
	s.OneOf = nil
	if s.jsonType() == "" {
		s.Type = json.RawMessage(`"object"`)
	}
}

// ============================================================================
// Naming
// ============================================================================

// initialisms records identifier fragments that should keep canonical casing
// rather than being title-cased. Add new ones as needed.
var initialisms = map[string]string{
	"id":     "ID",
	"url":    "URL",
	"cvss":   "CVSS",
	"cpe":    "CPE",
	"cpes":   "CPEs",
	"osv":    "OSV",
	"semver": "SemVer", // not strictly an initialism, but a recognized compound
}

// goTypeName converts a $def key or schema title into a Go type identifier.
func goTypeName(s string) string {
	return pascalCase(s)
}

// goFieldName converts a JSON property name into a Go field identifier.
func goFieldName(s string) string {
	return pascalCase(s)
}

// pascalCase splits on _ and non-letter-digit boundaries, then title-cases
// each part (applying the initialisms table). For ALL-CAPS parts the tail
// is lowercased so "SEMVER" → "Semver" (and via the initialism table,
// "SemVer"); MixedCase parts are left alone so "RangeType" stays
// "RangeType" instead of becoming "Rangetype".
func pascalCase(s string) string {
	parts := splitIdent(s)
	for i, p := range parts {
		if p == "" {
			continue
		}
		if up, ok := initialisms[strings.ToLower(p)]; ok {
			parts[i] = up
			continue
		}
		head := strings.ToUpper(p[:1])
		tail := p[1:]
		if isAllUpper(p) {
			tail = strings.ToLower(tail)
		}
		parts[i] = head + tail
	}
	return strings.Join(parts, "")
}

// isAllUpper reports whether s contains no lowercase letters (digits and
// other characters are tolerated).
func isAllUpper(s string) bool {
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			return false
		}
	}
	return true
}

// splitIdent breaks a string on _, -, space, and dot. Used to normalize
// $def keys ("affected_package"), enum values ("CVSS_V2"), and titles
// ("Open Source Vulnerability") into PascalCase-able parts.
func splitIdent(s string) []string {
	var parts []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			parts = append(parts, cur.String())
			cur.Reset()
		}
	}
	for _, c := range s {
		switch c {
		case '_', '-', ' ', '.', '/':
			flush()
		default:
			cur.WriteRune(c)
		}
	}
	flush()
	return parts
}

// enumValueSuffix returns the suffix appended to the enum type name to form
// a constant identifier. pascalCase handles the casing (with initialism
// awareness: "CVSS_V2" → "CVSSV2", "SEMVER" → "SemVer", "ECOSYSTEM" →
// "Ecosystem"). Mixed-case inputs like "Ubuntu" stay as-is.
func enumValueSuffix(v string) string {
	return pascalCase(v)
}

// singularize trims a trailing "s" from a plural-looking identifier so the
// element type of an array reads naturally ("ranges" → "Range"). The rule
// is intentionally narrow: only strips a single trailing 's', and only when
// it's not preceded by another 's' (avoiding mangling words ending in "ss").
// Good enough for OSV-style schemas where field names are simple plurals.
func singularize(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[len(s)-1] != 's' {
		return s
	}
	if s[len(s)-2] == 's' {
		return s
	}
	return s[:len(s)-1]
}

// ============================================================================
// Helpers
// ============================================================================

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
