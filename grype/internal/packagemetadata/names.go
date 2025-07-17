package packagemetadata

import (
	"reflect"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/pkg"
)

// jsonNameFromType is a map of all known package metadata types to their current JSON name and all previously known aliases.
// TODO: in the future the metadata type names should match how it is used in syft. However, since the data shapes are
// not the same it may be important to select different names. This design decision has been deferred, for now
// the same metadata types that have been used in the past should be used here.
var jsonNameFromType = map[reflect.Type][]string{
	reflect.TypeOf(pkg.ApkMetadata{}):                nameList("ApkMetadata"),
	reflect.TypeOf(pkg.GolangBinMetadata{}):          nameList("GolangBinMetadata"),
	reflect.TypeOf(pkg.GolangModMetadata{}):          nameList("GolangModMetadata"),
	reflect.TypeOf(pkg.JavaMetadata{}):               nameList("JavaMetadata"),
	reflect.TypeOf(pkg.RpmMetadata{}):                nameList("RpmMetadata"),
	reflect.TypeOf(pkg.JavaVMInstallationMetadata{}): nameList("JavaVMInstallationMetadata"),
}

//nolint:unparam
func nameList(id string, others ...string) []string {
	names := []string{id}
	for _, o := range others {
		names = append(names, expandLegacyNameVariants(o)...)
	}
	return names
}

func expandLegacyNameVariants(name string) []string {
	candidates := []string{name}
	if strings.HasSuffix(name, "MetadataType") {
		candidates = append(candidates, strings.TrimSuffix(name, "Type"))
	} else if strings.HasSuffix(name, "Metadata") {
		candidates = append(candidates, name+"Type")
	}
	return candidates
}

func AllTypeNames() []string {
	names := make([]string, 0)
	for _, t := range AllTypes() {
		names = append(names, reflect.TypeOf(t).Name())
	}
	return names
}

func JSONName(metadata any) string {
	if vs, exists := jsonNameFromType[reflect.TypeOf(metadata)]; exists {
		return vs[0]
	}
	return ""
}

func ReflectTypeFromJSONName(name string) reflect.Type {
	name = strings.ToLower(name)
	for _, t := range sortedTypes(jsonNameFromType) {
		vs := jsonNameFromType[t]
		for _, v := range vs {
			if strings.ToLower(v) == name {
				return t
			}
		}
	}
	return nil
}

func sortedTypes(typeNameMapping map[reflect.Type][]string) []reflect.Type {
	types := make([]reflect.Type, 0)
	for t := range typeNameMapping {
		types = append(types, t)
	}

	// sort the types by their first JSON name
	sort.Slice(types, func(i, j int) bool {
		return typeNameMapping[types[i]][0] < typeNameMapping[types[j]][0]
	})

	return types
}
