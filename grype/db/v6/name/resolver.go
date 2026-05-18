package name

import (
	"slices"

	"github.com/anchore/grype/grype/internal/rootio"
	grypePkg "github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Resolver interface {
	Normalize(string) string
	Names(p grypePkg.Package) []string
}

func FromType(t syftPkg.Type) Resolver {
	switch t {
	case syftPkg.PythonPkg:
		return &PythonResolver{}
	case syftPkg.JavaPkg, syftPkg.JenkinsPluginPkg:
		return &JavaResolver{}
	}

	return nil
}

// PackageNames returns the list of names a matcher should search the DB by
// when looking up vulnerabilities for p. Per-ecosystem resolvers (Python,
// Java) provide alternate canonical forms (PEP 503 normalization, Maven
// group+artifact splits); rootio packages additionally fan out to the bare
// upstream name so a scan against a `rootio-libssl3` apk reaches the
// `libssl3` disclosure in the Alpine namespace.
//
// Rootio data carries no false-positive risk through this fanout: rootio
// publishes only UnaffectedPackageHandles (NAKs), so any extra-name search
// can suppress a match but cannot manufacture one. The RootIO package
// qualifier on those NAKs gives second-line protection — it keeps a
// rootio-tagged record from applying to a scanned package that isn't
// itself a rootio build.
func PackageNames(p grypePkg.Package) []string {
	names := []string{p.Name}
	if r := FromType(p.Type); r != nil {
		if parts := r.Names(p); len(parts) > 0 {
			names = parts
		}
	}
	if rootio.IsPackage(p) {
		names = appendRootIOStrippedNames(names, p.Type)
	}
	return names
}

// appendRootIOStrippedNames appends the upstream (bare) form of each rootio-
// prefixed name to the search list, skipping duplicates and empty results.
// The caller is responsible for first confirming IsPackage(p); this helper
// trusts that and just strips.
func appendRootIOStrippedNames(names []string, t syftPkg.Type) []string {
	seen := make(map[string]struct{}, len(names)*2)
	for _, n := range names {
		seen[n] = struct{}{}
	}
	out := slices.Clone(names)
	for _, n := range names {
		stripped := rootio.StripPrefix(n, t)
		if stripped == "" || stripped == n {
			continue
		}
		if _, ok := seen[stripped]; ok {
			continue
		}
		out = append(out, stripped)
		seen[stripped] = struct{}{}
	}
	return out
}

func Normalize(name string, pkgType syftPkg.Type) string {
	r := FromType(pkgType)
	if r != nil {
		return r.Normalize(name)
	}
	return name
}
