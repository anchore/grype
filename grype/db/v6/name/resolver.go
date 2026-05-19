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
// group+artifact splits); rootio packages additionally fan out across both
// naming directions so the matcher reaches every record relevant to a rootio
// build regardless of which naming model the SBOM uses:
//
//   - prefixed → bare: a scan against `rootio-libssl3` reaches the upstream
//     `libssl3` disclosure in the distro namespace.
//   - bare → prefixed: a scan against `libgcrypt20@1.10.1-3.root.io.2`
//     (upstream-named rootio build) reaches the rootio NAK keyed under
//     `rootio-libgcrypt20`.
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
		names = appendRootIONameVariants(names, p.Type)
	}
	return names
}

// appendRootIONameVariants extends the search list with both the bare upstream
// form and the rootio-prefixed form of each name, skipping duplicates and
// empties. The caller is responsible for first confirming IsPackage(p).
//
// Both directions matter:
//   - prefixed-on-input (`rootio-libssl3`) needs the bare form to reach upstream
//     distro disclosures keyed under `libssl3`.
//   - bare-on-input (`libgcrypt20@1.10.1-3.root.io.2`) needs the prefixed form
//     to reach rootio NAKs keyed under `rootio-libgcrypt20`.
func appendRootIONameVariants(names []string, t syftPkg.Type) []string {
	seen := make(map[string]struct{}, len(names)*2)
	for _, n := range names {
		seen[n] = struct{}{}
	}
	out := slices.Clone(names)
	add := func(candidate string) {
		if candidate == "" {
			return
		}
		if _, ok := seen[candidate]; ok {
			return
		}
		out = append(out, candidate)
		seen[candidate] = struct{}{}
	}
	for _, n := range names {
		add(rootio.StripPrefix(n, t))
		add(rootio.AddPrefix(n, t))
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
