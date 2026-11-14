package internal

import "github.com/anchore/packageurl-go"

// PackageNameFromPURL reconstructs the package name in the form the rest
// of the v6 build pipeline (and the matchers) expect for the package's
// ecosystem. Most ecosystems are flat-namespaced and use purl.Name
// directly. Maven (java) packages are stored as "groupId:artifactId" by
// the github advisory transformer, so we mirror that here; otherwise
// the openvex unaffected handle and the github affected handle would
// land on different `packages` rows and the matcher's name search would
// silently miss the VEX statement.
//
// npm scoped names (purl form pkg:npm/%40scope/name) are already round-
// tripped by the packageurl library: purl.Namespace="@scope" and
// purl.Name="name", and the github transformer stores the GHSA's
// FixedIn name verbatim ("@scope/name"). Joining Namespace+"/"+Name
// reproduces that string. Callers can extend this switch as more VEX
// providers come online for additional ecosystems.
func PackageNameFromPURL(purl *packageurl.PackageURL) string {
	if purl.Namespace == "" {
		return purl.Name
	}
	switch purl.Type {
	case packageurl.TypeMaven:
		return purl.Namespace + ":" + purl.Name
	case packageurl.TypeNPM, packageurl.TypeGolang, packageurl.TypeComposer:
		// For Go the namespace is not metadata, it is the leading part of the
		// module path: pkg:golang/github.com/gin-gonic/gin splits into
		// Namespace="github.com/gin-gonic" and Name="gin", and the module is
		// only identified by the two joined. Dropping it would file the
		// statement under "gin". A module with no namespace, such as
		// pkg:golang/stdlib, is returned unchanged by the check above.
		//
		// A Composer package is "vendor/name", the form the github transformer
		// stores from the GHSA, and the vendor is the purl namespace.
		return purl.Namespace + "/" + purl.Name
	}
	return purl.Name
}
