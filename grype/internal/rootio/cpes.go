package rootio

import (
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
	cpes "github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
)

// EquivalentCPEs returns the upstream-name-derived CPEs to add to a rootio
// package's existing CPE list. Result is deduped against existing and
// contains only the additions — the caller is expected to splice them in
// (`grypePkg.CPEs = append(grypePkg.CPEs, rootio.EquivalentCPEs(...)...)`).
// Returns nil for non-rootio packages or when there is no upstream form to
// derive.
//
// This is the CPE-side counterpart of the resolver name fanout in
// grype/db/v6/name: syft's CPE generator produces CPEs from the (rootio-
// prefixed) package name. For `rootio-openssh`, that yields permutations of
// `rootio:rootio-openssh`, `rootio_openssh:rootio_openssh`, etc. — none of
// which match NVD's canonical-vendor CPE (`openbsd:openssh`). Without this
// synthesizer, the NVD-CPE matching path (used by the apk matcher in
// particular) cannot reach upstream disclosures for rootio packages, and the
// rootio NAK has nothing to suppress.
//
// Implementation: re-run syft's `cpes.Generate` against a synthetic package
// whose Name is the bare upstream form, then dedupe by BindToFmtString
// against the rootio-prefixed CPEs syft already produced for the original
// name.
//
// javaGroupID is consulted only when syftP.Type is JavaPkg / JenkinsPluginPkg;
// other ecosystems may pass "".
func EquivalentCPEs(syftP syftPkg.Package, javaGroupID string, existing []cpe.CPE) []cpe.CPE {
	if !IsPackage(syftP.Name, syftP.Version, syftP.Type, javaGroupID) {
		return nil
	}
	bare := StripPrefix(syftP.Name, syftP.Type)
	if bare == "" || bare == syftP.Name {
		return nil
	}

	synthetic := syftP
	synthetic.Name = bare
	candidates := cpes.Generate(synthetic)
	if len(candidates) == 0 {
		return nil
	}

	seen := strset.New()
	for _, c := range existing {
		seen.Add(c.Attributes.BindToFmtString())
	}
	var additions []cpe.CPE
	for _, c := range candidates {
		key := c.Attributes.BindToFmtString()
		if seen.Has(key) {
			continue
		}
		seen.Add(key)
		// override the version field if syft's generator emitted one that
		// differs from the package version (it shouldn't, but be defensive).
		if c.Attributes.Version == "" || strings.HasPrefix(c.Attributes.Version, "rootio-") {
			c.Attributes.Version = synthetic.Version
		}
		additions = append(additions, c)
	}
	return additions
}
