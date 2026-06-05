package architecture

import (
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

// Arch values stored on a vulnerability entry. The literal "src" matches the CSAF wire
// format (`?arch=src` qualifier on rpm PURLs). When a CSAF advisory lists a binary RPM
// without declaring a specific target architecture, the transformer synthesizes the
// ArchBinaryNoArchSpecified sentinel so the entry can be told apart from a source RPM
// during upstream-search filtering — the underlying source data simply did not carry an
// architecture, so we annotate that explicitly rather than store an empty string.
//
// An empty/unset value means the provider does not distinguish source from binary at all
// — older databases, non-CSAF providers, etc. Such entries pass through upstream search
// unchanged so existing behavior is preserved.
const (
	ArchSource                = "src"
	ArchBinaryNoArchSpecified = "binary-no-arch-specified"
)

type architectureQualifier struct {
	arch string
}

func New(arch string) qualifier.Qualifier {
	return &architectureQualifier{arch: arch}
}

// Arch returns the stored architecture value (e.g. "src", "x86_64",
// "binary-no-arch-specified", or "" if unset).
func (r architectureQualifier) Arch() string {
	return r.arch
}

// Satisfied checks whether the package's architecture matches the qualifier's architecture.
// If the package does not have an architecture specified, the qualifier is inert
// (i.e., it does not filter out packages without architecture information).
func (r architectureQualifier) Satisfied(p pkg.Package) (bool, error) {
	if p.Arch != "" {
		return p.Arch == r.arch, nil
	}
	return true, nil
}
