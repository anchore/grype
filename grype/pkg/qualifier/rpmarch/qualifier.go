package rpmarch

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

type rpmArch struct {
	arch string
}

func New(arch string) qualifier.Qualifier {
	return &rpmArch{arch: arch}
}

// Arch returns the stored architecture value (e.g. "src", "x86_64",
// "binary-no-arch-specified", or "" if unset).
func (r rpmArch) Arch() string {
	return r.arch
}

// Satisfied is intentionally inert: the rpmarch qualifier is read by criteria that operate
// on the vulnerability side (see internal.SourceOrUnspecifiedArch), not by per-package
// qualifier evaluation. Direct hits on a binary-tagged entry must still match by name, so
// this always returns true.
func (r rpmArch) Satisfied(_ pkg.Package) (bool, error) {
	return true, nil
}
