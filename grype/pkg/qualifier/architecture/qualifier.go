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
	arch    string
	aliases map[string]string
}

// New builds an architecture qualifier for a vulnerability entry's stored arch. aliases is the
// arch alias table read from the database (alias spelling -> canonical token); pass nil/empty
// to fall back to the built-in DefaultAliases (e.g. for databases built before the
// architecture_aliases table existed). See canonicalArch.
func New(arch string, aliases map[string]string) qualifier.Qualifier {
	return &architectureQualifier{arch: arch, aliases: aliases}
}

// Arch returns the stored architecture value (e.g. "src", "x86_64",
// "binary-no-arch-specified", or "" if unset).
func (r architectureQualifier) Arch() string {
	return r.arch
}

// Satisfied reports whether package p falls under what this vulnerability entry describes,
// based on the entry's stored arch:
//
//   - a concrete arch ("x86_64", "aarch64"): matches only packages of that arch. This lets
//     a provider (e.g. Chainguard) scope an advisory or its fix to a single architecture.
//   - ArchSource ("src"): a source-level record. It applies to the package by name
//     regardless of the scanned arch — a binary inherits its source RPM's vulnerability —
//     so it matches both source packages and same-name binaries. (Binaries whose source has
//     a different name reach it via the rpm matcher's upstream search, whose synthesized
//     package is tagged "src".)
//   - ArchBinaryNoArchSpecified: a binary disclosure with no specific arch — matches any
//     binary package (any non-src arch), but NOT a source package. That exclusion is what
//     keeps a binary record from matching through the synthesized "src" upstream package,
//     so a sibling binary built from the same source isn't falsely matched.
//
// A package with no recorded arch is inert (older DBs / inputs without arch, or a package
// type that doesn't carry one), as is an entry with no arch (treated as "any"); neither
// direction filters when we cannot decide.
//
// Concrete arches are compared in canonical form (see canonicalArch) so a package and an
// entry that name the same architecture in different ecosystem dialects still match — e.g.
// an "amd64" deb package against an "x86_64" RPM-dialect advisory.
func (r architectureQualifier) Satisfied(p pkg.Package) (bool, error) {
	pkgArch := packageArch(p)
	if pkgArch == "" || r.arch == "" {
		return true, nil
	}
	switch r.arch {
	case ArchSource:
		return true, nil
	case ArchBinaryNoArchSpecified:
		return pkgArch != ArchSource, nil
	default:
		return canonicalArch(pkgArch, r.aliases) == canonicalArch(r.arch, r.aliases), nil
	}
}

// packageArch reads the architecture off the package's metadata contract. Only RPM metadata
// carries an arch today; any other (or absent) metadata reports "", which Satisfied treats as
// inert. The architecture qualifier is only emitted on rpm/CSAF entries, so it is only ever
// evaluated against rpm packages in practice.
func packageArch(p pkg.Package) string {
	if m, ok := p.Metadata.(pkg.RpmMetadata); ok {
		return m.Arch
	}
	return ""
}

// canonicalArch folds an architecture string onto one token per CPU architecture so matching
// doesn't drop vulnerabilities across ecosystem dialects. The same architecture is spelled
// differently by different tooling: RPM/GNU/Alpine say "x86_64"/"aarch64", while Debian/Go/OCI
// say "amd64"/"arm64" (and Windows "x64"). Since a package carries its package manager's
// spelling and an advisory carries its source's spelling, an exact string compare would
// wrongly drop a real match when those dialects differ.
//
// The alias table is data-driven: it comes from the database (the architecture_aliases table),
// so the folding can be updated without shipping a new grype binary. An empty table — which is
// what a database built before that table existed reports — falls back to the built-in
// defaultAliases so historical databases keep cross-dialect matching.
//
// Only genuine CPU architectures are folded. The role markers ("src", binary-no-arch) and
// arch-independent values (rpm "noarch", deb "all") are not architectures and are simply
// absent from the table, so they pass through unchanged. A spelling not in the table is its
// own canonical form.
func canonicalArch(a string, aliases map[string]string) string {
	if len(aliases) == 0 {
		aliases = defaultAliases
	}
	if canonical, ok := aliases[a]; ok {
		return canonical
	}
	return a
}

// defaultAliases maps each non-canonical architecture spelling to its canonical token. The
// canonical token is arbitrary (we use the Go/OCI spelling); only equivalence matters, so a
// canonical spelling (e.g. "amd64") is intentionally absent and resolves to itself.
var defaultAliases = map[string]string{
	"x86_64":  "amd64",
	"x64":     "amd64",
	"aarch64": "arm64",
	"i386":    "386",
	"i686":    "386",
	"x86":     "386",
	"ppc64el": "ppc64le",
}

// DefaultAliases returns a copy of the built-in architecture alias table (alias spelling ->
// canonical token). It is the single source of truth for both seeding the database's
// architecture_aliases table at build time and the match-time fallback for databases that
// predate that table.
func DefaultAliases() map[string]string {
	out := make(map[string]string, len(defaultAliases))
	for alias, canonical := range defaultAliases {
		out[alias] = canonical
	}
	return out
}
