package architecture

import "strings"

// Arch values stored on a vulnerability entry. The literal "src" matches the CSAF wire
// format (`?arch=src` qualifier on rpm PURLs) and is what a synthesized upstream (source)
// package carries. When a CSAF advisory lists a binary RPM without declaring a specific
// target architecture, the transformer synthesizes the ArchBinaryNoArchSpecified sentinel so
// the entry can be told apart from a source RPM — the underlying source data simply did not
// carry an architecture, so we annotate that explicitly rather than store an empty string.
//
// An empty/unset value means the provider does not scope the entry to an architecture at all
// (older databases, most providers), and such entries apply to every package.
const (
	ArchSource                = "src"
	ArchBinaryNoArchSpecified = "binary-no-arch-specified"

	// archIndependent is the normalized form of the arch-independent spellings (rpm "noarch",
	// deb "all"): a package with no architecture-specific content, installed identically on
	// every architecture. These are real values seen in data, not sentinels we emit.
	archIndependent = "noarch"
	amd64           = "amd64"
	arm64           = "arm64"
	i386            = "386"
)

var defaultAliases = map[string]string{
	"source":      ArchSource,
	"all":         archIndependent,
	"x86_64":      amd64,
	"x86-64":      amd64,
	"x64":         amd64,
	"aarch64":     arm64,
	"i386":        i386,
	"i486":        i386,
	"i586":        i386,
	"i686":        i386,
	"x86":         i386,
	"ppc64el":     "ppc64le",
	"loongarch64": "loong64",
}

// DefaultAliases returns the built-in architecture alias table (alias spelling -> canonical token).
// It seeds the database's architecture_aliases table at build time and is the fallback for
// databases that predate that table; a database's own table replaces it entirely.
//
// The canonical CPU token is arbitrary (we use the Go/OCI spelling); only equivalence matters, so a
// canonical spelling (e.g. "amd64") is intentionally absent and resolves to itself. The role tokens
// are not arbitrary: Matches interprets ArchSource, ArchBinaryNoArchSpecified and "noarch", so
// other spellings must fold onto them, never the reverse. The 32-bit ARM spellings (armhf, armel,
// armv7hl, ...) are intentionally not folded: the same name denotes different ABIs across
// ecosystems (e.g. Alpine armhf is ARMv6, Debian armhf is ARMv7).
func DefaultAliases() map[string]string {
	return defaultAliases
}

// BinaryDefault returns the architecture to search with for an OS package (or an upstream source
// package synthesized from one): the package's own architecture, or ArchBinaryNoArchSpecified when
// none was recorded. A cataloged package with no recorded architecture is still known not to be a
// source package: package managers catalog binaries, and the source packages grype searches with
// are synthesized upstreams, which are tagged ArchSource (see pkg.UpstreamPackages).
func BinaryDefault(pkgArch string) string {
	if pkgArch == "" {
		return ArchBinaryNoArchSpecified
	}
	return pkgArch
}

// IsSource reports whether arch names a source package, in any spelling the built-in aliases fold to
// ArchSource.
func IsSource(arch string) bool {
	return canonical(arch, DefaultAliases()) == ArchSource
}

// Matches reports whether a package of architecture pkgArch falls under a vulnerability entry
// scoped to recordArch. The rules are identical for affected and unaffected entries:
//
//   - an unset arch on either side matches: an entry with no arch applies to every package, and
//     a package with no arch cannot be ruled out.
//   - an ArchSource entry matches only a source package, and a source package matches only an
//     ArchSource entry (or one with no arch). A binary reaches what applies to its source through
//     its upstream search, whose synthesized package is tagged ArchSource (see pkg.UpstreamPackages),
//     so a binary that shares its name with an unrelated source package is not matched against that
//     source's entries, and a binary entry is not matched through the upstream of a sibling binary.
//   - an arch-independent value (rpm "noarch", deb "all") on either side of two binaries matches: it
//     has no architecture-specific content, so there is nothing to compare against.
//   - an ArchBinaryNoArchSpecified value on either side of two binaries matches: the binary's arch
//     was not recorded, so it cannot be ruled out.
//   - otherwise the canonical arches must be equal.
//
// Both arches are first folded to their canonical spelling through aliases (alias spelling ->
// canonical token), so the rules above apply to every dialect spelling the table knows about. A nil
// table uses DefaultAliases. A spelling absent from the table is compared as-is, apart from case
// and surrounding whitespace.
func Matches(pkgArch, recordArch string, aliases map[string]string) bool {
	if aliases == nil {
		aliases = DefaultAliases()
	}
	p, r := canonical(pkgArch, aliases), canonical(recordArch, aliases)
	switch {
	case p == "" || r == "":
		return true
	case p == ArchSource || r == ArchSource:
		return p == r
	case p == archIndependent || r == archIndependent:
		return true
	case p == ArchBinaryNoArchSpecified || r == ArchBinaryNoArchSpecified:
		return true
	}
	return p == r
}

// canonical normalizes an architecture string (see normalize) and folds it onto its canonical token
// using aliases (alias spelling -> canonical token), so a package and a vulnerability entry that
// name the same architecture or role in different ecosystem dialects compare equal. The same
// architecture is spelled differently by different tooling: RPM/GNU/Alpine say "x86_64"/"aarch64",
// while Debian/Go/OCI say "amd64"/"arm64" (and Windows "x64"); deb says "source" and "all" where
// rpm says "src" and "noarch". A spelling not in the table is its own canonical form.
func canonical(a string, aliases map[string]string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	if c, ok := aliases[a]; ok {
		return c
	}
	return a
}
