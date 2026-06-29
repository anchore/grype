package architecture

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
)

// TestArchitecture_Satisfied pins down the per-package gating logic for the AFFECTED qualifier:
// match the package's arch against the arch the entry affects. Concrete arches compare exactly;
// the src entry matches only source packages; binary-no-arch matches any binary (any non-src)
// package; and an unset or arch-independent (rpm "noarch", deb "all") value on either side is
// inert (cannot/should not decide, so don't filter).
//
// A satisfied AFFECTED entry QUALIFIES (keeps) the match, so want==true means "qualifies".
// Leniency fails toward the vulnerability (a false positive) rather than dropping a real match.
// The cases below enumerate each distinct (package arch, entry arch) combination, then add
// supplementary cross-dialect spellings and the src/src and binary/src pairings.
func TestArchitecture_Satisfied(t *testing.T) {
	tests := []struct {
		name          string
		qualifierArch string // arch stored on the vulnerability entry
		pkgArch       string // arch read off the scanned package
		want          bool   // does the affected entry qualify (keep) the package?
	}{
		{
			// a binary record excludes the source package — a binary vuln must not
			// match a package that isn't a binary.
			name:          "src package / binary-no-arch entry -> does not qualify",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       ArchSource,
			want:          false,
		},
		{
			// a binary-no-arch vuln matches any binary package, whatever its arch.
			name:          "aarch64 binary / binary-no-arch entry -> qualifies",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       "aarch64",
			want:          true,
		},
		{
			// an arch-independent package has no arch-specific content and is installed
			// on every arch, so an arch-scoped entry still applies and must not drop it.
			name:          "noarch package / concrete (x86_64) entry -> qualifies",
			qualifierArch: "x86_64",
			pkgArch:       archNoarch,
			want:          true,
		},
		{
			// "all" is debian's arch-independent marker; same reasoning as noarch.
			name:          "deb 'all' package / concrete (amd64) entry -> qualifies",
			qualifierArch: "amd64",
			pkgArch:       archAll,
			want:          true,
		},
		{
			// a binary package matches a src entry — the binary is built from the
			// vulnerable source and inherits its vulnerability.
			name:          "binary package / src entry -> qualifies (built from vulnerable src)",
			qualifierArch: ArchSource,
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			// matching concrete arches qualify.
			name:          "aarch64 package / aarch64 entry -> qualifies (arches match)",
			qualifierArch: "aarch64",
			pkgArch:       "aarch64",
			want:          true,
		},
		{
			// mismatched concrete arches do not qualify.
			name:          "x86_64 package / aarch64 entry -> does not qualify (arches differ)",
			qualifierArch: "aarch64",
			pkgArch:       "x86_64",
			want:          false,
		},
		{
			// unknown package arch — assume the vuln may apply (fail toward the
			// vulnerable claim). Older DBs / non-PURL providers surface no arch.
			name:          "empty package arch / concrete entry -> qualifies (unknown, assume applies)",
			qualifierArch: "x86_64",
			pkgArch:       "",
			want:          true,
		},
		{
			// an entry with no arch is not scoped to any architecture, so any package
			// matches. Transformers should emit nil, but "" stays permissive too.
			name:          "concrete package / empty entry -> qualifies (vuln not arch-scoped)",
			qualifierArch: "",
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			// a concrete package vs an arch-independent entry qualifies — a binary rpm
			// can be affected by a vuln that isn't in architecture-specific code.
			name:          "aarch64 package / noarch entry -> qualifies",
			qualifierArch: archNoarch,
			pkgArch:       "aarch64",
			want:          true,
		},

		// supplementary: cross-dialect spellings and extra pairings
		{
			// cross-dialect: a deb/Go/OCI "amd64" package must match an RPM-dialect
			// "x86_64" advisory — same architecture, different spelling.
			name:          "amd64 package matches x86_64 entry (canonicalized)",
			qualifierArch: "x86_64",
			pkgArch:       "amd64",
			want:          true,
		},
		{
			name:          "x86_64 package matches amd64 entry (canonicalized)",
			qualifierArch: "amd64",
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			name:          "arm64 package matches aarch64 entry (canonicalized)",
			qualifierArch: "aarch64",
			pkgArch:       "arm64",
			want:          true,
		},
		{
			// canonicalization must not collapse genuinely different architectures.
			name:          "amd64 package does not match arm64 entry",
			qualifierArch: "arm64",
			pkgArch:       "amd64",
			want:          false,
		},
		{
			// an arch-independent entry doesn't constrain by arch either (rpm-dialect spelling).
			name:          "arch-independent entry is inert against a concrete package",
			qualifierArch: "noarch",
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			// A src entry matches a source package. Binary packages reach src entries via
			// the rpm matcher's upstream search, which tags its synthesized package "src".
			name:          "src entry matches source package",
			qualifierArch: ArchSource,
			pkgArch:       ArchSource,
			want:          true,
		},
		{
			// a src record is source-level, applying by name regardless of arch, so a
			// same-name binary matches it. Required for same-name-source binaries, which
			// have no synthesized upstream (e.g. CVE-2026-31790 openssl-fips-provider,
			// source == binary name).
			name:          "src entry matches a same-name binary regardless of arch",
			qualifierArch: ArchSource,
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			// binary-no-arch matches an x86_64 binary too.
			name:          "binary-no-arch entry matches an x86_64 binary",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       "x86_64",
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := New(tt.qualifierArch, nil)
			got, err := q.Satisfied(pkg.Package{Metadata: pkg.RpmMetadata{Arch: tt.pkgArch}})
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestUnaffectedArchitecture_Satisfied pins the conservative polarity of NewUnaffected: a satisfied
// unaffected record SUPPRESSES a match, so it must never suppress on an arch it can't positively
// confirm. It mirrors TestArchitecture_Satisfied (the affected qualifier); the two differ only on
// the uncertain cases the affected side resolves leniently, which are called out below.
//
// want==true means the unaffected entry applies and SUPPRESSES the match. The arch-independent,
// empty-package-arch, and arch-independent-entry cases are where this qualifier diverges from the
// affected one: where the affected qualifier leniently keeps a match it can't decide, the
// unaffected qualifier conservatively declines to suppress (the safe direction is opposite).
func TestUnaffectedArchitecture_Satisfied(t *testing.T) {
	tests := []struct {
		name          string
		qualifierArch string // arch stored on the (unaffected/negation) vulnerability entry
		pkgArch       string // arch read off the scanned package
		want          bool   // does the unaffected entry apply (suppress) the package?
	}{
		{
			// the UAP applies only to binary RPMs, so it does not suppress a source pkg.
			name:          "src package / binary-no-arch entry -> does not suppress",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       ArchSource,
			want:          false,
		},
		{
			// the UAP applies to all binary RPMs, so it suppresses any binary package.
			name:          "aarch64 binary / binary-no-arch entry -> suppresses",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       "aarch64",
			want:          true,
		},
		{
			// diverges from affected: a "not affected on x86_64" record says nothing
			// about the arch-independent build, so it must not suppress it.
			name:          "noarch package / concrete (x86_64) entry -> does not suppress",
			qualifierArch: "x86_64",
			pkgArch:       archNoarch,
			want:          false,
		},
		{
			// same reasoning for the deb-dialect "all".
			name:          "deb 'all' package / concrete (amd64) entry -> does not suppress",
			qualifierArch: "amd64",
			pkgArch:       archAll,
			want:          false,
		},
		{
			// a src-level not-affected applies by name regardless of arch — the binary
			// is built from the unaffected source — so it suppresses the binary.
			name:          "binary package / src entry -> suppresses (built from unaffected src)",
			qualifierArch: ArchSource,
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			// matching concrete arches — the UAP applies, suppress.
			name:          "aarch64 package / aarch64 entry -> suppresses (arches match)",
			qualifierArch: "aarch64",
			pkgArch:       "aarch64",
			want:          true,
		},
		{
			// mismatched concrete arches — the UAP doesn't apply, don't suppress.
			name:          "x86_64 package / aarch64 entry -> does not suppress (arches differ)",
			qualifierArch: "aarch64",
			pkgArch:       "x86_64",
			want:          false,
		},
		{
			// diverges from affected: package arch unknown — can't prove the UAP
			// applies, so don't suppress.
			name:          "empty package arch / concrete entry -> does not suppress (can't prove it applies)",
			qualifierArch: "x86_64",
			pkgArch:       "",
			want:          false,
		},
		{
			// a blanket no-arch unaffected record applies to every package.
			name:          "concrete package / empty entry -> suppresses (blanket not-affected)",
			qualifierArch: "",
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			// diverges from affected: the UAP is about an arch-independent RPM and we
			// can't show it applies to a concrete arch, so don't suppress.
			name:          "aarch64 package / noarch entry -> does not suppress",
			qualifierArch: archNoarch,
			pkgArch:       "aarch64",
			want:          false,
		},

		// supplementary: cross-dialect spellings and extra pairings
		{
			// Confirmed: an exact arch-independent match is a real correspondence, so suppress.
			name:          "noarch package is suppressed by a noarch entry",
			qualifierArch: "noarch",
			pkgArch:       "noarch",
			want:          true,
		},
		{
			// arch-independent entry vs a concrete package, rpm-dialect spelling.
			name:          "concrete package is not suppressed by an arch-independent entry",
			qualifierArch: "noarch",
			pkgArch:       "x86_64",
			want:          false,
		},
		{
			// binary-no-arch does not suppress a source package (the upstream
			// search's synthesized package is tagged "src").
			name:          "binary-no-arch entry does not suppress a source package",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       ArchSource,
			want:          false,
		},
		{
			// cross-dialect: confirmed concrete match suppresses.
			name:          "matching concrete arch suppresses (canonicalized)",
			qualifierArch: "x86_64",
			pkgArch:       "amd64",
			want:          true,
		},
		{
			// confirmed concrete mismatch does not suppress.
			name:          "mismatched concrete arch does not suppress",
			qualifierArch: "x86_64",
			pkgArch:       "aarch64",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewUnaffected(tt.qualifierArch, nil).Satisfied(pkg.Package{Metadata: pkg.RpmMetadata{Arch: tt.pkgArch}})
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestArchitecture_Satisfied_NonRpmMetadataInert pins that a package whose metadata is absent
// or isn't RpmMetadata reports no arch and so is never filtered — arch lives on the rpm
// metadata contract, and the qualifier only ever sees rpm packages in practice.
func TestArchitecture_Satisfied_NonRpmMetadataInert(t *testing.T) {
	for _, p := range []pkg.Package{
		{Name: "no-metadata"},
		{Name: "apk-metadata", Metadata: pkg.ApkMetadata{}},
	} {
		got, err := New("x86_64", nil).Satisfied(p)
		require.NoError(t, err)
		require.True(t, got, "package %q should be inert (no rpm arch to decide on)", p.Name)
	}
}

// TestArchitecture_Satisfied_DataDrivenAliases pins that the DB-supplied alias table — not the
// built-in defaults — drives canonicalization when present. A non-empty table is trusted
// exclusively, so a default fold absent from it no longer applies.
func TestArchitecture_Satisfied_DataDrivenAliases(t *testing.T) {
	// a DB whose table folds a dialect the built-in defaults don't know about ("riscv64" =
	// "riscv") and intentionally omits the built-in amd64 fold.
	aliases := map[string]string{"riscv64": "riscv"}

	// the DB-provided fold applies
	got, err := New("riscv", aliases).Satisfied(pkg.Package{Metadata: pkg.RpmMetadata{Arch: "riscv64"}})
	require.NoError(t, err)
	require.True(t, got, "DB-supplied alias should fold riscv64 -> riscv")

	// the built-in default fold (x86_64 -> amd64) is NOT merged in when the DB table is present
	got, err = New("amd64", aliases).Satisfied(pkg.Package{Metadata: pkg.RpmMetadata{Arch: "x86_64"}})
	require.NoError(t, err)
	require.False(t, got, "non-empty DB table is trusted exclusively; built-in defaults must not leak in")
}

// TestDefaultAliases pins the built-in fold table (the match-time fallback for pre-table
// databases and the seed source for the DB) and that callers get an isolated copy.
func TestDefaultAliases(t *testing.T) {
	a := DefaultAliases()
	require.Equal(t, "amd64", a["x86_64"])
	require.Equal(t, "arm64", a["aarch64"])
	require.NotContains(t, a, "amd64", "canonical tokens resolve to themselves and must not be keyed")

	a["x86_64"] = "tampered"
	require.Equal(t, "amd64", DefaultAliases()["x86_64"], "DefaultAliases must return an isolated copy")
}
