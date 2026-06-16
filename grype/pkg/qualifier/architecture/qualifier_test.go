package architecture

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
)

// TestArchitecture_Arch covers the Arch() accessor — it must round-trip whatever string the
// transformer stored (including the two reserved sentinels and the unset empty string).
func TestArchitecture_Arch(t *testing.T) {
	tests := []struct {
		name string
		arch string
	}{
		{name: "source sentinel", arch: ArchSource},
		{name: "binary-no-arch-specified sentinel", arch: ArchBinaryNoArchSpecified},
		{name: "literal architecture", arch: "x86_64"},
		{name: "empty (provider does not distinguish)", arch: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := New(tt.arch, nil)
			archer, ok := q.(interface{ Arch() string })
			require.True(t, ok, "qualifier must expose Arch() so criteria can read the stored value")
			require.Equal(t, tt.arch, archer.Arch())
		})
	}
}

// TestArchitecture_Satisfied pins down the per-package gating logic: match the package's
// arch against the arch the entry affects. Concrete arches compare exactly; the src entry
// matches only source packages; binary-no-arch matches any binary (any non-src) package;
// and an unset arch on either side is inert (cannot decide, so don't filter).
func TestArchitecture_Satisfied(t *testing.T) {
	tests := []struct {
		name          string
		qualifierArch string
		pkgArch       string
		want          bool
	}{
		{
			// Inert: no arch on the package means the input didn't surface one, so we
			// can't decide and must pass (older DBs / non-PURL providers).
			name:          "package without arch is inert",
			qualifierArch: "x86_64",
			pkgArch:       "",
			want:          true,
		},
		{
			// Inert: an entry with no arch means "any"; it must not filter a concrete
			// package. Transformers should emit nil, but "" stays permissive too.
			name:          "entry without arch is inert",
			qualifierArch: "",
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			name:          "concrete arch matches same concrete arch",
			qualifierArch: "x86_64",
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			name:          "concrete arch does not match different concrete arch",
			qualifierArch: "x86_64",
			pkgArch:       "aarch64",
			want:          false,
		},
		{
			// Cross-dialect: a deb/Go/OCI "amd64" package must match an RPM-dialect
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
			// Canonicalization must not collapse genuinely different architectures.
			name:          "amd64 package does not match arm64 entry",
			qualifierArch: "arm64",
			pkgArch:       "amd64",
			want:          false,
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
			// A src record is source-level: it applies by name regardless of arch, so a
			// same-name binary matches it (the binary inherits its source's vuln). This is
			// required for same-name-source binaries, which have no synthesized upstream
			// (e.g. CVE-2026-31790 openssl-fips-provider, source == binary name).
			name:          "src entry matches a same-name binary regardless of arch",
			qualifierArch: ArchSource,
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			// binary-no-arch is a binary disclosure with no specific arch: it matches any
			// binary package regardless of arch.
			name:          "binary-no-arch entry matches an x86_64 binary",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			name:          "binary-no-arch entry matches an aarch64 binary",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       "aarch64",
			want:          true,
		},
		{
			// ...but not a source package. This is what rejects binary entries on the
			// upstream search (whose synthesized package is tagged "src"), preventing
			// sibling-binary false positives.
			name:          "binary-no-arch entry does not match a source package",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       ArchSource,
			want:          false,
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
